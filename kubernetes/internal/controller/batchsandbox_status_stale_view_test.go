// Copyright 2025 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/expectations"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/fieldindex"
)

// The sequence the PauseResume e2e spec "should set Phase=Succeed+PauseFailed when
// commit/push fails with invalid registry" lost in 6 of 63 PauseResume jobs of wm-ci
// since 2026-09-27, every time the same way.
// The pause handler writes phase=Succeed (ackPauseWithPhase), then PauseFailed
// (setCondition) -- two status updates. The reconcile woken by the first finds the
// informer at the first, without PauseFailed. The expectation says the cache is behind,
// but its clock had been running since an older write, so persistRuntimeView reported
// "unsatisfiedDuration 1m13s", took the 10s stale-cache valve and wrote anyway. Its
// merge patch carries the whole `conditions` list computed from that view, so the
// condition the server already held was replaced by a list that never saw it: the
// e2e controller log shows conditions [Ready], nothing else, in the same second as
// "SandboxSnapshot Failed" -- and nothing writes PauseFailed again.
//
// The clock is TestWM20ExpectRestartsTheStalenessClock. This is the valve: once it
// is open the view is known to be behind, and a write computed from it must not
// replace what the server holds.
type wm20ValveOpen struct{}

func (wm20ValveOpen) Expect(metav1.Object)  {}
func (wm20ValveOpen) Observe(metav1.Object) {}
func (wm20ValveOpen) Delete(metav1.Object)  {}

// IsSatisfied answers as the controller's expectation did in the e2e run.
func (wm20ValveOpen) IsSatisfied(metav1.Object) (bool, time.Duration) {
	return false, 73 * time.Second
}

func TestWM20StatusWriteFromStaleViewKeepsPauseFailed(t *testing.T) {
	ctx := context.Background()
	bs := &sandboxv1alpha1.BatchSandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "wm20-bs",
			Namespace:  "default",
			Generation: 2,
			UID:        "wm20-uid",
			Annotations: map[string]string{
				annotationSandboxEndpoints: `["10.0.0.20"]`,
			},
		},
		Spec: sandboxv1alpha1.BatchSandboxSpec{
			Pause:    ptr.To(true),
			Replicas: ptr.To(int32(1)),
			Template: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: "img"}},
				},
			},
		},
		Status: sandboxv1alpha1.BatchSandboxStatus{
			ObservedGeneration:      1,
			PauseObservedGeneration: 2,
			Phase:                   sandboxv1alpha1.BatchSandboxPhasePausing,
			Replicas:                1,
			Allocated:               1,
			Ready:                   1,
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wm20-bs-0",
			Namespace: "default",
			Labels: map[string]string{
				labelBatchSandboxNameKey:     "wm20-bs",
				labelBatchSandboxPodIndexKey: "0",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: sandboxv1alpha1.GroupVersion.String(),
				Kind:       "BatchSandbox",
				Name:       "wm20-bs",
				UID:        "wm20-uid",
				Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.20",
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	// The reconciler's reads of the BatchSandbox come from an informer. While
	// informerAt is set they answer with that copy, as a cache one update behind does;
	// a plain fake client would answer every read with the server's latest object and
	// hide exactly the lag this is about.
	var informerAt *sandboxv1alpha1.BatchSandbox
	fakeClient := fake.NewClientBuilder().
		WithScheme(testscheme).
		WithIndex(&corev1.Pod{}, fieldindex.IndexNameForOwnerRefUID, fieldindex.OwnerIndexFunc).
		WithStatusSubresource(&sandboxv1alpha1.BatchSandbox{}).
		WithObjects(bs, pod).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, k client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if out, ok := obj.(*sandboxv1alpha1.BatchSandbox); ok && informerAt != nil && k.Name == informerAt.Name {
					informerAt.DeepCopyInto(out)
					return nil
				}
				return c.Get(ctx, k, obj, opts...)
			},
		}).
		Build()
	r := &BatchSandboxReconciler{
		Client:              fakeClient,
		Scheme:              testscheme,
		Recorder:            record.NewFakeRecorder(10),
		StatusRVExpectation: expectations.NewResourceVersionExpectation(),
	}
	key := types.NamespacedName{Namespace: "default", Name: "wm20-bs"}

	// The snapshot failed: the pause handler's two writes, through the real code.
	working := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, working))
	require.NoError(t, r.ackPauseWithPhase(ctx, working, sandboxv1alpha1.BatchSandboxPhaseSucceed, ""))

	// What the informer holds when the next reconcile starts: the first write only.
	staleView := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, staleView))

	require.NoError(t, r.setCondition(ctx, working, sandboxv1alpha1.BatchSandboxConditionPauseFailed,
		sandboxv1alpha1.ConditionTrue, "SnapshotFailed", "Job has reached the specified backoff limit"))
	server := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, server))
	require.NotEqual(t, staleView.ResourceVersion, server.ResourceVersion,
		"fixture: the server must be ahead of the view the reconcile works from")
	require.True(t, hasTrueBatchSandboxCondition(server.Status.Conditions, sandboxv1alpha1.BatchSandboxConditionPauseFailed),
		"fixture: setCondition must have written PauseFailed")

	// The reconcile on the stale view, past the stale-cache valve, with the informer
	// still at the first write.
	informerAt = staleView.DeepCopy()
	r.StatusRVExpectation = wm20ValveOpen{}
	view := buildRuntimeView(staleView, []*corev1.Pod{pod})
	require.NotEqual(t, staleView.Status, *view.status, "fixture: the reconcile must have a status to write")
	requeue, _ := r.persistRuntimeView(ctx, staleView, view)

	informerAt = nil
	after := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, after))
	var pauseFailed *sandboxv1alpha1.BatchSandboxCondition
	for i := range after.Status.Conditions {
		if after.Status.Conditions[i].Type == sandboxv1alpha1.BatchSandboxConditionPauseFailed {
			pauseFailed = &after.Status.Conditions[i]
		}
	}
	require.NotNil(t, pauseFailed,
		"a status write computed from a view without PauseFailed removed it from the server: conditions now %+v",
		after.Status.Conditions)
	assert.Equal(t, sandboxv1alpha1.ConditionTrue, pauseFailed.Status)
	assert.Equal(t, "SnapshotFailed", pauseFailed.Reason)
	assert.Equal(t, sandboxv1alpha1.BatchSandboxPhaseSucceed, after.Status.Phase)
	assert.NotZero(t, requeue, "a refused write must come back to the object")
}
