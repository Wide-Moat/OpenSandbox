// Copyright 2025 Alibaba Group Holding Ltd.
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
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	taskscheduler "github.com/alibaba/OpenSandbox/sandbox-k8s/internal/scheduler"
)

// Reflection keeps the behavioral regression executable on upstream, where the
// registry field is absent. Missing configuration still reaches real pause code.
func setPauseRegistryForTest(r *BatchSandboxReconciler, registry string) {
	field := reflect.ValueOf(r).Elem().FieldByName("SnapshotRegistry")
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
		field.SetString(registry)
	}
}

// pauseFixture builds a BatchSandbox that is being paused, plus its pod.
func pauseFixture(name string) (*sandboxv1alpha1.BatchSandbox, *corev1.Pod) {
	bs := &sandboxv1alpha1.BatchSandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Generation: 2,
			UID:        types.UID(name + "-uid"),
		},
		Spec: sandboxv1alpha1.BatchSandboxSpec{
			Pause:    ptr.To(true),
			Replicas: ptr.To(int32(1)),
			Template: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: "img"}},
				},
			},
			TaskTemplate: &sandboxv1alpha1.TaskTemplateSpec{
				Spec: sandboxv1alpha1.TaskSpec{
					Process: &sandboxv1alpha1.ProcessTask{Command: []string{"sleep", "3600"}},
				},
			},
		},
		Status: sandboxv1alpha1.BatchSandboxStatus{
			PauseObservedGeneration: 1,
			Phase:                   sandboxv1alpha1.BatchSandboxPhaseSucceed,
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-0",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: sandboxv1alpha1.GroupVersion.String(),
				Kind:       "BatchSandbox",
				Name:       name,
				UID:        types.UID(name + "-uid"),
			}},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.1"},
	}
	return bs, pod
}

func TestWM9PausePreflight_MissingRegistryPreservesRunningTask(t *testing.T) {
	ctx := context.Background()
	bs, pod := pauseFixture("missing-registry")
	r := newTestReconciler(bs, pod)
	setPauseRegistryForTest(r, "")
	scheduler := &recordingTaskScheduler{tasks: []taskscheduler.Task{fakeSchedulerTask{
		name: bs.Name + "-0", state: taskscheduler.RunningTaskState, podName: pod.Name, released: false,
	}}}
	key := types.NamespacedName{Namespace: bs.Namespace, Name: bs.Name}
	r.taskSchedulers.Store(key.String(), scheduler)
	_, _, err := r.dispatchPauseResume(ctx, bs)
	require.NoError(t, err)
	assert.Zero(t, scheduler.stopCalls, "unconfigured snapshots must not stop a running task")
	assert.Zero(t, scheduler.scheduleCalls)
	updated := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, updated))
	assert.Equal(t, sandboxv1alpha1.BatchSandboxPhaseSucceed, updated.Status.Phase)
	assert.Equal(t, updated.Generation, updated.Status.PauseObservedGeneration)
	var reason string
	for _, cond := range updated.Status.Conditions {
		if cond.Type == sandboxv1alpha1.BatchSandboxConditionPauseFailed && cond.Status == sandboxv1alpha1.ConditionTrue {
			reason = cond.Reason
		}
	}
	assert.Equal(t, "RegistryNotConfigured", reason)
	snap := &sandboxv1alpha1.SandboxSnapshot{}
	assert.True(t, apierrors.IsNotFound(r.Get(ctx, types.NamespacedName{Namespace: bs.Namespace, Name: internalPauseSnapshotName(bs.Name)}, snap)))
	require.NoError(t, r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, &corev1.Pod{}))
	_, handled, err := r.dispatchPauseResume(ctx, updated)
	require.NoError(t, err)
	assert.False(t, handled, "acknowledged failed request must not repeat task cleanup")
	assert.Zero(t, scheduler.stopCalls)
}

func TestPausePreflight_StatusFailureDoesNotAcknowledgeOrStop(t *testing.T) {
	ctx := context.Background()
	bs, pod := pauseFixture("status-error")
	r := newTestReconciler(bs, pod)
	setPauseRegistryForTest(r, "")
	underlying := r.Client
	r.Client = interceptor.NewClient(underlying.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if sub == "status" {
				return fmt.Errorf("injected status failure")
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	scheduler := &recordingTaskScheduler{}
	key := types.NamespacedName{Namespace: bs.Namespace, Name: bs.Name}
	r.taskSchedulers.Store(key.String(), scheduler)
	_, _, err := r.dispatchPauseResume(ctx, bs)
	require.ErrorContains(t, err, "injected status failure")
	assert.Zero(t, scheduler.stopCalls)
	assert.Equal(t, int64(1), bs.Status.PauseObservedGeneration)
	updated := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, underlying.Get(ctx, key, updated))
	assert.Equal(t, int64(1), updated.Status.PauseObservedGeneration)
	assert.Equal(t, sandboxv1alpha1.BatchSandboxPhaseSucceed, updated.Status.Phase)
	// Once persistence recovers the same request must still be handled.
	r.Client = underlying
	_, handled, err := r.dispatchPauseResume(ctx, updated)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, updated.Generation, updated.Status.PauseObservedGeneration)
	assert.Zero(t, scheduler.stopCalls)
}

func TestPausePreflight_NewRequestAfterRegistryConfigured(t *testing.T) {
	ctx := context.Background()
	bs, pod := pauseFixture("retry")
	r := newTestReconciler(bs, pod)
	setPauseRegistryForTest(r, "")
	scheduler := &recordingTaskScheduler{tasks: []taskscheduler.Task{fakeSchedulerTask{
		name: pod.Name, state: taskscheduler.RunningTaskState, podName: pod.Name, released: false,
	}}}
	key := types.NamespacedName{Namespace: bs.Namespace, Name: bs.Name}
	r.taskSchedulers.Store(key.String(), scheduler)
	_, _, err := r.dispatchPauseResume(ctx, bs)
	require.NoError(t, err)
	assert.Zero(t, scheduler.stopCalls)
	setPauseRegistryForTest(r, "registry.example.invalid/snapshots")
	require.NoError(t, r.Get(ctx, key, bs))
	bs.Generation++
	require.NoError(t, r.Update(ctx, bs))
	_, handled, err := r.dispatchPauseResume(ctx, bs)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, 1, scheduler.stopCalls)
	assert.Equal(t, sandboxv1alpha1.BatchSandboxPhasePausing, bs.Status.Phase)
	updated := &sandboxv1alpha1.BatchSandbox{}
	require.NoError(t, r.Get(ctx, key, updated))
	for _, cond := range updated.Status.Conditions {
		assert.False(t, cond.Type == sandboxv1alpha1.BatchSandboxConditionPauseFailed && cond.Status == sandboxv1alpha1.ConditionTrue)
	}
}
