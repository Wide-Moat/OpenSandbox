// Copyright 2026 The OpenSandbox Authors
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
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/expectations"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/fieldindex"
)

// TestWM22EndedCleanup executes the same reconciliation on the fork and upstream.
// Optional fields use reflection so upstream fails on the retained parent, not compilation.
func TestWM22EndedCleanup(t *testing.T) {
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true, BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir()}
	config, err := environment.Start()
	if err != nil {
		t.Fatalf("WM-TEST-BUILD-FAILED: real API test environment: %v", err)
	}
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	ctx, stop := context.WithCancel(context.Background())
	manager, err := ctrl.NewManager(config, ctrl.Options{Scheme: testscheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	require.NoError(t, fieldindex.RegisterFieldIndexes(manager.GetCache()))
	done := make(chan error, 1)
	go func() { done <- manager.Start(ctx) }()
	t.Cleanup(func() { stop(); require.NoError(t, <-done) })
	require.True(t, manager.GetCache().WaitForCacheSync(ctx))
	api, err := client.New(config, client.Options{Scheme: testscheme})
	require.NoError(t, err)
	r := &BatchSandboxReconciler{Client: manager.GetClient(), Scheme: testscheme, Recorder: record.NewFakeRecorder(20), StatusRVExpectation: expectations.NewResourceVersionExpectation()}
	value := reflect.ValueOf(r).Elem()
	if f := value.FieldByName("FeatureConfig"); f.IsValid() && f.CanSet() {
		f.Set(reflect.New(f.Type().Elem()))
		f.MethodByName("Load").Call([]reflect.Value{reflect.ValueOf(map[string]string{"ended-sandbox-grace": "10m"})})
	}
	if f := value.FieldByName("APIReader"); f.IsValid() && f.CanSet() {
		f.Set(reflect.ValueOf(api))
	}
	if f := value.FieldByName("LeaderElectionEnabled"); f.IsValid() && f.CanSet() {
		f.SetBool(true)
	}
	bs := &sandboxv1alpha1.BatchSandbox{ObjectMeta: metav1.ObjectMeta{Name: "wm22-ended", Namespace: "default"}, Spec: sandboxv1alpha1.BatchSandboxSpec{Replicas: ptr.To(int32(1)), Template: &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "busybox:latest"}}}}}}
	require.NoError(t, api.Create(ctx, bs))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "wm22-ended-0", Namespace: "default", Labels: map[string]string{labelBatchSandboxNameKey: bs.Name, labelBatchSandboxPodIndexKey: "0"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(bs, sandboxv1alpha1.GroupVersion.WithKind("BatchSandbox"))}}, Spec: *bs.Spec.Template.Spec.DeepCopy()}
	require.NoError(t, api.Create(ctx, pod))
	pod.Status.Phase = corev1.PodSucceeded
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "main", Image: "busybox:latest", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(time.Now().Add(-20 * time.Minute))}}}}
	require.NoError(t, api.Status().Update(ctx, pod))
	for _, obj := range []client.Object{bs, pod} {
		require.Eventually(t, func() bool {
			cached := obj.DeepCopyObject().(client.Object)
			return r.Get(ctx, client.ObjectKeyFromObject(obj), cached) == nil && cached.GetResourceVersion() == obj.GetResourceVersion()
		}, 5*time.Second, 20*time.Millisecond)
	}
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(bs)})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(api.Get(ctx, client.ObjectKeyFromObject(bs), &sandboxv1alpha1.BatchSandbox{}))
	}, time.Second, 20*time.Millisecond, "completed sandbox must be removed after configured grace")
}
