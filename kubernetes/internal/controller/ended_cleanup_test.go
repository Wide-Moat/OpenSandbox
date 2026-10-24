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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"testing"
	"time"
)

func TestEndedCleanupActivationRequiresLeadership(t *testing.T) {
	r := &BatchSandboxReconciler{FeatureConfig: NewFeatureConfig()}
	r.FeatureConfig.Load(map[string]string{"ended-sandbox-grace": "10m"})
	_, _, err := r.cleanupEndedSandbox(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "leader election") {
		t.Fatalf("want fail-closed leadership error before API access, got %v", err)
	}
}

func TestEndedCleanupDisabled(t *testing.T) {
	for _, raw := range []string{"", "0s", "-1m", "invalid"} {
		r := &BatchSandboxReconciler{FeatureConfig: NewFeatureConfig()}
		r.FeatureConfig.Load(map[string]string{"ended-sandbox-grace": raw})
		handled, wait, err := r.cleanupEndedSandbox(context.Background(), nil)
		if handled || wait != 0 || err != nil {
			t.Fatalf("disabled value %q changed behavior: %v %v %v", raw, handled, wait, err)
		}
	}
}

func TestEndedCleanupFinishEvidence(t *testing.T) {
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	term := func(name string, code int, at time.Time) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: int32(code), FinishedAt: metav1.NewTime(at)}}}
	}
	base := func() *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{term("main", 0, stamp)}}}
	}
	for _, tc := range []struct {
		name string
		edit func(*corev1.Pod)
		want time.Time
	}{
		{"complete", func(p *corev1.Pod) {}, stamp},
		{"missing declared main", func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "other"}) }, time.Time{}},
		{"undated termination", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = metav1.Time{} }, time.Time{}},
		{"running main", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
		}, time.Time{}},
		{"missing declared init", func(p *corev1.Pod) { p.Spec.InitContainers = []corev1.Container{{Name: "init"}} }, time.Time{}},
		{"running init sidecar", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init"}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
		}, time.Time{}},
		{"later init finish", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init"}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{term("init", 0, stamp.Add(time.Minute))}
		}, stamp.Add(time.Minute)},
		{"init failed before main starts", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init"}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{term("init", 1, stamp)}
			p.Status.ContainerStatuses = nil
		}, stamp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.edit(p)
			if got := endedCleanupFinish(p); !got.Equal(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
