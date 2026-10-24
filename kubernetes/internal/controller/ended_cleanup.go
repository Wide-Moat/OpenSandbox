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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	controllerutils "github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/controller"
)

// cleanupEndedSandbox runs in the lifecycle reconciler before recovery or scaling.
// A separate reaper must not delete parents from an earlier child snapshot.
// The feature is opt-in; missing or invalid configuration preserves existing behavior.
func (r *BatchSandboxReconciler) cleanupEndedSandbox(ctx context.Context, observed *sandboxv1alpha1.BatchSandbox) (bool, time.Duration, error) {
	if r.FeatureConfig == nil {
		return false, 0, nil
	}
	grace := r.FeatureConfig.duration("ended-sandbox-grace", 0)
	if grace <= 0 {
		return false, 0, nil
	}
	if !r.LeaderElectionEnabled {
		return true, 0, fmt.Errorf("ended cleanup requires leader election")
	}
	if r.APIReader == nil {
		return true, 0, fmt.Errorf("ended cleanup requires an uncached API reader")
	}
	current := &sandboxv1alpha1.BatchSandbox{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(observed), current); err != nil {
		if apierrors.IsNotFound(err) {
			return true, 0, nil
		}
		return true, 0, err
	}
	if current.UID != observed.UID || current.Generation != observed.Generation {
		return true, time.Second, nil
	}
	if current.DeletionTimestamp != nil {
		// Existing task finalizers still need the rest of reconciliation.
		return false, 0, nil
	}
	switch current.Status.Phase {
	case sandboxv1alpha1.BatchSandboxPhasePaused, sandboxv1alpha1.BatchSandboxPhasePausing, sandboxv1alpha1.BatchSandboxPhaseResuming:
		return false, 0, nil
	}
	if current.Spec.Replicas == nil || *current.Spec.Replicas < 1 {
		return false, 0, nil
	}
	list := &corev1.PodList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(current.Namespace)); err != nil {
		return true, 0, err
	}
	var pods []*corev1.Pod
	for i := range list.Items {
		pod := &list.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner != nil && owner.UID == current.UID {
			pods = append(pods, pod)
		}
	}
	if len(pods) != int(*current.Spec.Replicas) {
		return false, 0, nil
	}
	now := time.Now()
	var wait time.Duration
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil || (pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed) {
			return false, 0, nil
		}
		// Recovery owns pending provisioning failures until its bounded attempts are spent.
		// Never use cleanup to overtake a recovery that can create a replacement child.
		if current.Status.Phase == "" || current.Status.Phase == sandboxv1alpha1.BatchSandboxPhasePending {
			if failure, ok := detectProvisioningFailure(pod); ok && !failure.Permanent && podRecoveryBudgets.count(controllerutils.GetControllerKey(current), current.Generation) < r.podRecoveryMaxAttempts() {
				return false, 0, nil
			}
		}
		finished := endedCleanupFinish(pod)
		if finished.IsZero() {
			return false, 0, nil
		}
		if remaining := grace - now.Sub(finished); remaining > wait {
			wait = remaining
		}
	}
	if wait > 0 {
		return false, wait, nil
	}
	uid, rv := current.UID, current.ResourceVersion
	err := r.Delete(ctx, current, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	if apierrors.IsConflict(err) {
		return true, time.Second, nil
	}
	if apierrors.IsNotFound(err) {
		return true, 0, nil
	}
	return true, 0, err
}

// endedCleanupFinish requires status evidence for declared containers, rather than
// mistaking a partially reported terminal pod for a fully stopped workload.
func endedCleanupFinish(pod *corev1.Pod) time.Time {
	var latest time.Time
	statuses := map[string]corev1.ContainerStatus{}
	for _, s := range pod.Status.ContainerStatuses {
		statuses[s.Name] = s
	}
	inits := map[string]corev1.ContainerStatus{}
	initFailed := false
	for _, s := range pod.Status.InitContainerStatuses {
		inits[s.Name] = s
		if s.State.Running != nil {
			return time.Time{}
		}
		if term := s.State.Terminated; term != nil {
			if term.FinishedAt.IsZero() {
				return time.Time{}
			}
			if term.FinishedAt.Time.After(latest) {
				latest = term.FinishedAt.Time
			}
			if term.ExitCode != 0 {
				initFailed = true
			}
		}
	}
	for _, s := range statuses {
		if s.State.Running != nil {
			return time.Time{}
		}
		if term := s.State.Terminated; term != nil {
			if term.FinishedAt.IsZero() {
				return time.Time{}
			}
			if term.FinishedAt.Time.After(latest) {
				latest = term.FinishedAt.Time
			}
		}
	}
	completed := 0
	for _, declared := range pod.Spec.Containers {
		if s, ok := statuses[declared.Name]; ok && s.State.Terminated != nil {
			completed++
		}
	}
	if completed == len(pod.Spec.Containers) && completed > 0 {
		for _, declared := range pod.Spec.InitContainers {
			if s, ok := inits[declared.Name]; !ok || s.State.Terminated == nil {
				return time.Time{}
			}
		}
		return latest
	}
	if completed == 0 && initFailed {
		return latest
	}
	return time.Time{}
}
