/*
Copyright 2026 Alibaba Group Holding Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
)

// An empty list must leave the cache cluster-wide, which is what every existing
// deployment has. This is the guard: without it, a change that always scoped the cache
// would pass the tests below while silently narrowing what running controllers see.
func TestWM6NoNamespacesLeavesTheCacheClusterWide(t *testing.T) {
	for _, in := range []string{"", "   ", ",", " , ,"} {
		options := ctrl.Options{}
		applyWatchNamespaces(&options, in)
		if len(options.Cache.DefaultNamespaces) != 0 {
			t.Fatalf("input %q scoped the cache to %v; empty must stay cluster-wide",
				in, options.Cache.DefaultNamespaces)
		}
	}
}

// The cache must be restricted to exactly the namespaces named.
//
// Leader election does not cover this. The lease lives in the controller's own
// namespace, so it coordinates replicas of ONE installation and knows nothing about a
// second one; two installations in a cluster both elect a leader, both watch
// everything, and each acts on the other's pool pods.
func TestWM6NamespacesAreScopedToWhatWasNamed(t *testing.T) {
	options := ctrl.Options{}
	applyWatchNamespaces(&options, "sandbox-prod")

	got := options.Cache.DefaultNamespaces
	if len(got) != 1 {
		t.Fatalf("expected exactly one namespace, got %v", got)
	}
	if _, ok := got["sandbox-prod"]; !ok {
		t.Fatalf("expected the cache scoped to sandbox-prod, got %v", got)
	}
}

func TestWM6SeveralNamespacesAndSurroundingSpaceAreAccepted(t *testing.T) {
	options := ctrl.Options{}
	applyWatchNamespaces(&options, " sandbox-prod , sandbox-stage ,, ")

	got := options.Cache.DefaultNamespaces
	if len(got) != 2 {
		t.Fatalf("expected two namespaces, got %v", got)
	}
	for _, want := range []string{"sandbox-prod", "sandbox-stage"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %s among the watched namespaces, got %v", want, got)
		}
	}
}
