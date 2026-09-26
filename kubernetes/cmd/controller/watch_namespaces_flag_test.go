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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildController builds this command, so the tests run what an operator runs and
// compile on a tree without the change. A failed build says so with
// WM-TEST-BUILD-FAILED, which hack/wm-fail-on-base.sh reads as "did not reach its
// assertion" rather than as a failure on behaviour.
func buildController(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "controller")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("WM-TEST-BUILD-FAILED: building the controller: %v\n%s", err, out)
	}
	return bin
}

// The flag must exist and be documented, which is what an operator actually reaches
// for. Asserted by running the built binary's own help output rather than by naming a
// Go symbol: on a tree without the change this compiles, runs, and fails on the
// ABSENCE OF THE OPTION rather than on a missing function.
func TestWM6TheFlagIsOffered(t *testing.T) {
	bin := buildController(t)

	// -h exits non-zero by convention; the output is what matters.
	out, _ := exec.Command(bin, "-h").CombinedOutput()
	if !strings.Contains(string(out), "-watch-namespaces") {
		t.Fatalf("the controller offers no -watch-namespaces flag, so an operator "+
			"running two installations in one cluster cannot scope either of them.\n"+
			"flags offered:\n%s", out)
	}
}

// The flag is APPLIED by the controller as it starts, not only parsed. The unit tests
// drive registerWatchNamespacesFlag themselves, so they stay green when main parses the
// flag and hands ctrl.NewManager options that never went through it -- a cluster-wide
// cache behind a flag that says otherwise, and a second installation's controller
// reconciling the first's sandboxes. Measured: replacing the call with `_ = scopeCache`
// passed every other WM-6 test.
//
// Run against an API server that is not there: the options are built, and the scope
// applied, before anything dials it.
func TestWM6TheFlagIsAppliedAtStartup(t *testing.T) {
	bin := buildController(t)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: nowhere
  cluster:
    server: https://127.0.0.1:1
contexts:
- name: nowhere
  context:
    cluster: nowhere
    user: nobody
current-context: nowhere
users:
- name: nobody
  user:
    token: none
`), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, bin,
		"--watch-namespaces=sandbox-a,sandbox-b",
		"--health-probe-bind-address=0",
		"--metrics-bind-address=0")
	run.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	out, _ := run.CombinedOutput()

	for _, want := range []string{"watching namespaces", "sandbox-a,sandbox-b"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("the controller did not apply --watch-namespaces as it built its "+
				"manager (no %q in its output), so its cache stays cluster-wide:\n%s", want, out)
		}
	}
}
