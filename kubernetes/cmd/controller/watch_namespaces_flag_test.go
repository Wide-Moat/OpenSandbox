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
	"os/exec"
	"strings"
	"testing"
)

// The flag must exist and be documented, which is what an operator actually reaches
// for. Asserted by running the built binary's own help output rather than by naming a
// Go symbol: on a tree without the change this compiles, runs, and fails on the
// ABSENCE OF THE OPTION rather than on a missing function.
func TestWM6TheFlagIsOffered(t *testing.T) {
	bin := t.TempDir() + "/controller"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building the controller failed: %v\n%s", err, out)
	}

	// -h exits non-zero by convention; the output is what matters.
	out, _ := exec.Command(bin, "-h").CombinedOutput()
	if !strings.Contains(string(out), "-watch-namespaces") {
		t.Fatalf("the controller offers no -watch-namespaces flag, so an operator "+
			"running two installations in one cluster cannot scope either of them.\n"+
			"flags offered:\n%s", out)
	}
}
