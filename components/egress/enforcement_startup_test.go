// Copyright 2026 Alibaba Group Holding Ltd.
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

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buildEgress builds the component. The tests here run the process rather than call
// its functions, so that they compile on a tree without the change and fail there on
// what the process does.
func buildEgress(t *testing.T) string {
	t.Helper()
	// hack/wm-fail-on-base.sh builds the binary itself when it runs a test as root in a
	// throwaway network namespace, where the go tool has neither the network nor the
	// user's build cache.
	if prebuilt := os.Getenv("WM_EGRESS_BINARY"); prebuilt != "" {
		return prebuilt
	}
	// A failed build says so with WM-TEST-BUILD-FAILED, which hack/wm-fail-on-base.sh
	// reads as "did not reach its assertion" rather than as a failure on behaviour.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("WM-TEST-BUILD-FAILED: the test builds the component, so it needs the go tool on PATH: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "egress")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("WM-TEST-BUILD-FAILED: building the component: %v\n%s", err, out)
	}
	return bin
}

// egressEnv is the environment every run gets: its own HOME, and the policy API on an
// ephemeral port, clear of any real sidecar on this machine.
func egressEnv(t *testing.T, env []string) []string {
	return append(append(os.Environ(), "HOME="+t.TempDir(),
		"OPENSANDBOX_EGRESS_HTTP_ADDR=127.0.0.1:0"), env...)
}

// startEgress builds the component and starts it with extra environment, returning
// what it printed. It must exit by itself: every configuration these tests give it is
// one it has to refuse at startup.
//
// Asserted on the process, not on a helper. A tree that never validates the input still
// exits here -- later, on netfilter it cannot install -- so the exit status proves
// nothing; the tests read whether the refusal names what is wrong, and that nothing
// reached netfilter first.
func startEgress(t *testing.T, env ...string) string {
	t.Helper()
	bin := buildEgress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, bin)
	run.Env = egressEnv(t, env)
	out, err := run.CombinedOutput()

	require.NoError(t, ctx.Err(), "the component kept running:\n%s", out)
	require.Error(t, err, "the component started:\n%s", out)
	return string(out)
}

// lockedBuffer collects a child's output while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runEgressUntil starts the component, waits until it prints marker, then stops it with
// SIGTERM -- as the kubelet does -- and returns everything it printed, shutdown
// included, and whether the marker appeared. A process that exits first, or does not
// print the marker within the timeout, returns what it printed and false.
func runEgressUntil(t *testing.T, marker string, env ...string) (string, bool) {
	t.Helper()
	bin := buildEgress(t)
	var out lockedBuffer
	run := exec.Command(bin)
	run.Env = egressEnv(t, env)
	run.Stdout, run.Stderr = &out, &out
	require.NoError(t, run.Start())
	exited := make(chan struct{})
	go func() { _ = run.Wait(); close(exited) }()

	deadline := time.After(30 * time.Second)
wait:
	for !strings.Contains(out.String(), marker) {
		select {
		case <-exited:
			break wait
		case <-deadline:
			break wait
		case <-time.After(20 * time.Millisecond):
		}
	}
	_ = run.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		_ = run.Process.Kill()
		<-exited
		t.Errorf("the component did not stop within 15s of SIGTERM")
	}
	final := out.String()
	return final, strings.Contains(final, marker)
}

// An unrecognised OPENSANDBOX_EGRESS_ENFORCEMENT must stop the sidecar at startup, and
// say which variable is wrong.
//
// Every call site asks constants.EnforcementIsExternal, which reads a bad value as "not
// external" so that a typo can never switch in-pod enforcement OFF. That half is safe
// on its own, and it is also the whole problem: a misspelt "externl" then runs the
// sidecar path the operator was configuring away from, and under gVisor the only
// symptom is a crash-loop whose message is about netlink.
func TestWM1UnknownEnforcementIsRefusedAtStartup(t *testing.T) {
	out := startEgress(t, "OPENSANDBOX_EGRESS_ENFORCEMENT=externl")

	// The log line is JSON, so the value's quotes arrive escaped; match the two parts.
	require.Contains(t, out, "unknown OPENSANDBOX_EGRESS_ENFORCEMENT value",
		"the refusal must name the variable, not fail later on netfilter:\n%s", out)
	require.Contains(t, out, "externl", "the refusal must name the value:\n%s", out)
	require.NotContains(t, out, "iptables",
		"refused before anything acts on the value, so no redirect is attempted:\n%s", out)
}

// External enforcement installs no netfilter rules in the pod; mode dns+nft IS an
// in-pod nftables policy. Given both, the sidecar used to announce that it was not
// installing the DNS redirect and then apply the nftables policy anyway -- which
// under gVisor fails exactly the way external enforcement exists to avoid. The pair is
// refused instead, naming both variables.
func TestWM1ExternalEnforcementRefusesAnNftMode(t *testing.T) {
	out := startEgress(t,
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns+nft")

	require.Contains(t, out, "OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"the refusal must name the enforcement setting:\n%s", out)
	require.Contains(t, out, "OPENSANDBOX_EGRESS_MODE=dns+nft",
		"the refusal must name the mode that contradicts it:\n%s", out)
	require.NotContains(t, out, "applying nftables",
		"refused before any nftables policy is applied:\n%s", out)
}

// External enforcement installs no DNS redirect at startup and removes none at shutdown.
// Run to "policy server listening", the line after the redirect would have been
// installed, and then stopped with SIGTERM so the shutdown path runs too. A tree that
// ignores the setting attempts the redirect, and off a privileged Linux host that is
// fatal: the process never gets that far.
func TestWM1ExternalEnforcementInstallsAndRemovesNoRedirect(t *testing.T) {
	out, up := runEgressUntil(t, "policy server listening",
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns")

	require.True(t, up, "the sidecar did not come up under external enforcement:\n%s", out)
	require.Contains(t, out, "egress shutdown complete", "the shutdown path did not run:\n%s", out)
	require.NotContains(t, out, "installing iptables DNS redirect",
		"external enforcement must not install a redirect:\n%s", out)
	require.NotContains(t, out, "iptables DNS redirect removed",
		"nothing was installed, so nothing may be removed:\n%s", out)
}

// The guard: by default the redirect is still attempted, which also proves the log line
// the test above looks for is the one SetupRedirect prints. Without it, a reworded line
// would make that test's NotContains vacuous.
func TestWM1SidecarEnforcementStillInstallsTheRedirect(t *testing.T) {
	out, attempted := runEgressUntil(t, "installing iptables DNS redirect",
		"OPENSANDBOX_EGRESS_MODE=dns")

	require.True(t, attempted, "the default must still install the DNS redirect:\n%s", out)
}
