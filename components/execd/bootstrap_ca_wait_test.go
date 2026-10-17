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

//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// WM-28. bootstrap.sh runs as it ships, with the environment variables that name its files
// given as literals, so this builds on a tree without the change. On upstream it fails
// because upstream has neither the path overrides nor the 50 ms poll: the run tests never
// see execd start (the script waits for the fixed /opt path), and the loop test sees
// the old loop sleep a whole second. Only the loop test fails there on the poll itself.
//
// Everything is in a temporary directory, with no root: a stub `id` and `sudo` keep the
// system-store step away from the host's, and the stub `sudo` runs only the fake JDK's
// keytool, never one that happens to be installed.

// wm28Write writes an executable stub that answers --wm28-warm at once. A stub that was
// written a moment ago is slow to run the first time on some hosts (macOS scans it): each
// is run once before the measurement, so that what is measured is the script and not the
// host's first-execution cost.
func wm28Write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	lines := strings.SplitN(body, "\n", 2)
	require.True(t, strings.HasPrefix(lines[0], "#!"), "stub without an interpreter line: %s", path)
	body = lines[0] + "\n[ \"${1:-}\" = --wm28-warm ] && exit 0\n" + lines[1]
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	if out, err := exec.Command(path, "--wm28-warm").CombinedOutput(); err != nil {
		t.Fatalf("warming %s: %v\n%s", path, err, out)
	}
}

type wm28Opts struct {
	background  bool // OPENSANDBOX_CA_TRUST_BACKGROUND=true
	interceptOn bool // OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT=true
	logPath     string
}

type wm28Run struct {
	caPath, mergedPath string
	started, caWritten time.Time
	markerAtStart      bool   // the done marker existed when execd started
	callsAtStart       string // what the stub keytool and certutil had logged by then
	callLog, doneFile  string
	execdEnv           string
}

func (r *wm28Run) calls() string {
	b, _ := os.ReadFile(r.callLog)
	return string(b)
}

func (r *wm28Run) waitForMarker(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(r.doneFile); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the done marker %s never appeared", r.doneFile)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *wm28Run) env(name string) string {
	for _, line := range strings.Split(r.execdEnv, "\n") {
		if strings.HasPrefix(line, name+"=") {
			return strings.TrimPrefix(line, name+"=")
		}
	}
	return ""
}

func runBootstrapWithSlowImports(t *testing.T, o wm28Opts) *wm28Run {
	t.Helper()
	// Resolved, because bootstrap resolves the JDK's path and the stub `sudo` compares it.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	bin := filepath.Join(dir, "bin")
	jdk := filepath.Join(dir, "jdk")
	r := &wm28Run{
		callLog:    filepath.Join(dir, "calls.log"),
		doneFile:   filepath.Join(dir, "ca-trust-done"),
		caPath:     filepath.Join(dir, "ca", "mitmproxy-ca-cert.pem"),
		mergedPath: filepath.Join(dir, "merged.pem"),
	}
	startedFile := filepath.Join(dir, "execd-started")
	envFile := filepath.Join(dir, "execd-env")
	require.NoError(t, os.MkdirAll(filepath.Dir(r.caPath), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "home"), 0o755))

	wm28Write(t, filepath.Join(bin, "id"), "#!/bin/sh\necho 1000\n")
	wm28Write(t, filepath.Join(bin, "sudo"), `#!/bin/sh
[ "$1" = "-n" ] && shift
case "$1" in
"`+jdk+`"/*) exec "$@" ;;
*) exit 0 ;;
esac
`)
	for _, tool := range []string{"update-ca-certificates", "update-ca-trust"} {
		wm28Write(t, filepath.Join(bin, tool), "#!/bin/sh\nexit 0\n")
	}
	// No certifi to ask for: bootstrap looks for one with python, and where python is a
	// shim that launches an installer (macOS without the developer tools) that takes
	// seconds and has nothing to do with what is measured.
	for _, tool := range []string{"python3", "python"} {
		wm28Write(t, filepath.Join(bin, tool), "#!/bin/sh\nexit 1\n")
	}
	// certutil's subcommand is its FIRST argument: -N creates the database, -A imports and
	// takes a second, the rest are instant.
	wm28Write(t, filepath.Join(bin, "certutil"), `#!/bin/sh
echo "certutil $*" >> "`+r.callLog+`"
case "$1" in
-N) d=""; while [ $# -gt 0 ]; do [ "$1" = "-d" ] && d="${2#*:}"; shift; done; : > "$d/cert9.db" ;;
-A) sleep 1; echo "certutil-done $1" >> "`+r.callLog+`" ;;
esac
exit 0
`)
	wm28Write(t, filepath.Join(jdk, "bin", "keytool"), `#!/bin/sh
echo "keytool $*" >> "`+r.callLog+`"
case "$*" in
*-list*) exit 1 ;;
*-importcert*) sleep 1; echo "keytool-done importcert" >> "`+r.callLog+`" ;;
esac
exit 0
`)
	require.NoError(t, os.MkdirAll(filepath.Join(jdk, "lib", "security"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(jdk, "lib", "security", "cacerts"), []byte("x"), 0o644))
	wm28Write(t, filepath.Join(dir, "execd"), `#!/bin/sh
: > "`+startedFile+`"
env > "`+envFile+`"
`)

	cmd := exec.Command("sh", "bootstrap.sh")
	cmd.Env = []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"HOME=" + filepath.Join(dir, "home"),
		"JAVA_HOME=" + jdk,
		"EXECD=" + filepath.Join(dir, "execd"),
		"EXECD_ENVS=" + filepath.Join(dir, "execd.env"),
		"EXECD_INIT=true",
		"OPENSANDBOX_MITM_CA_FILE=" + r.caPath,
		"OPENSANDBOX_MERGED_CA_FILE=" + r.mergedPath,
		"OPENSANDBOX_CA_TRUST_DONE_FILE=" + r.doneFile,
		"OPENSANDBOX_CA_TRUST_LOG=" + filepath.Join(dir, "ca-trust.log"),
	}
	if o.logPath != "" {
		cmd.Env = append(cmd.Env, "OPENSANDBOX_CA_TRUST_LOG="+o.logPath)
	}
	if o.interceptOn {
		cmd.Env = append(cmd.Env, "OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT=true")
	}
	if o.background {
		cmd.Env = append(cmd.Env, "OPENSANDBOX_CA_TRUST_BACKGROUND=true")
	}
	// Files, not pipes: a background job holding a pipe open is not what is measured here.
	stdout, err := os.Create(filepath.Join(dir, "bootstrap.out"))
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = stdout, stdout
	// Its own process group, so that whatever the background job leaves behind can be
	// reaped as a group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	pgid := cmd.Process.Pid
	finished := make(chan struct{})
	go func() { _ = cmd.Wait(); close(finished) }()
	t.Cleanup(func() {
		// Give a background import its bounded time to finish, then kill what is left of
		// the group before TempDir is removed under it.
		if o.background {
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(r.doneFile); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
		}
		stdout.Close()
	})

	// The exporter makes the CA appear a little after the container starts. Written whole,
	// then renamed, so bootstrap never sees it half-written.
	time.Sleep(100 * time.Millisecond)
	if o.interceptOn {
		require.NoError(t, os.WriteFile(r.caPath+".tmp", []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o644))
		require.NoError(t, os.Rename(r.caPath+".tmp", r.caPath))
	}
	r.caWritten = time.Now()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(startedFile); err == nil {
			r.started = time.Now()
			break
		}
		if time.Now().After(deadline) {
			out, _ := os.ReadFile(filepath.Join(dir, "bootstrap.out"))
			t.Fatalf("execd was not started within 15s of the CA appearing (a bootstrap that does not read OPENSANDBOX_MITM_CA_FILE waits for the fixed /opt path instead):\n%s", out)
		}
		time.Sleep(2 * time.Millisecond)
	}
	_, err = os.Stat(r.doneFile)
	r.markerAtStart = err == nil
	r.callsAtStart = r.calls()
	// bootstrap has become execd (init mode) and execd has exited: nothing of the shell is
	// left but a background import, which must not keep it from returning.
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatalf("bootstrap did not return")
	}
	if b, err := os.ReadFile(envFile); err == nil {
		r.execdEnv = string(b)
	}
	return r
}

// The CA variables stay in the foreground, with exactly the fixture's paths.
func (r *wm28Run) requireCaVariables(t *testing.T) {
	t.Helper()
	require.Equal(t, r.caPath, r.env("NODE_EXTRA_CA_CERTS"))
	// REQUESTS_CA_BUNDLE and SSL_CERT_FILE replace the default roots: the merged bundle when
	// one could be built from this host's roots, else the CA alone.
	want := r.caPath
	if _, err := os.Stat(r.mergedPath); err == nil {
		want = r.mergedPath
	}
	require.Equal(t, want, r.env("REQUESTS_CA_BUNDLE"))
	require.Equal(t, want, r.env("SSL_CERT_FILE"))
}

func (r *wm28Run) requireBothImports(t *testing.T, calls string) {
	t.Helper()
	// The stubs log a completion line after their second, so this asserts that the imports
	// finished, not only that they were started.
	require.Contains(t, calls, "keytool-done importcert", "the JDK import did not complete")
	require.Contains(t, calls, "certutil-done -A", "the NSS import did not complete")
}

// With OPENSANDBOX_CA_TRUST_BACKGROUND=true execd starts well inside the second the imports
// take, and the imports finish after it.
func TestWM28BackgroundImportsDoNotDelayExecd(t *testing.T) {
	r := runBootstrapWithSlowImports(t, wm28Opts{background: true, interceptOn: true})

	lag := r.started.Sub(r.caWritten)
	require.Less(t, lag, 600*time.Millisecond,
		"execd started %v after the CA appeared: the wait polls too slowly, or the NSS and JDK imports are still on the path", lag)
	require.False(t, r.markerAtStart, "the imports had finished when execd started: they did not run in the background")
	require.NotContains(t, r.callsAtStart, "certutil-done", "the NSS import had finished when execd started")

	r.waitForMarker(t)
	r.requireBothImports(t, r.calls())
	r.requireCaVariables(t)
}

// The guard: without the option the imports are done before execd starts, as they always
// were, and the marker is already there when it does.
func TestWM28DefaultKeepsTheImportsBeforeExecd(t *testing.T) {
	r := runBootstrapWithSlowImports(t, wm28Opts{interceptOn: true})

	require.True(t, r.markerAtStart, "execd started before the trust step was over")
	r.requireBothImports(t, r.callsAtStart)
	require.GreaterOrEqual(t, r.started.Sub(r.caWritten), time.Second,
		"execd started before the one-second imports could have finished")
	r.requireCaVariables(t)
}

// With interception off there is nothing to import, and the marker still appears: a caller
// that waits for it must never hang.
func TestWM28MarkerIsWrittenWhenInterceptionIsOff(t *testing.T) {
	r := runBootstrapWithSlowImports(t, wm28Opts{})

	require.True(t, r.markerAtStart, "no done marker with interception off")
	require.NotContains(t, r.calls(), "keytool -importcert")
}

// An unwritable log must not cost the imports or the marker: with the option on and a log
// that cannot be opened, the imports run in the foreground and the marker appears.
func TestWM28UnwritableLogFallsBackToForegroundImports(t *testing.T) {
	r := runBootstrapWithSlowImports(t, wm28Opts{background: true, interceptOn: true, logPath: "/nonexistent-dir/ca.log"})

	require.True(t, r.markerAtStart, "the marker was not there when execd started: the imports were not done in the foreground")
	r.requireBothImports(t, r.callsAtStart)
}

// The wait loop itself, taken out of bootstrap.sh as it is written there, with the CA
// appearing 100 ms in. A loop that sleeps a second per try cannot leave before a second.
func TestWM28CaWaitLoopNoticesTheCaWithinFiftyMilliseconds(t *testing.T) {
	script, err := os.ReadFile("bootstrap.sh")
	require.NoError(t, err)
	text := string(script)

	// The helper the new loop calls; absent from a script that has no such loop.
	helper := regexp.MustCompile(`(?ms)^_now_ms\(\) \{.*?^\}\n`).FindString(text)
	// From the loop's first statement to the `done` that closes it.
	loop := regexp.MustCompile(`(?ms)^\t(?:i=0|_wait_budget_ms=300000)\n.*?^\tdone\n`).FindString(text)
	require.NotEmpty(t, loop, "the CA wait loop was not found in bootstrap.sh")

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	snippet := "MITM_CA='" + ca + "'\n" + helper + loop
	cmd := exec.Command("sh", "-c", snippet)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	require.NoError(t, cmd.Start())
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, os.WriteFile(ca+".tmp", []byte("x"), 0o644))
	require.NoError(t, os.Rename(ca+".tmp", ca))
	appeared := time.Now()
	require.NoError(t, cmd.Wait())
	require.Less(t, time.Since(appeared), 400*time.Millisecond,
		"the wait loop took %v to notice a CA that was there", time.Since(appeared))
}
