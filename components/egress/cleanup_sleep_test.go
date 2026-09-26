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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cleanupWithPkillExit runs the hook with a pkill stub that reports `code` for a
// -TERM invocation, and returns every pkill and sleep the hook ran, in order, with
// their arguments.
//
// Recorded, not timed: `sleep` is an external command under sh, so a stub on PATH sees
// each call. A wall-clock threshold measured the machine as much as the hook -- one cold
// run that never slept at all took 1.19 s -- and needed a best-of-three to hold. And
// pkill's arguments with it: which user and which signal are the whole of what makes
// the reap safe, and a stub that looked only for -TERM would pass a hook that signalled
// every mitmdump on the host, or never sent the SIGKILL at all.
func cleanupWithPkillExit(t *testing.T, code string) []string {
	t.Helper()
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	require.NoError(t, os.Mkdir(binDir, 0o755))
	callLog := filepath.Join(tmpDir, "calls.log")

	writeExecutable(t, filepath.Join(binDir, "pkill"), `#!/bin/sh
printf 'pkill %s\n' "$*" >> "`+callLog+`"
for a in "$@"; do
  if [ "$a" = "-TERM" ]; then exit `+code+`; fi
done
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "sleep"), `#!/bin/sh
printf 'sleep %s\n' "$*" >> "`+callLog+`"
`)
	for _, stub := range []string{"nft", "iptables", "ip6tables"} {
		writeExecutable(t, filepath.Join(binDir, stub), "#!/bin/sh\nexit 0\n")
	}

	cmd := exec.Command("sh", "scripts/cleanup.sh")
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	logged, err := os.ReadFile(callLog)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(logged)), "\n")
}

const (
	termMitmdump = "pkill -TERM -u mitmproxy -f mitmdump"
	killMitmdump = "pkill -KILL -u mitmproxy -f mitmdump"
)

// A stop where nothing was signalled must not wait.
//
// pkill exits 1 when it matched nothing, which is the ordinary case: a clean stop has
// already reaped mitmdump. Sleeping anyway spends a second on every sandbox stop
// waiting for a process that was never sent a signal.
func TestWM7NoSleepWhenNothingWasSignalled(t *testing.T) {
	require.Equal(t, []string{termMitmdump}, cleanupWithPkillExit(t, "1"),
		"the hook waited for, or went on to kill, a mitmdump that pkill reported it had not matched")
}

// The guard, and the half that matters for correctness: when something WAS signalled
// the wait stays, and SIGKILL follows it, scoped to the mitmproxy user. Removing the
// sleep outright would pass the test above while SIGKILLing a process that had not yet
// had a chance to handle SIGTERM.
func TestWM7StillSleepsWhenSomethingWasSignalled(t *testing.T) {
	require.Equal(t, []string{termMitmdump, "sleep 1", killMitmdump}, cleanupWithPkillExit(t, "0"),
		"a signalled mitmdump must be given time to exit before SIGKILL")
}
