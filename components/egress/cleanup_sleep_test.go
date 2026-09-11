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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cleanupWithPkillExit runs the hook with a pkill stub that reports `code` for a
// -TERM invocation, and returns how long the hook took.
func cleanupWithPkillExit(t *testing.T, code string) time.Duration {
	t.Helper()
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	require.NoError(t, os.Mkdir(binDir, 0o755))

	writeExecutable(t, filepath.Join(binDir, "pkill"), `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "-TERM" ]; then exit `+code+`; fi
done
exit 0
`)
	for _, stub := range []string{"nft", "iptables", "ip6tables"} {
		writeExecutable(t, filepath.Join(binDir, stub), "#!/bin/sh\nexit 0\n")
	}

	env := append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Best of three. The first run of a fresh process tree pays for page-ins and stub
	// lookups -- measured at 782ms against 51ms for the two runs after it, on an
	// otherwise idle machine. Taking the minimum measures the hook rather than the
	// machine's warm-up, and the property under test is a one-second sleep, which no
	// amount of start-up noise produces.
	best := time.Hour
	for i := 0; i < 3; i++ {
		cmd := exec.Command("sh", "scripts/cleanup.sh")
		cmd.Env = env
		started := time.Now()
		out, err := cmd.CombinedOutput()
		elapsed := time.Since(started)
		require.NoError(t, err, string(out))
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

// A stop where nothing was signalled must not wait.
//
// pkill exits 1 when it matched nothing, which is the ordinary case: a clean stop has
// already reaped mitmdump. Sleeping anyway spends a second on every sandbox stop
// waiting for a process that was never sent a signal.
func TestWM7NoSleepWhenNothingWasSignalled(t *testing.T) {
	elapsed := cleanupWithPkillExit(t, "1")
	require.Less(t, elapsed, 900*time.Millisecond,
		"the hook waited for a mitmdump that pkill reported it had not matched")
}

// The guard, and the half that matters for correctness: when something WAS signalled
// the wait stays. Removing the sleep outright would pass the test above while
// SIGKILLing a process that had not yet had a chance to handle SIGTERM.
func TestWM7StillSleepsWhenSomethingWasSignalled(t *testing.T) {
	elapsed := cleanupWithPkillExit(t, "0")
	require.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
		"a signalled mitmdump must be given time to exit before SIGKILL")
}
