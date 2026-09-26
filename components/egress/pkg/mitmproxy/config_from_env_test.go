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

package mitmproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ConfigFromEnv is the call the launcher makes (mitmproxy_transparent.go), so it is the
// wiring between OPENSANDBOX_EGRESS_ENFORCEMENT and what mitmdump is told. The tests in
// regular_mode_test.go reach buildMitmdumpArgs through configFromEnvForTest instead --
// deliberately, so they compile on upstream for hack/wm-fail-on-base.sh -- which means a
// ConfigFromEnv that stopped setting Regular would leave every one of them green while
// the sidecar ran transparent under external enforcement and reset every connection.
//
// This file names ConfigFromEnv directly, so it cannot compile on upstream and is not
// copied there; it runs in CI on this tree only, like the WM-6 and WM-8 unit tests.
func TestWM1ConfigFromEnvIsWhatTheLauncherTellsMitmdump(t *testing.T) {
	// ListenV6 set as Launch sets it on any host with ::1 (see argsForEnv).
	v6 := true
	modes := func() []string {
		var out []string
		args := buildMitmdumpArgs(ConfigFromEnv(Config{ListenPort: 18081, ListenV6: &v6}))
		for i, a := range args {
			if a == "--mode" && i+1 < len(args) {
				out = append(out, args[i+1])
			}
		}
		return out
	}

	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "external")
	require.Equal(t, []string{"regular@127.0.0.1:18081"}, modes(),
		"with enforcement outside the pod the launcher must run mitmdump as a regular proxy")

	transparent := []string{"transparent@127.0.0.1:18081", "transparent@::1:18081"}
	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "sidecar")
	require.Equal(t, transparent, modes(),
		"sidecar enforcement keeps upstream's transparent listeners")

	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "")
	require.Equal(t, transparent, modes(), "unset means sidecar")
}
