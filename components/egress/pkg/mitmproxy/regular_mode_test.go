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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// argsForEnv is what the component will tell mitmdump, given the environment.
//
// It goes through configFromEnvForTest rather than naming the Config field the change
// adds, because a test that named a new field would fail to COMPILE against unmodified
// upstream — which proves only that a field is missing, and would turn green the moment
// one existed with no behaviour behind it. Written with reflection so this file
// compiles on both trees and fails on what the component DOES.
func argsForEnv(port int) []string {
	return buildMitmdumpArgs(configFromEnvForTest(Config{ListenPort: port}))
}

// Transparent mode recovers the real destination with SO_ORIGINAL_DST, which holds
// only when a redirect put the connection there. With enforcement outside the pod
// there is no redirect: clients arrive through HTTPS_PROXY and name the destination
// in CONNECT, which is regular mode.
//
// ⚠ IT MUST BE `--mode`, AND THIS TEST USED TO REQUIRE THE FORM THAT DOES NOT WORK.
// config.yaml sets `mode: [transparent]`, and `mode` is a SEQUENCE option: `--set
// mode=regular` does not replace that list, so mitmdump stayed transparent and every
// client connection was closed without a byte. The process stays alive, keeps
// listening and logs nothing, so the only symptom is `Connection reset by peer` from
// inside the sandbox.
//
// Measured in a live sidecar, one variable at a time, with the sidecar's own HOME so
// the same config file is read:
//
//	HOME=/var/lib/mitmproxy mitmdump -s system.py                 -> reset
//	HOME=/var/lib/mitmproxy mitmdump --mode regular -s system.py  -> HTTP 401
//
// The 401 is file-gate refusing an unauthenticated request: proof it arrived.
func TestWM1RegularModeIsSetWhenEnforcementIsExternal(t *testing.T) {
	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "external")

	// ⚠ ASSERTED ON THE SLICE, NOT ON A JOINED STRING. `strings.Join` renders
	// []string{"--mode", "regular"} and []string{"--mode regular"} identically, so a
	// Contains check passes for both -- and the second is a single argv entry that
	// mitmdump rejects as an unknown option, so the sidecar would not start at all.
	// Measured: Join produces "--mode regular" either way and Contains answers true to
	// both, which makes that form of the check unable to fail on the defect it names.
	args := argsForEnv(18081)

	mode := -1
	for i, a := range args {
		if a == "--mode" {
			mode = i
			break
		}
	}
	require.GreaterOrEqual(t, mode, 0,
		"with enforcement outside the pod mitmdump must be given --mode, which replaces "+
			"the transparent baked into config.yaml")
	require.Less(t, mode, len(args)-1, "--mode must be followed by its value")
	require.Equal(t, "regular", args[mode+1],
		"--mode must name regular exactly, as its own argv entry")

	for _, a := range args {
		require.NotContains(t, a, "mode=",
			"--set does not replace a sequence option, so that form leaves mitmdump "+
				"transparent and every connection is reset")
	}
}

// The guard: the default must leave config.yaml alone, or every existing deployment's
// transparent interception becomes a proxy nobody is pointed at.
func TestWM1TransparentStaysTheDefault(t *testing.T) {
	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "")

	require.NotContains(t, strings.Join(argsForEnv(18081), " "), "mode=",
		"without external enforcement the mode must come from config.yaml, untouched")
}

// configFromEnvForTest applies the environment to a Config the way the component
// does. Reflection keeps the file compiling where the field does not exist yet.
func configFromEnvForTest(cfg Config) Config {
	if os.Getenv("OPENSANDBOX_EGRESS_ENFORCEMENT") == "external" {
		setBoolFieldIfPresent(&cfg, "Regular", true)
	}
	return cfg
}
