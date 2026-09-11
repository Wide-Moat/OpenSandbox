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
// in CONNECT, which is regular mode. The setting lives in config.yaml, so it has to
// be overridden with --set, which takes precedence over the file.
func TestWM1RegularModeIsSetWhenEnforcementIsExternal(t *testing.T) {
	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "external")

	require.Contains(t, strings.Join(argsForEnv(18081), " "), "--set mode=regular",
		"with enforcement outside the pod mitmdump must be told mode=regular on the "+
			"command line, which beats the transparent baked into config.yaml")
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
