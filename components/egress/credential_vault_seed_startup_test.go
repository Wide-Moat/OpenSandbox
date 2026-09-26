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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// WM-8 through the process: the variable the server sets reaches the vault, by the path
// main() takes. The unit tests call seedCredentialVault directly; nothing there would
// notice the call leaving startPolicyServer, moving ahead of setAlwaysRules, or the
// variable being renamed on this side only.
//
// The user policy allows nothing; files.example.com is permitted only by the
// always-allow overlay, which the OTLP endpoint adds. So the binding loads only if the
// seed is judged after setAlwaysRules, as the API is. The variable is named here as a
// literal, as the server's tests name it, so a rename on either side fails one of them.
//
// ⚠ ONLY A RUN THAT REACHED THE POLICY SERVER SAYS ANYTHING ABOUT THE SEED. The seed is
// loaded there, and a sidecar that died before it -- on netfilter it may not touch, as
// upstream does off a privileged host, where it ignores the enforcement variable -- has
// said nothing about seeding either way. Such a run skips instead of failing, so that
// "fails without WM-8" can only ever mean the seed was missing; hack/wm-fail-on-base.sh
// runs this test on upstream as root in a throwaway network namespace, where upstream
// gets that far. startPolicyServer, not "policy server listening": off the image both
// trees stop inside it, on the mitmproxy user, just after the seed.
func TestWM8TheSeedVariableFillsTheVaultAtStartup(t *testing.T) {
	// Until the seed's own log line: a transparent-mitm sidecar goes on to look up the
	// mitmproxy user, which exists only in the image, and stops there off it.
	out, _ := runEgressUntil(t, "credential vault seed:",
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns",
		"OPENSANDBOX_EGRESS_TOKEN=test-token",
		"OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT=true",
		"OTEL_EXPORTER_OTLP_ENDPOINT=http://files.example.com:4318",
		"OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED="+`{
		  "credentials": [{"name": "k", "source": {"type": "inline", "value": "secret-value"}}],
		  "bindings": [{"name": "b", "match": {"hosts": ["files.example.com"]},
		                "auth": {"type": "bearer", "credential": "k"}}]
		}`)
	// The first line startPolicyServer prints, upstream's own, before the seed.
	if !strings.Contains(out, "policy API: max egress rules") {
		t.Skipf("the sidecar never reached startPolicyServer, so the seed was not exercised:\n%s", out)
	}

	require.Contains(t, out, "credential vault seed: 1 credential(s) and 1 binding(s) loaded",
		"the seed variable did not fill the vault at startup:\n%s", out)
}
