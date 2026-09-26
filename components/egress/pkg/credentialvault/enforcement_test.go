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

package credentialvault

import (
	"context"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/stretchr/testify/require"
)

// The variable name as a literal, not the exported constant: referring to the
// constant would make this file fail to COMPILE on unmodified upstream, which proves
// only that a symbol is missing. The test must fail on what Ready DECIDES.
const envEnforcement = "OPENSANDBOX_EGRESS_ENFORCEMENT"

// readyStore builds a Store whose every OTHER precondition is satisfied, so a
// failure can only be about the egress mode.
func readyStore(t *testing.T) *Store {
	t.Helper()
	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	t.Setenv(constants.EnvMitmproxySslInsecure, "")
	gate := mitmproxy.NewHealthGate()
	gate.MarkStackReady()
	return NewStore(gate, func() bool { return true })
}

// The dns+nft requirement is about IN-POD enforcement: without nftables the sidecar
// cannot stop a client reaching a credential's destination by another route, so
// substituting the credential would be a false promise. When enforcement is external
// that guarantee is made outside the pod, and demanding a subsystem a sandboxed
// kernel does not have refuses the configuration for a reason that does not apply.
func TestWM1ReadyAcceptsDnsOnlyWhenEnforcementIsExternal(t *testing.T) {
	v := readyStore(t)
	t.Setenv(constants.EnvEgressMode, "dns")
	t.Setenv(envEnforcement, "external")

	require.NoError(t, v.Ready(context.Background()),
		"external enforcement must not require nftables inside the pod")
}

// The guard: the default is unchanged. Deleting the mode check outright would pass
// the test above while quietly weakening every existing deployment.
func TestWM1ReadyStillRequiresNftInSidecarMode(t *testing.T) {
	v := readyStore(t)
	t.Setenv(constants.EnvEgressMode, "dns")
	t.Setenv(envEnforcement, "")

	err := v.Ready(context.Background())
	require.Error(t, err, "in-pod enforcement still needs nftables to make its promise good")
	require.Contains(t, err.Error(), "dns+nft")
}

func TestWM1ReadyAcceptsDnsNftInSidecarMode(t *testing.T) {
	v := readyStore(t)
	t.Setenv(constants.EnvEgressMode, "dns+nft")
	t.Setenv(envEnforcement, "sidecar")

	require.NoError(t, v.Ready(context.Background()))
}
