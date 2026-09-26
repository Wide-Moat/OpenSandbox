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

//go:build linux

package dnsproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The dialer must not install a Control hook when enforcement is external.
//
// The hook is where SO_MARK is set, and SO_MARK needs CAP_NET_ADMIN. A deployment
// that enforces outside the pod does not have that capability, and the failure is
// not a warning: setsockopt returns EPERM inside Control, which fails the whole
// dial. Every upstream probe then errors on a resolver that is otherwise fine.
//
// Asserting on Control rather than on an observed EPERM is deliberate — this test
// has to mean the same thing on a developer's machine, where the capability is
// present and nothing would fail.
func TestWM1DialerSetsNoMarkWhenEnforcementIsExternal(t *testing.T) {
	resetNameserverExemptCache(t)
	t.Setenv(envEnforcement, "external")

	p := &Proxy{upstreamExchangeTimeout: time.Second}
	d := p.dialerForUpstream("10.43.0.10:53")

	require.NotNil(t, d)
	require.Nil(t, d.Control,
		"external enforcement must produce a plain dialer: SO_MARK needs CAP_NET_ADMIN, "+
			"and there is no redirect for the mark to bypass")
}

// The guard, in the other direction: the default must still set the mark. Without
// this, deleting the Control hook altogether would pass the test above.
func TestWM1DialerStillSetsMarkByDefault(t *testing.T) {
	resetNameserverExemptCache(t)
	t.Setenv(envEnforcement, "")

	p := &Proxy{upstreamExchangeTimeout: time.Second}
	d := p.dialerForUpstream("10.43.0.10:53")

	require.NotNil(t, d)
	require.NotNil(t, d.Control,
		"the default is unchanged in-pod enforcement, which marks its own upstream queries")
}

// The variable name as a literal rather than the exported constant. The constant is
// part of the change under test, so referring to it would make this file fail to
// COMPILE against unmodified upstream — which is indistinguishable from the change
// being absent, and would go green the moment a constant existed with no behaviour
// behind it. A literal makes the test fail on what the dialer DOES.
const envEnforcement = "OPENSANDBOX_EGRESS_ENFORCEMENT"
