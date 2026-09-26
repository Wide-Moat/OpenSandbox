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

package constants

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWM1ParseEnforcementDefaultsToSidecar(t *testing.T) {
	got, err := ParseEnforcement("")
	require.NoError(t, err)
	require.Equal(t, EnforcementSidecar, got,
		"an unset variable must mean today's behaviour, or upgrading changes what a running deployment does")
}

func TestWM1ParseEnforcementAcceptsBothValues(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"sidecar", EnforcementSidecar},
		{"external", EnforcementExternal},
		{"  External  ", EnforcementExternal},
		{"SIDECAR", EnforcementSidecar},
	} {
		got, err := ParseEnforcement(tc.in)
		require.NoErrorf(t, err, "input %q", tc.in)
		require.Equalf(t, tc.want, got, "input %q", tc.in)
	}
}

// A typo must be refused rather than silently read as the default. Were it a
// fallback, an operator configuring for a sandboxed kernel would get the in-pod
// path anyway, and the only symptom would be a crash-loop about netlink — a
// message that names neither the variable nor the misspelling.
func TestWM1ParseEnforcementRefusesAnythingElse(t *testing.T) {
	for _, bad := range []string{"externl", "off", "true", "cni", "none"} {
		_, err := ParseEnforcement(bad)
		require.Errorf(t, err, "%q was accepted", bad)
		require.Containsf(t, err.Error(), bad, "the error must quote what was given: %q", bad)
	}
}

func TestWM1EnforcementIsExternalReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvEnforcement, "external")
	require.True(t, EnforcementIsExternal())

	t.Setenv(EnvEnforcement, "sidecar")
	require.False(t, EnforcementIsExternal())

	// Unset is the default, which is not external.
	t.Setenv(EnvEnforcement, "")
	require.False(t, EnforcementIsExternal())

	// A value that does not parse must not disable in-pod enforcement. Failing open
	// here would turn a typo into a silently unenforced sandbox; startup refuses it
	// through ParseEnforcement instead.
	t.Setenv(EnvEnforcement, "externl")
	require.False(t, EnforcementIsExternal(),
		"an unparsable value must not read as external")
}
