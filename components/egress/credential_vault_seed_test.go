package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// WM-8: the vault can be filled before the first request. Why the API cannot serve that
// case, with the measurement behind it: NOTICE-WIDE-MOAT.md, WM-8.

func seededServer(t *testing.T) *policyServer {
	t.Helper()
	// ⚠ A POLICY THAT ALLOWS THE BOUND HOST, BECAUSE A BINDING WITHOUT ONE IS REFUSED --
	// `credential vault bindings require an egress policy`. A stub returning nil would
	// have made every case below fail for that reason instead of the one it tests, and
	// it is not what the sidecar does: dnsproxy.New always holds a policy, defaulting to
	// deny-all when the environment names none.
	allow, err := policy.ParseValidatedEgressRule(policy.ActionAllow, "files.example.com")
	require.NoError(t, err)
	pol := &policy.NetworkPolicy{DefaultAction: policy.ActionDeny, Egress: []policy.EgressRule{allow}}
	// ⚠ A REAL, UNMARKED HEALTH GATE, BECAUSE THAT IS WHAT STARTUP HAS. main.go builds
	// the gate and hands it to startPolicyServer, marking it ready only after that
	// returns -- so at seed time the gate is always pending and Ready() always reports
	// "credential proxy is not ready". A nil gate here would skip that branch entirely,
	// and dropping the seed helper's exception for it would break every real sandbox
	// while these tests stayed green.
	// ⚠ BEFORE NewHealthGate, because the gate reads this at construction: a gate built
	// with transparent mitm off is never "required" and never pending, which would make
	// the fixture skip the very branch production always takes.
	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	t.Setenv(constants.EnvEnforcement, constants.EnforcementExternal)
	gate := mitmproxy.NewHealthGate()
	srv := &policyServer{proxy: &stubProxy{updated: pol}, enforcementMode: "dns", mitmGate: gate}
	srv.credentialVault = credentialvault.NewStore(gate, func() bool { return true })
	return srv
}

const oneBinding = `{
  "credentials": [{"name": "k", "source": {"type": "inline", "value": "secret-value"}}],
  "bindings": [{"name": "b", "match": {"hosts": ["files.example.com"]},
                "auth": {"type": "bearer", "credential": "k"}}]
}`

func TestWM8SeedFillsTheVaultBeforeAnyRequest(t *testing.T) {
	srv := seededServer(t)
	srv.seedCredentialVault(oneBinding)

	state, err := srv.credentialVault.Sanitized()
	require.NoError(t, err, "the vault must exist after seeding")
	require.Len(t, state.Bindings, 1, "the seeded binding must be present")
	require.Equal(t, "b", state.Bindings[0].Name)
}

// ⚠ The negative half, and the reason this is not one assertion: every one of these
// inputs must leave a WORKING sidecar with an EMPTY vault. A seed that refuses to start
// the sidecar would turn a missing credential into no sandbox at all.
func TestWM8ABadSeedLeavesAnEmptyVaultAndAWorkingSidecar(t *testing.T) {
	cases := map[string]string{
		"not json":            `{`,
		"empty object":        `{}`,
		"no credential named": `{"credentials": [], "bindings": [{"name": "b", "match": {"hosts": ["h.example.com"]}, "auth": {"type": "bearer", "credential": "missing"}}]}`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			srv := seededServer(t)
			srv.seedCredentialVault(contents)
			_, err := srv.credentialVault.Sanitized()
			require.Error(t, err, "a refused seed must leave the vault empty, not half-written")
		})
	}
}

// ⚠ THE DEFAULT IS TODAY'S BEHAVIOUR. Unset means no seeding at all, which is what makes
// this diff one an installation opts into rather than one it inherits.
func TestWM8UnsetMeansNoSeeding(t *testing.T) {
	srv := seededServer(t)
	srv.seedCredentialVault("")
	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "an unset variable must seed nothing")
	srv.seedCredentialVault("   ")
	_, err = srv.credentialVault.Sanitized()
	require.Error(t, err, "a blank variable must seed nothing")
}

// The vault is created once. A seed must not quietly merge into, or overwrite, a vault a
// client already wrote -- two sources for one vault is how a binding becomes something
// nobody wrote.
func TestWM8SeedDoesNotOverwriteAVaultThatAlreadyExists(t *testing.T) {
	srv := seededServer(t)
	_, err := srv.credentialVault.Create(credentialvault.CreateRequest{
		Credentials: []credentialvault.Credential{{
			Name:   "first",
			Source: json.RawMessage(`{"type":"inline","value":"written-by-the-client"}`),
		}},
	}, nil)
	require.NoError(t, err)

	srv.seedCredentialVault(oneBinding)

	state, err := srv.credentialVault.Sanitized()
	require.NoError(t, err)
	require.Len(t, state.Credentials, 1, "the client's vault must survive untouched")
	require.Equal(t, "first", state.Credentials[0].Name)
}

// ⚠ A SEED MUST NOT BE A WAY ROUND THE REFUSALS THE API MAKES. Ready() rejects a vault
// whose upstream TLS is unverified; POST is refused outright in that configuration, and
// a seed that ignored it would inject the credential anyway. Found by review.
func TestWM8SeedIsRefusedWhereTheAPIWouldBeRefused(t *testing.T) {
	srv := seededServer(t)
	t.Setenv(constants.EnvMitmproxySslInsecure, "true")

	srv.seedCredentialVault(oneBinding)

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "insecure upstream TLS must refuse the seed as it refuses the API")
}

func TestWM8SeedIsRefusedWithoutTransparentMitmproxy(t *testing.T) {
	srv := seededServer(t)
	t.Setenv(constants.EnvMitmproxyTransparent, "false")

	srv.seedCredentialVault(oneBinding)

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "no transparent mitmproxy must refuse the seed as it refuses the API")
}

// ⚠ THE SEED IS JUDGED BY THE SAME POLICY THE API USES. effectivePolicy merges the
// always-allow/always-deny overlay over the user policy; validating against the user
// policy alone refuses a binding whose destination the overlay permits, so the same
// request would succeed over the API and fail as a seed. Found by review.
func TestWM8SeedIsJudgedByTheEffectivePolicyIncludingAlwaysAllow(t *testing.T) {
	// The USER policy allows nothing; only the always-allow overlay permits the host.
	deny := &policy.NetworkPolicy{DefaultAction: policy.ActionDeny}
	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	t.Setenv(constants.EnvEnforcement, constants.EnforcementExternal)
	gate := mitmproxy.NewHealthGate()
	srv := &policyServer{proxy: &stubProxy{updated: deny}, enforcementMode: "dns", mitmGate: gate}
	srv.credentialVault = credentialvault.NewStore(gate, func() bool { return true })

	allow, err := policy.ParseValidatedEgressRule(policy.ActionAllow, "files.example.com")
	require.NoError(t, err)
	srv.setAlwaysRules(nil, []policy.EgressRule{allow})

	srv.seedCredentialVault(oneBinding)

	_, err = srv.credentialVault.Sanitized()
	require.NoError(t, err, "a host permitted only by always-allow must still seed")
}

// postVault sends body to POST /credential-vault as a client would, once the proxy is up.
func postVault(t *testing.T, srv *policyServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	srv.mitmGate.MarkStackReady()
	srv.mitmGate.SetReady(true)
	req := httptest.NewRequest(http.MethodPost, "/credential-vault", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCredentialVault(w, req)
	return w
}

// ⚠ A SEED IS DECODED AS THE API DECODES IT. A misspelt field is refused by the API; a
// lenient decoder would instead load what it recognised -- here the credential without
// its binding -- and the client's own POST would then be answered 409 for a vault
// nobody wrote as intended.
func TestWM8ASeedWithAnUnknownFieldIsRefusedAsTheAPIRefusesIt(t *testing.T) {
	misspelt := strings.Replace(oneBinding, `"bindings"`, `"bindngs"`, 1)
	srv := seededServer(t)

	srv.seedCredentialVault(misspelt)

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "a seed the API would refuse must leave the vault uncreated")
	w := postVault(t, srv, misspelt)
	require.Equal(t, http.StatusBadRequest, w.Code, "the API refuses the same body: %s", w.Body)
	w = postVault(t, srv, oneBinding)
	require.Equal(t, http.StatusCreated, w.Code, "the client's own write must still succeed: %s", w.Body)
}

// ⚠ AND IS REFUSED WHERE THE API REFUSES WRITES. Under upstream's experimental revision
// runtime every vault write is answered 503; the seed follows the same rule.
func TestWM8SeedIsRefusedUnderTheRevisionRuntime(t *testing.T) {
	srv := seededServer(t)
	t.Setenv(constants.EnvExperimentalRevisionRuntime, "true")

	srv.seedCredentialVault(oneBinding)

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "the seed must be refused where POST is")
	w := postVault(t, srv, oneBinding)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "%s", w.Body)
}
