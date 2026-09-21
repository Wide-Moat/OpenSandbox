package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// WM-8. The vault can be filled before the first request, because the API cannot be
// reached in time for anything the sandbox does at boot.
//
// The measurement this exists for, taken on a live installation: a sandbox mounting its
// files over WebDAV probes at 18:37:56 and is refused `401 no key presented`; the pod
// becomes Ready at 18:37:58; the client writes the vault at 18:37:59. The client cannot
// write sooner -- the server does not answer the create call until Ready -- and the
// sandbox cannot wait, because waiting delays Ready and therefore delays the write by
// the same amount.

func seededServer(t *testing.T, contents string) (*policyServer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
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
	return srv, path
}

const oneBinding = `{
  "credentials": [{"name": "k", "source": {"type": "inline", "value": "secret-value"}}],
  "bindings": [{"name": "b", "match": {"hosts": ["files.example.com"]},
                "auth": {"type": "bearer", "credential": "k"}}]
}`

func TestWM8SeedFillsTheVaultBeforeAnyRequest(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	srv.seedCredentialVault(path, "")

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
			srv, path := seededServer(t, contents)
			srv.seedCredentialVault(path, "")
			_, err := srv.credentialVault.Sanitized()
			require.Error(t, err, "a refused seed must leave the vault empty, not half-written")
		})
	}
}

func TestWM8AnAbsentFileIsNotAnError(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	require.NoError(t, os.Remove(path))
	srv.seedCredentialVault(path, "")
	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "a missing seed file must leave the vault empty")
}

// ⚠ THE DEFAULT IS TODAY'S BEHAVIOUR. Unset means no seeding at all, which is what makes
// this diff one an installation opts into rather than one it inherits.
func TestWM8UnsetMeansNoSeeding(t *testing.T) {
	srv, _ := seededServer(t, oneBinding)
	srv.seedCredentialVault("", "")
	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "an empty path must seed nothing")
	srv.seedCredentialVault("   ", "")
	_, err = srv.credentialVault.Sanitized()
	require.Error(t, err, "a blank path must seed nothing")
}

// The vault is created once. A seed must not quietly merge into, or overwrite, a vault a
// client already wrote -- two sources for one vault is how a binding becomes something
// nobody wrote.
func TestWM8SeedDoesNotOverwriteAVaultThatAlreadyExists(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	_, err := srv.credentialVault.Create(credentialvault.CreateRequest{
		Credentials: []credentialvault.Credential{{
			Name:   "first",
			Source: json.RawMessage(`{"type":"inline","value":"written-by-the-client"}`),
		}},
	}, nil)
	require.NoError(t, err)

	srv.seedCredentialVault(path, "")

	state, err := srv.credentialVault.Sanitized()
	require.NoError(t, err)
	require.Len(t, state.Credentials, 1, "the client's vault must survive untouched")
	require.Equal(t, "first", state.Credentials[0].Name)
}

// The inline variable is the channel that needs no shared volume -- which matters
// because the one volume the sidecar and the sandbox share is where the sandbox reads
// the CA, so a seed placed there would be readable by the code the vault exists to keep
// the credential away from.
func TestWM8InlineSeedFillsTheVaultToo(t *testing.T) {
	srv, _ := seededServer(t, oneBinding)
	srv.seedCredentialVault("", oneBinding)

	state, err := srv.credentialVault.Sanitized()
	require.NoError(t, err, "an inline seed must fill the vault")
	require.Len(t, state.Bindings, 1)
}

// Both set is not ambiguous: the path is the more deliberate of the two and wins, so a
// stale variable cannot silently outrank a file somebody placed on purpose.
func TestWM8TheFileWinsWhenBothAreSet(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	other := `{"credentials":[{"name":"from-env","source":{"type":"inline","value":"v"}}]}`
	srv.seedCredentialVault(path, other)

	state, err := srv.credentialVault.Sanitized()
	require.NoError(t, err)
	require.Len(t, state.Credentials, 1)
	require.Equal(t, "k", state.Credentials[0].Name, "the file's credential, not the variable's")
}

// ⚠ A SEED MUST NOT BE A WAY ROUND THE REFUSALS THE API MAKES. Ready() rejects a vault
// whose upstream TLS is unverified; POST is refused outright in that configuration, and
// a seed that ignored it would inject the credential anyway. Found by review.
func TestWM8SeedIsRefusedWhereTheAPIWouldBeRefused(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	t.Setenv(constants.EnvMitmproxySslInsecure, "true")

	srv.seedCredentialVault(path, "")

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "insecure upstream TLS must refuse the seed as it refuses the API")
}

func TestWM8SeedIsRefusedWithoutTransparentMitmproxy(t *testing.T) {
	srv, path := seededServer(t, oneBinding)
	t.Setenv(constants.EnvMitmproxyTransparent, "false")

	srv.seedCredentialVault(path, "")

	_, err := srv.credentialVault.Sanitized()
	require.Error(t, err, "no transparent mitmproxy must refuse the seed as it refuses the API")
}

// ⚠ THE SEED IS JUDGED BY THE SAME POLICY THE API USES. effectivePolicy merges the
// always-allow/always-deny overlay over the user policy; validating against the user
// policy alone refuses a binding whose destination the overlay permits, so the same
// request would succeed over the API and fail as a seed. Found by review.
func TestWM8SeedIsJudgedByTheEffectivePolicyIncludingAlwaysAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.json")
	require.NoError(t, os.WriteFile(path, []byte(oneBinding), 0o600))

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

	srv.seedCredentialVault(path, "")

	_, err = srv.credentialVault.Sanitized()
	require.NoError(t, err, "a host permitted only by always-allow must still seed")
}
