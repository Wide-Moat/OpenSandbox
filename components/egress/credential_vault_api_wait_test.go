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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

// WM-8's guard on the API. The seed skips the wait for mitmdump -- it runs before mitmdump
// exists -- and so WM-8 split the vault's readiness into Preconditions, which the seed
// uses, and Ready, which is Preconditions plus that wait. The API must keep the wait: a
// vault written before mitmdump is up substitutes credentials through a proxy that is not
// there. A tidy-up that merged the two, or a handler switched to Preconditions, would
// drop it without a failing test anywhere else.
//
// Only upstream symbols, and upstream's behaviour: this runs against unmodified upstream
// too, and must pass there.
func TestWM8TheAPIStillWaitsForTheCredentialProxy(t *testing.T) {
	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	t.Setenv(constants.EnvEgressMode, constants.PolicyDnsNft)
	gate := mitmproxy.NewHealthGate()
	allow, err := policy.ParseValidatedEgressRule(policy.ActionAllow, "files.example.com")
	require.NoError(t, err)
	pol := &policy.NetworkPolicy{DefaultAction: policy.ActionDeny, Egress: []policy.EgressRule{allow}}
	srv := &policyServer{proxy: &stubProxy{updated: pol}, enforcementMode: "dns+nft", mitmGate: gate}
	srv.credentialVault = credentialvault.NewStore(gate, func() bool { return true })
	const body = `{
	  "credentials": [{"name": "k", "source": {"type": "inline", "value": "secret-value"}}],
	  "bindings": [{"name": "b", "match": {"hosts": ["files.example.com"]},
	                "auth": {"type": "bearer", "credential": "k"}}]
	}`
	post := func(ctx context.Context) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/credential-vault", strings.NewReader(body)).WithContext(ctx)
		w := httptest.NewRecorder()
		srv.handleCredentialVault(w, req)
		return w
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	w := post(ctx)
	require.Equal(t, http.StatusPreconditionFailed, w.Code,
		"a vault write must wait for mitmdump and give up with it pending: %s", w.Body)
	require.Contains(t, w.Body.String(), "credential proxy is not ready")

	gate.MarkStackReady()
	gate.SetReady(true)
	w = post(context.Background())
	require.Equal(t, http.StatusCreated, w.Code, "once mitmdump is up the same write succeeds: %s", w.Body)
}
