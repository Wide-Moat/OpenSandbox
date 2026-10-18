// Copyright 2026 The OpenSandbox Authors
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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/stretchr/testify/require"
)

// freeAddr returns a loopback address nothing listens on at the moment it returns.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// WM-34: startPolicyServer returns as soon as its socket is open, and the server answers
// then. Upstream waits a fixed 200 ms for ListenAndServe to fail before returning, and every
// sidecar start paid it before mitmdump was launched. The fastest of three starts is held to
// half that wait: one scheduling pause on a loaded runner cannot fail it, and upstream's
// unconditional 200 ms is in every sample, so it cannot pass.
func TestWM34PolicyServerReturnsWithoutAFixedWait(t *testing.T) {
	t.Setenv(constants.EnvMitmproxyTransparent, "false")
	client := &http.Client{Timeout: 2 * time.Second}

	fastest := time.Hour
	for i := 0; i < 3; i++ {
		addr := freeAddr(t)
		began := time.Now()
		srv, handler, err := startPolicyServer(&stubProxy{}, nil, "", addr, "", nil, "", nil, nil, nil)
		took := time.Since(began)
		require.NoError(t, err)
		require.NotNil(t, handler)
		if took < fastest {
			fastest = took
		}

		// And it is serving the policy API at that moment, not merely returned: one
		// request, no retry, answered by its own /healthz.
		resp, err := client.Get("http://" + addr + "/healthz")
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, srv.Shutdown(context.Background()))
	}
	require.Less(t, fastest, 100*time.Millisecond, "the fastest of three starts took %v", fastest)
}

// The wait existed to report an address that cannot be served; that still comes back as an
// error, and nothing is left serving. A guard: upstream answers the same.
func TestWM34PolicyServerStillReportsATakenAddress(t *testing.T) {
	t.Setenv(constants.EnvMitmproxyTransparent, "false")
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })

	srv, handler, err := startPolicyServer(&stubProxy{}, nil, "", taken.Addr().String(), "", nil, "", nil, nil, nil)
	require.Error(t, err)
	require.Nil(t, srv)
	require.Nil(t, handler)
}
