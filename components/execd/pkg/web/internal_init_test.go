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

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// WM-12. Through the real router, with only upstream symbols, so this builds on a tree
// without the change and fails there on what the route answers.
//
// The body is deliberately incomplete: a served route refuses it with 400 and applies
// nothing, so a run against a tree that serves the route changes no process state.
func postInternalInit(t *testing.T, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/init", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	NewRouter(accessToken).ServeHTTP(w, req)
	return w
}

// Outside runtime-init mode nothing is waiting for /internal/init, and it takes no access
// token, so it must not be served -- not even when execd HAS a token, which is the case
// where the rebind it allows turns into a lock-out of the rightful caller.
func TestWM12InternalInitIsNotServedOutsideRuntimeInitMode(t *testing.T) {
	withRuntimeInit(t, false)
	withTestBinding(t, nil)
	withManager(t, true)

	for _, token := range []string{"", "legit-token"} {
		w := postInternalInit(t, token)
		require.Equal(t, http.StatusNotFound, w.Code,
			"an unauthenticated POST /internal/init reached the runtime-init handler (token %q): %s", token, w.Body)
		require.Contains(t, w.Body.String(), "--runtime-init", "the 404 must be the refusal, not a missing route")
	}
}

// The guard: in runtime-init mode the route is served exactly as upstream serves it --
// here it reaches the handler, which refuses the incomplete body.
func TestWM12InternalInitIsStillServedInRuntimeInitMode(t *testing.T) {
	withRuntimeInit(t, true)
	withTestBinding(t, nil)
	withManager(t, false)

	w := postInternalInit(t, "")
	require.Equal(t, http.StatusBadRequest, w.Code, "the runtime-init handler did not answer: %s", w.Body)
}
