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
	stdflag "flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/execd/pkg/binding"
	"github.com/alibaba/opensandbox/execd/pkg/flag"
	"github.com/alibaba/opensandbox/execd/pkg/web/model"
)

// WM-26. Runtime-init-once mode is switched on the way a deployment does it: through
// EXECD_RUNTIME_INIT_ONCE and flag.InitFlags, so this file names no symbol that only the
// change has. On a tree without the change the variable is ignored, a second
// /internal/init is accepted and replaces the token, and the assertions below fail on
// what the router answers.
func initFlagsFromEnv(t *testing.T, once string) {
	t.Helper()
	previousArgs, previousCommandLine := os.Args, stdflag.CommandLine
	stdflag.CommandLine = stdflag.NewFlagSet(os.Args[0], stdflag.ContinueOnError)
	os.Args = []string{previousArgs[0]}
	require.NoError(t, os.Setenv("EXECD_RUNTIME_INIT", "true"))
	require.NoError(t, os.Setenv("EXECD_RUNTIME_INIT_ONCE", once))
	flag.InitFlags()
	os.Args, stdflag.CommandLine = previousArgs, previousCommandLine
}

func withRuntimeInitOnce(t *testing.T) {
	t.Helper()
	previous := flag.RuntimeInit
	// Registered first, so the environment is restored last.
	t.Setenv("EXECD_RUNTIME_INIT", "")
	t.Setenv("EXECD_RUNTIME_INIT_ONCE", "")
	initFlagsFromEnv(t, "true")
	t.Cleanup(func() {
		// Switch the mode back off through the same door, then restore the gate.
		initFlagsFromEnv(t, "false")
		flag.RuntimeInit = previous
	})
}

func hashOf(t *testing.T, token string) string {
	t.Helper()
	return binding.HashAccessToken(token)
}

func existingFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe.txt")
	require.NoError(t, os.WriteFile(path, []byte("probe"), 0o644))
	return path
}

func postInit(t *testing.T, r http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/init", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func getWith(r http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set(model.ApiAccessTokenHeader, token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func initBody(sandbox string, generation int, hash string) string {
	body := `{"sandboxId":"` + sandbox + `","generation":` + strconv.Itoa(generation)
	if hash != "" {
		body += `,"accessTokenHash":"` + hash + `"`
	}
	return body + `}`
}

// The first completed init is the only one: a later one with another token hash answers
// 409 and the first token keeps working while the second is refused.
func TestWM26SecondRuntimeInitIsRefusedAndKeepsTheFirstToken(t *testing.T) {
	withRuntimeInitOnce(t)
	withTestBinding(t, nil)
	withManager(t, false)
	r := NewRouter("")

	first := postInit(t, r, initBody("sbx", 1, hashOf(t, "token-A")))
	require.Equal(t, http.StatusOK, first.Code, "the first init must complete: %s", first.Body)
	require.Equal(t, http.StatusOK, getWith(r, "/ready", "").Code)

	second := postInit(t, r, initBody("other", 2, hashOf(t, "token-B")))
	require.Equal(t, http.StatusConflict, second.Code,
		"a second /internal/init was not refused, it replaced the binding: %s", second.Body)
	require.Contains(t, second.Body.String(), "ALREADY_INITIALIZED")

	probe := "/files/info?path=" + url.QueryEscape(existingFile(t))
	okA := getWith(r, probe, "token-A")
	require.Equal(t, http.StatusOK, okA.Code, "token A was refused after a second init: %s", okA.Body)
	require.Contains(t, okA.Body.String(), "size", "the authorized route did not answer with file info: %s", okA.Body)
	require.Equal(t, http.StatusUnauthorized, getWith(r, probe, "token-B").Code,
		"token B was accepted: the second init took the sandbox over")
	b := binding.Current()
	require.NotNil(t, b)
	require.Equal(t, "sbx", b.SandboxID, "the binding was replaced by the refused init")
}

// Without a token hash a binding would leave execd open for good, so once mode refuses
// it and execd stays uninitialized -- and the init is not consumed.
func TestWM26InitWithoutAccessTokenHashIsRefused(t *testing.T) {
	withRuntimeInitOnce(t)
	withTestBinding(t, nil)
	withManager(t, false)
	r := NewRouter("")

	w := postInit(t, r, initBody("sbx", 1, ""))
	require.Equal(t, http.StatusBadRequest, w.Code, "an init without accessTokenHash was accepted: %s", w.Body)
	require.Equal(t, http.StatusServiceUnavailable, getWith(r, "/ready", "").Code, "execd became ready without a token")

	ok := postInit(t, r, initBody("sbx", 1, hashOf(t, "token-A")))
	require.Equal(t, http.StatusOK, ok.Code, "a refused init consumed the one allowed: %s", ok.Body)
}

// Of concurrent inits exactly one wins; the rest see 409.
func TestWM26ConcurrentRuntimeInitsExactlyOneWins(t *testing.T) {
	withRuntimeInitOnce(t)
	withTestBinding(t, nil)
	withManager(t, false)
	r := NewRouter("")

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = postInit(t, r, initBody("sbx-"+strconv.Itoa(i), i+1, hashOf(t, "token-"+string(rune('a'+i))))).Code
		}(i)
	}
	wg.Wait()
	wins, conflicts, winner := 0, 0, -1
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
			winner = i
		case http.StatusConflict:
			conflicts++
		}
	}
	require.Equal(t, 1, wins, "codes: %v", codes)
	require.Equal(t, n-1, conflicts, "codes: %v", codes)

	// The state is the winner's, whole: its binding, and only its token.
	b := binding.Current()
	require.NotNil(t, b)
	require.Equal(t, "sbx-"+strconv.Itoa(winner), b.SandboxID, "the binding is not the winner's")
	require.Equal(t, uint64(winner+1), uint64(b.Generation), "the generation is not the winner's")
	probe := "/files/info?path=" + url.QueryEscape(existingFile(t))
	for i := 0; i < n; i++ {
		want := http.StatusUnauthorized
		if i == winner {
			want = http.StatusOK
		}
		require.Equal(t, want, getWith(r, probe, "token-"+string(rune('a'+i))).Code, "token of request %d (winner %d)", i, winner)
	}
}

// A preserve-state init also installs a token and opens the gate, so it consumes the
// one allowed: a later, ordinary init must not replace the token it installed.
func TestWM26PreserveStateInitConsumesTheOneAllowed(t *testing.T) {
	withRuntimeInitOnce(t)
	withTestBinding(t, nil)
	withManager(t, false)
	r := NewRouter("")

	first := postInit(t, r, `{"sandboxId":"sbx","generation":1,"preserveRuntimeState":true,"accessTokenHash":"`+hashOf(t, "token-A")+`"}`)
	require.Equal(t, http.StatusOK, first.Code, "the preserve-state init must complete: %s", first.Body)

	second := postInit(t, r, initBody("other", 2, hashOf(t, "token-B")))
	require.Equal(t, http.StatusConflict, second.Code,
		"an init after a preserve-state init replaced the token: %s", second.Body)

	probe := "/files/info?path=" + url.QueryEscape(existingFile(t))
	require.Equal(t, http.StatusOK, getWith(r, probe, "token-A").Code, "token A was refused")
	require.Equal(t, http.StatusUnauthorized, getWith(r, probe, "token-B").Code, "token B was accepted")
}
