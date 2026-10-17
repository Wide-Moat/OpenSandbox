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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// WM-27, through the process, with the variables named as literals and the HMAC computed
// here, so this builds on a tree without the change and fails there on what the policy
// API answers. Upstream reads an empty OPENSANDBOX_EGRESS_TOKEN as "no authentication at
// all", so a request with no header is answered 200 there.

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// startEgressServing starts the component and waits until its policy API is listening.
// It returns the output so far (for the failure message) and a stop function.
func startEgressServing(t *testing.T, env ...string) (*lockedBuffer, func()) {
	t.Helper()
	bin := buildEgress(t)
	out := &lockedBuffer{}
	run := exec.Command(bin)
	run.Env = egressEnv(t, env)
	run.Stdout, run.Stderr = out, out
	require.NoError(t, run.Start())
	exited := make(chan struct{})
	go func() { _ = run.Wait(); close(exited) }()
	stop := func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = run.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = run.Process.Kill()
			<-exited
		}
	}
	t.Cleanup(stop)

	deadline := time.After(30 * time.Second)
	for !strings.Contains(out.String(), "policy server listening") {
		select {
		case <-exited:
			t.Fatalf("the sidecar exited before its policy API was up:\n%s", out.String())
		case <-deadline:
			t.Fatalf("the sidecar did not bring its policy API up within 30s:\n%s", out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	return out, stop
}

func getPolicyWithToken(t *testing.T, addr, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/policy", nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("OPENSANDBOX-EGRESS-AUTH", token)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func hmacHex(key, subject string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(subject))
	return hex.EncodeToString(mac.Sum(nil))
}

// A key and a subject, no explicit token: the token is hex(HMAC-SHA256(key, subject)).
func TestWM27TokenIsDerivedFromKeyAndSubject(t *testing.T) {
	addr := freeLoopbackAddr(t)
	out, _ := startEgressServing(t,
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns",
		"OPENSANDBOX_EGRESS_HTTP_ADDR="+addr,
		"OPENSANDBOX_EGRESS_TOKEN=",
		"OPENSANDBOX_EGRESS_TOKEN_KEY=k",
		"OPENSANDBOX_EGRESS_TOKEN_SUBJECT=s")

	derived := hmacHex("k", "s")
	require.Len(t, derived, 64)
	require.Equal(t, http.StatusOK, getPolicyWithToken(t, addr, derived),
		"the derived token was refused:\n%s", out.String())
	require.Equal(t, http.StatusUnauthorized, getPolicyWithToken(t, addr, "not-the-token"),
		"a wrong token was accepted:\n%s", out.String())
	require.Equal(t, http.StatusUnauthorized, getPolicyWithToken(t, addr, hmacHex("k", "other-pod")),
		"another pod's token was accepted:\n%s", out.String())
	require.Equal(t, http.StatusUnauthorized, getPolicyWithToken(t, addr, ""),
		"a request with no token was accepted, the sidecar is running open:\n%s", out.String())
}

// An explicit token wins over the key, and the key is said to be ignored.
func TestWM27ExplicitTokenWinsOverTheKey(t *testing.T) {
	addr := freeLoopbackAddr(t)
	out, _ := startEgressServing(t,
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns",
		"OPENSANDBOX_EGRESS_HTTP_ADDR="+addr,
		"OPENSANDBOX_EGRESS_TOKEN=explicit-token",
		"OPENSANDBOX_EGRESS_TOKEN_KEY=k",
		"OPENSANDBOX_EGRESS_TOKEN_SUBJECT=s")

	require.Equal(t, http.StatusOK, getPolicyWithToken(t, addr, "explicit-token"), out.String())
	require.Equal(t, http.StatusUnauthorized, getPolicyWithToken(t, addr, hmacHex("k", "s")),
		"the derived token was accepted next to an explicit one:\n%s", out.String())
	require.Contains(t, out.String(), "OPENSANDBOX_EGRESS_TOKEN_KEY", "the ignored key must be warned about")
}

// A key without a subject must stop the sidecar at startup, not leave it open.
func TestWM27KeyWithoutSubjectIsRefusedAtStartup(t *testing.T) {
	// Built before the clock starts: the bound is on the process, not on go build.
	bin := buildEgress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, bin)
	run.Env = egressEnv(t, []string{
		"OPENSANDBOX_EGRESS_ENFORCEMENT=external",
		"OPENSANDBOX_EGRESS_MODE=dns",
		"OPENSANDBOX_EGRESS_TOKEN=",
		"OPENSANDBOX_EGRESS_TOKEN_KEY=k",
		"OPENSANDBOX_EGRESS_TOKEN_SUBJECT=",
	})
	started := time.Now()
	out, err := run.CombinedOutput()

	require.NoError(t, ctx.Err(), "the component kept running:\n%s", out)
	require.Error(t, err, "the component started:\n%s", out)
	require.Contains(t, string(out), "OPENSANDBOX_EGRESS_TOKEN_SUBJECT",
		"the refusal must name the missing variable:\n%s", out)
	require.Less(t, time.Since(started), 5*time.Second, "the refusal was not prompt")
}
