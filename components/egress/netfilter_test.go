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
	"net/netip"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/stretchr/testify/require"
)

// recordNetfilter replaces the four redirect calls with recorders for one test.
func recordNetfilter(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	origSetupDNS, origRemoveDNS := setupDNSRedirect, removeDNSRedirect
	origSetupHTTP, origRemoveHTTP := setupHTTPRedirect, removeHTTPRedirect
	t.Cleanup(func() {
		setupDNSRedirect, removeDNSRedirect = origSetupDNS, origRemoveDNS
		setupHTTPRedirect, removeHTTPRedirect = origSetupHTTP, origRemoveHTTP
	})
	setupDNSRedirect = func(int, []netip.Addr) error { calls = append(calls, "setup dns"); return nil }
	removeDNSRedirect = func(int, []netip.Addr) { calls = append(calls, "remove dns") }
	setupHTTPRedirect = func(int, uint32, string) error { calls = append(calls, "setup http"); return nil }
	removeHTTPRedirect = func(int, uint32, string) { calls = append(calls, "remove http") }
	return &calls
}

// shutDown runs waitForShutdown as SIGTERM would, with a mitmproxy that was running.
func shutDown(t *testing.T) {
	t.Helper()
	proxy, err := dnsproxy.New(nil, "127.0.0.1:0", nil, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waitForShutdown(ctx, proxy, nil, nil, nil, &mitmTransparent{port: 18081, dports: "80,443"}, nil)
}

// WM-1: external enforcement installed no HTTP redirect, so shutdown removes none, and no
// DNS redirect either. The process-level test in enforcement_startup_test.go covers the
// DNS half; only this one can reach the mitmproxy half, which needs a running mitmdump.
func TestWM1ShutdownRemovesNoRedirectUnderExternalEnforcement(t *testing.T) {
	t.Setenv(constants.EnvEnforcement, constants.EnforcementExternal)
	calls := recordNetfilter(t)

	shutDown(t)

	require.Empty(t, *calls, "nothing was installed under external enforcement")
}

// The guard, and the proof the recorders see the calls at all.
func TestWM1ShutdownStillRemovesBothRedirectsByDefault(t *testing.T) {
	calls := recordNetfilter(t)

	shutDown(t)

	require.Equal(t, []string{"remove http", "remove dns"}, *calls)
}

func TestWM1ExternalEnforcementInstallsNoHTTPRedirect(t *testing.T) {
	calls := recordNetfilter(t)

	require.NoError(t, installHTTPRedirect(true, 18081, 1000, "80,443"))
	require.Empty(t, *calls, "a regular proxy needs no redirect")

	require.NoError(t, installHTTPRedirect(false, 18081, 1000, "80,443"))
	require.Equal(t, []string{"setup http"}, *calls, "transparent mode still installs it")
}

// launchOffTheImage runs startMitmproxyTransparentIfEnabled with no mitmproxy user, no
// mitmdump and no CA to export -- none of which exist off the image -- and returns the
// Config the launcher handed to mitmdump.
func launchOffTheImage(t *testing.T) mitmproxy.Config {
	t.Helper()
	origLookup, origLaunch := lookupMitmproxyUser, launchMitmdump
	origWait, origExport := waitMitmdumpListen, exportMitmCA
	t.Cleanup(func() {
		lookupMitmproxyUser, launchMitmdump = origLookup, origLaunch
		waitMitmdumpListen, exportMitmCA = origWait, origExport
	})
	var launched *mitmproxy.Config
	lookupMitmproxyUser = func(string) (uint32, uint32, string, error) { return 10042, 10042, t.TempDir(), nil }
	launchMitmdump = func(_ context.Context, cfg mitmproxy.Config, _ chan<- exitEvent, _ <-chan struct{}, _ uint64,
		_ *revisionLaunchOwner) (*mitmproxy.Running, revisionProcessSession, error) {
		launched = &cfg
		return &mitmproxy.Running{}, nil, nil
	}
	waitMitmdumpListen = func(context.Context, string, time.Duration) error { return nil }
	exportMitmCA = func(string, string) error { return nil }

	t.Setenv(constants.EnvMitmproxyTransparent, "true")
	mitm, err := startMitmproxyTransparentIfEnabled(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, mitm)
	require.NotNil(t, launched, "the launcher never started mitmdump")
	return *launched
}

// WM-1 through the launcher itself: under external enforcement mitmdump is told to run
// as a regular proxy, and no HTTP redirect is installed. The two halves are separate
// lines in startMitmproxyTransparentIfEnabled -- the ConfigFromEnv wrapper and the
// external flag handed to installHTTPRedirect -- and deleting either one left every
// other test green: the tests of each helper pass it their own input.
func TestWM1ExternalEnforcementLaunchesARegularProxyAndInstallsNoRedirect(t *testing.T) {
	t.Setenv(constants.EnvEnforcement, constants.EnforcementExternal)
	calls := recordNetfilter(t)

	cfg := launchOffTheImage(t)

	require.True(t, cfg.Regular, "mitmdump was launched transparent under external enforcement")
	require.Empty(t, *calls, "external enforcement must install no HTTP redirect")
}

// The guard, and the proof the stubs see the launcher's decision at all.
func TestWM1TheLauncherIsStillTransparentByDefault(t *testing.T) {
	calls := recordNetfilter(t)

	cfg := launchOffTheImage(t)

	require.False(t, cfg.Regular, "mitmdump must stay transparent by default")
	require.Equal(t, []string{"setup http"}, *calls, "the default still installs the HTTP redirect")
}
