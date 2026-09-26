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
	"errors"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/events"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

const (
	defaultWebhookDrainTimeout   = 5 * time.Second
	defaultPolicyShutdownTimeout = 5 * time.Second
	defaultNftTeardownTimeout    = 5 * time.Second
	defaultMitmShutdownTimeout   = 5 * time.Second
)

func waitForShutdown(ctx context.Context, proxy *dnsproxy.Proxy, policySrv *http.Server, exemptDst []netip.Addr, applier nftApplier, mitm *mitmTransparent, broadcaster *events.Broadcaster) {
	<-ctx.Done()
	log.Infof("received shutdown signal; beginning graceful shutdown")

	// Keep DNS and enforcement alive while accepted notifications finish.
	if broadcaster != nil {
		drainCtx, cancel := context.WithTimeout(context.Background(), defaultWebhookDrainTimeout)
		if err := broadcaster.Shutdown(drainCtx); err != nil {
			log.Warnf("[webhook] drain timed out; remaining deliveries cancelled: %v", err)
		}
		cancel()
	}

	policyShutdownCtx, policyCancel := context.WithTimeout(context.Background(), defaultPolicyShutdownTimeout)
	defer policyCancel()

	if policySrv != nil {
		if err := policySrv.Shutdown(policyShutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("policy server shutdown error: %v", err)
		}
	}

	proxy.SetOnResolved(nil)

	if err := proxy.Shutdown(); err != nil {
		log.Errorf("dns proxy shutdown error: %v", err)
	}

	if mitm != nil {
		if !constants.EnforcementIsExternal() {
			removeHTTPRedirect(mitm.port, mitm.uid, mitm.dports)
		}
		mitm.shutdown(defaultMitmShutdownTimeout)
	}
	// Symmetric with startup: nothing was installed under external enforcement, so
	// there is nothing to remove — and the attempt would fail the same way the setup
	// would, on a netfilter subsystem that is not there.
	if !constants.EnforcementIsExternal() {
		removeDNSRedirect(15353, exemptDst)
	}

	if applier != nil {
		nftCtx, nftCancel := context.WithTimeout(context.Background(), defaultNftTeardownTimeout)
		defer nftCancel()
		if err := applier.RemoveEnforcement(nftCtx); err != nil {
			log.Errorf("nftables teardown error: %v", err)
		}
	}

	log.Infof("egress shutdown complete")
	_ = os.Stderr.Sync()
}
