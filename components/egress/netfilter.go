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
	"fmt"

	"github.com/alibaba/opensandbox/egress/pkg/iptables"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// The redirects the sidecar installs in its own pod, and removes on shutdown. Variables
// so that a test can see whether each is attempted at all: under external enforcement
// none may be, and a guard that nothing observes is one a rebase can drop silently.
var (
	setupDNSRedirect   = iptables.SetupRedirect
	removeDNSRedirect  = iptables.RemoveRedirect
	setupHTTPRedirect  = iptables.SetupTransparentHTTP
	removeHTTPRedirect = iptables.RemoveTransparentHTTP
)

// installHTTPRedirect points the pod's outbound HTTP(S) at mitmdump. Not under external
// enforcement: clients then reach mitmdump as an explicit proxy and name the destination
// in CONNECT, so there is nothing to install.
func installHTTPRedirect(external bool, port int, uid uint32, dports string) error {
	if external {
		log.Infof("mitmproxy: regular proxy on 127.0.0.1:%d (enforcement=external; point clients at it with HTTPS_PROXY and trust the mitm CA)", port)
		return nil
	}
	if err := setupHTTPRedirect(port, uid, dports); err != nil {
		return fmt.Errorf("iptables transparent: %w", err)
	}
	log.Infof("mitmproxy: transparent intercept active (OUTPUT tcp %s -> %d; trust mitm CA in clients)", dports, port)
	return nil
}
