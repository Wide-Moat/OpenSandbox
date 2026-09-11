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

//go:build linux

package dnsproxy

import (
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

var (
	exemptDialerLogOnce   sync.Once
	externalDialerLogOnce sync.Once
)

// dialerForUpstream sets SO_MARK so iptables can RETURN marked packets (bypass
// redirect for proxy's own upstream DNS queries). When upstream is in the nameserver
// exempt list, returns a plain dialer (no mark) so upstream traffic follows normal
// routing (e.g. via tun); iptables still does not redirect by destination exempt.
// The mark is also skipped entirely when enforcement is external — see below.
func (p *Proxy) dialerForUpstream(upstreamAddr string) *net.Dialer {
	host, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		host = upstreamAddr
	}
	// The mark exists for exactly one reader: the iptables RETURN rule that keeps the
	// proxy's own upstream queries out of the redirect it installed. With enforcement
	// outside the pod there is no redirect and therefore no rule, so the mark has no
	// reader — and setting it would need CAP_NET_ADMIN, which such a deployment does
	// not have. setsockopt then returns EPERM, and because it happens inside Control
	// the whole dial FAILS rather than degrading: every upstream probe errors, twice a
	// minute, on a resolver that is otherwise working.
	//
	// A branch of its own rather than one folded into the exempt-list check below,
	// which it superficially resembles: that one logs "in nameserver exempt list", and
	// saying so about an address that is not in the list would send the next reader to
	// look for a list entry nobody wrote.
	if constants.EnforcementIsExternal() {
		externalDialerLogOnce.Do(func() {
			log.Infof("[dns] enforcement=external: not setting SO_MARK on upstream queries (no redirect to bypass)")
		})
		return &net.Dialer{Timeout: p.upstreamExchangeTimeout}
	}
	if UpstreamInExemptList(host) {
		exemptDialerLogOnce.Do(func() {
			log.Infof("[dns] upstream %s in nameserver exempt list, not setting SO_MARK", host)
		})
		return &net.Dialer{Timeout: p.upstreamExchangeTimeout}
	}

	return &net.Dialer{
		Timeout: p.upstreamExchangeTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, constants.MarkValue)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
}
