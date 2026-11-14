# Copyright 2026 The OpenSandbox Authors
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.25.9-bookworm AS builder

WORKDIR /workspace

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG GOFLAGS=
ARG LDFLAGS=
ARG CGO_ENABLED=0
ARG CC=
ARG CXX=
ARG CFLAGS=
ARG CXXFLAGS=
ARG CGO_CFLAGS=
ARG CGO_CXXFLAGS=
ARG CGO_LDFLAGS=

# Copy only go mod/sum first for better caching
COPY components/egress/go.mod components/egress/go.sum ./components/egress/
# Bring internal module so replace ../internal works during download/build
COPY components/internal ./components/internal

WORKDIR /workspace/components/egress

# Static-ish build (no cgo by default) to simplify runtime deps.
RUN go mod download

# Pre-download internal-module deps for the supervisor build below.
RUN cd /workspace/components/internal && go mod download

# Copy the rest of the egress sources
COPY components/egress ./
RUN if [ -n "${CC}" ]; then export CC; fi; \
    if [ -n "${CXX}" ]; then export CXX; fi; \
    export CGO_ENABLED="${CGO_ENABLED}" \
           CGO_CFLAGS="${CGO_CFLAGS:-${CFLAGS}}" \
           CGO_CXXFLAGS="${CGO_CXXFLAGS:-${CXXFLAGS}}" \
           CGO_LDFLAGS="${CGO_LDFLAGS}"; \
    go build ${GOFLAGS} -trimpath -buildvcs=false \
    -ldflags "${LDFLAGS} -buildid= -B none \
              -X 'github.com/alibaba/opensandbox/internal/version.Version=${VERSION}' \
              -X 'github.com/alibaba/opensandbox/internal/version.BuildTime=${BUILD_TIME}' \
              -X 'github.com/alibaba/opensandbox/internal/version.GitCommit=${GIT_COMMIT}'" \
    -o /out/egress .

# Build the opensandbox-supervisor binary from the internal module.
# Installed alongside /egress so a future ENTRYPOINT switch can wrap egress
# without changing this stage again.
RUN cd /workspace/components/internal && \
    if [ -n "${CC}" ]; then export CC; fi; \
    if [ -n "${CXX}" ]; then export CXX; fi; \
    export CGO_ENABLED="${CGO_ENABLED}" \
           CGO_CFLAGS="${CGO_CFLAGS:-${CFLAGS}}" \
           CGO_CXXFLAGS="${CGO_CXXFLAGS:-${CXXFLAGS}}" \
           CGO_LDFLAGS="${CGO_LDFLAGS}"; \
    go build ${GOFLAGS} -trimpath -buildvcs=false \
    -ldflags "${LDFLAGS} -buildid= -B none \
              -X 'github.com/alibaba/opensandbox/internal/version.Version=${VERSION}' \
              -X 'github.com/alibaba/opensandbox/internal/version.BuildTime=${BUILD_TIME}' \
              -X 'github.com/alibaba/opensandbox/internal/version.GitCommit=${GIT_COMMIT}'" \
    -o /out/opensandbox-supervisor ./cmd/supervisor

FROM debian:bookworm-slim

# iptables is needed for DNS REDIRECT; ca-certificates for TLS to upstream resolvers
# Wide Moat: upgrade first -- the base snapshot ships libbrotli1 1.0.9-2+b6, which has a
# CRITICAL advisory fixed in 1.0.9-2+deb12u1 (WID-361).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        nftables \
        ca-certificates \
        sudo \
        curl \
        wget \
        net-tools \
        dnsutils \
        netcat-openbsd \
        iputils-ping \
        traceroute \
        telnet \
        tcpdump \
        nmap \
        htop \
        procps \
        strace \
        lsof \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Python mitmproxy (transparent mode): mitmdump runs as user mitmproxy; iptables skips this uid.
# /var/lib/mitmproxy is mitm's home, used as the confdir (CA + config.yaml live under .mitmproxy/).
COPY components/egress/mitmproxy/check-h11.py /tmp/check-h11.py
RUN useradd -r -u 10042 -d /var/lib/mitmproxy -s /usr/sbin/nologin mitmproxy \
    && mkdir -p /var/lib/mitmproxy/.mitmproxy \
    && chown -R mitmproxy:mitmproxy /var/lib/mitmproxy \
    && pip3 install --no-cache-dir --break-system-packages 'mitmproxy==11.0.2' \
    # Wide Moat (WID-361): mitmproxy 11.0.2 declares Brotli<=1.1.0, and Brotli 1.1.0 and the
    # certifi pip resolves at build time carry CRITICAL advisories with fixes (Brotli 1.2.1,
    # certifi 2026.10.18). Every mitmproxy release that allows Brotli 1.2.1 needs Python
    # >=3.12, which bookworm (3.11) does not have, so the pin is overridden rather than
    # followed: --no-deps, because pip would otherwise refuse the conflict. mitmproxy only
    # calls brotli.compress/decompress, which 1.2.1 keeps. The check below fails the build
    # if either floor is missing or content decoding through mitmproxy stops working: each
    # direction is checked against the other library, since mitmproxy caches its last
    # encode/decode pair and a round-trip through it alone could skip decompress.
    # h11 the same way: mitmproxy 11.0.2 declares h11<=0.14.0, and h11 0.14.0 carries
    # CVE-2025-43859 (CRITICAL, fixed in 0.16.0); the mitmproxy releases that allow 0.16 need
    # Python >=3.12 as well. The readers mitmproxy uses keep their signatures in 0.16.0 (diffed:
    # only ChunkedReader's footer check changed, which is the fix); check-h11.py drives them
    # through mitmproxy and fails the build if a body stops reading or the fix is absent.
    && pip3 install --no-cache-dir --break-system-packages --no-deps 'Brotli==1.2.1' 'certifi>=2026.10.18' 'h11==0.16.0' \
    && python3 /tmp/check-h11.py && rm -f /tmp/check-h11.py \
    && python3 -c "import importlib.metadata as m; from mitmproxy.net import encoding; \
assert m.version('brotli') == '1.2.1', m.version('brotli'); \
assert tuple(map(int, m.version('certifi').split('.'))) >= (2026, 10, 18), m.version('certifi'); \
import brotli; raw = brotli.compress(b'y' * 1000); assert encoding.decode(raw, 'br') == b'y' * 1000; \
d = encoding.encode(b'x' * 1000, 'br'); assert brotli.decompress(d) == b'x' * 1000; \
print('brotli', m.version('brotli'), 'certifi', m.version('certifi'), 'mitmproxy', m.version('mitmproxy'))" \
    && (command -v mitmdump && mitmdump --version) \
    && mkdir -p /var/egress/mitmscripts

# Static mitmproxy options (mode, listen_host, connection_strategy, stream_large_bodies,
# http2, ignore_hosts, ssl_verify_upstream_trusted_confdir). mitmdump auto-loads
# config.yaml from its confdir. Dynamic per-deployment options stay env-driven and
# are applied as --set by launch.go (which overrides values declared here).
COPY components/egress/mitmproxy/config.yaml /var/lib/mitmproxy/.mitmproxy/config.yaml
RUN chown mitmproxy:mitmproxy /var/lib/mitmproxy/.mitmproxy/config.yaml \
    && chmod 0644 /var/lib/mitmproxy/.mitmproxy/config.yaml

# All egress runtime artifacts live under one directory to keep paths grouped.
COPY --from=builder /out/egress /opt/opensandbox-egress/egress
COPY --from=builder /out/opensandbox-supervisor /opt/opensandbox-egress/supervisor
# Pre-start hook: reap any mitmdump left over from a previous crashed
# egress, and remove stale DNS-redirect iptables rules + opensandbox_dns_redirect
# nft tables left pointing at a dead proxy. The `inet opensandbox` policy table
# is intentionally NOT touched — the nftables manager prepends its own delete
# and recreates the table on every ApplyStatic, so it is idempotent.
COPY components/egress/scripts/cleanup.sh /opt/opensandbox-egress/cleanup.sh
RUN chmod 0755 /opt/opensandbox-egress/cleanup.sh \
            /opt/opensandbox-egress/egress \
            /opt/opensandbox-egress/supervisor \
    && ln -s /opt/opensandbox-egress/egress /egress

COPY components/egress/mitmscripts /var/egress/mitmscripts
# The mitmdump addon is loaded by the mitmproxy user (uid 10042): normalize
# permissions so a restrictive build umask (e.g. 027) can never leave the
# scripts unreadable to it.
RUN chmod -R a+rX /var/egress/mitmscripts

# Supervisor wraps the egress binary: restarts on crash with backoff and
# forwards SIGTERM gracefully. The cleanup hook runs only as pre-start; the
# next egress process re-installs all redirect rules itself after startup,
# so there is nothing to run on post-exit.
# Expects OPENSANDBOX_NETWORK_POLICY env at runtime.
ENTRYPOINT ["/opt/opensandbox-egress/supervisor", \
            "--pre-start=/opt/opensandbox-egress/cleanup.sh", \
            "--name=egress", \
            "--grace-period=20s", \
            "--", \
            "/opt/opensandbox-egress/egress"]
