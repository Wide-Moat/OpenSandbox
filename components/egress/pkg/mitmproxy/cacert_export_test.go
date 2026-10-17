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

package mitmproxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
)

func TestCandidateCACertPaths(t *testing.T) {
	h := "/var/lib/mitmproxy"
	got := candidateCACertPaths("", h)
	require.Equal(t, []string{filepath.Join(h, ".mitmproxy", mitmCACertName)}, got)

	got = candidateCACertPaths("/custom", h)
	require.Equal(t, []string{
		filepath.Join("/custom", mitmCACertName),
		filepath.Join("/custom", ".mitmproxy", mitmCACertName),
		filepath.Join(h, ".mitmproxy", mitmCACertName),
	}, got)
}

func TestPurgeStaleExportedCAFrom_RemovesExistingFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, mitmCACertName)
	require.NoError(t, os.WriteFile(path, []byte("stale-ca"), 0o644))

	purgeStaleExportedCAFrom(root)

	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "expected file to be removed, got err=%v", err)
}

func TestPurgeStaleExportedCAFrom_NoFileIsNoOp(t *testing.T) {
	root := t.TempDir()
	// No file present; must not panic and must not create anything.
	purgeStaleExportedCAFrom(root)

	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestPurgeStaleExportedCAFrom_LeavesUnrelatedFiles(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, mitmCACertName)
	require.NoError(t, os.WriteFile(stale, []byte("stale-ca"), 0o644))

	// A sibling file that must survive (e.g. the agent's merged bundle).
	other := filepath.Join(root, "merged-ca-certificates.pem")
	require.NoError(t, os.WriteFile(other, []byte("merged"), 0o644))

	purgeStaleExportedCAFrom(root)

	_, err := os.Stat(stale)
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(other)
	require.NoError(t, err)
}

func TestSyncRootCAFastSandboxExportsToSubdirWithoutSystemTrust(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "mitmhome")
	confdir := filepath.Join(home, ".mitmproxy")
	require.NoError(t, os.MkdirAll(confdir, 0o755))
	cert := filepath.Join(confdir, mitmCACertName)
	require.NoError(t, os.WriteFile(cert, []byte("fast-sandbox-ca"), 0o644))

	// constants.OpenSandboxRootDir is a fixed /opt/opensandbox path; verify
	// exportRootCA directly with a temp root instead of the env-dependent
	// SyncRootCAFastSandbox wrapper.
	rootDir := filepath.Join(root, "opt", "opensandbox", FastSandboxCAExportDir)
	require.NoError(t, exportRootCA(confdir, home, rootDir, false))

	dst := filepath.Join(rootDir, mitmCACertName)
	content, err := os.ReadFile(dst)
	require.NoError(t, err)
	require.Equal(t, "fast-sandbox-ca", string(content))

	// no system-trust install was attempted: no ca-certificates dirs created
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotEqual(t, "usr", e.Name(), "system trust install must be skipped for the fast-sandbox export")
	}
}

// The guard on WM-31: in-pod (sidecar) enforcement keeps upstream's behaviour -- the
// export adds the CA to the system store, through update-ca-certificates, before it
// answers. The store is pointed at a temporary directory and the tool is a stub on PATH.
func TestWM31SidecarEnforcementStillWritesTheSystemTrustStore(t *testing.T) {
	t.Setenv(constants.EnvEnforcement, "")
	root := t.TempDir()
	home := filepath.Join(root, "mitmhome")
	confdir := filepath.Join(home, ".mitmproxy")
	require.NoError(t, os.MkdirAll(confdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(confdir, mitmCACertName), []byte("wm31-ca"), 0o644))
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	marker := filepath.Join(root, "update-ca-certificates.ran")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "update-ca-certificates"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	trust := filepath.Join(root, "ca-certificates")
	orig := systemTrustDir
	systemTrustDir = trust
	t.Cleanup(func() { systemTrustDir = orig })

	require.NoError(t, exportRootCA(confdir, home, filepath.Join(root, "opt"), true))

	_, err := os.Stat(marker)
	require.NoError(t, err, "update-ca-certificates was not run under sidecar enforcement")
	installed, err := os.ReadFile(filepath.Join(trust, "opensandbox-mitmproxy-ca.crt"))
	require.NoError(t, err)
	require.Equal(t, "wm31-ca", string(installed))
}

// WM-31 on any host: under external enforcement the export never runs
// update-ca-certificates and never writes the system store -- here a temporary directory --
// while the sandbox's copy is in place. (system_trust_wm31_test.go proves the same with
// upstream symbols only, where the host allows it.)
func TestWM31ExternalEnforcementWritesNoSystemTrustStore(t *testing.T) {
	t.Setenv(constants.EnvEnforcement, constants.EnforcementExternal)
	root := t.TempDir()
	home := filepath.Join(root, "mitmhome")
	confdir := filepath.Join(home, ".mitmproxy")
	require.NoError(t, os.MkdirAll(confdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(confdir, mitmCACertName), []byte("wm31-ca"), 0o644))
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	marker := filepath.Join(root, "update-ca-certificates.ran")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "update-ca-certificates"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	trust := filepath.Join(root, "ca-certificates")
	orig := systemTrustDir
	systemTrustDir = trust
	t.Cleanup(func() { systemTrustDir = orig })
	rootDir := filepath.Join(root, "opt")

	require.NoError(t, exportRootCA(confdir, home, rootDir, true))

	content, err := os.ReadFile(filepath.Join(rootDir, mitmCACertName))
	require.NoError(t, err)
	require.Equal(t, "wm31-ca", string(content))
	_, err = os.Stat(marker)
	require.True(t, os.IsNotExist(err), "update-ca-certificates was run under external enforcement")
	_, err = os.Stat(trust)
	require.True(t, os.IsNotExist(err), "the system store was written under external enforcement")
}
