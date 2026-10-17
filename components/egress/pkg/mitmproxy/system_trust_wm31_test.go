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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// WM-31, with upstream's symbols only, so that hack/wm-fail-on-base.sh runs it there: under
// external enforcement the export answers once the CA is copied where the sandbox reads it,
// and update-ca-certificates is never run. Upstream ignores the enforcement variable and
// adds the CA to the system store first: unprivileged that fails on the store's directory
// (an error), and where it could write there it runs the stub (which this test refuses).
//
// Linux only, and only where the host's store directory exists and this process cannot
// write it, so that upstream's attempt fails harmlessly instead of adding a test CA to the
// host.
//
// hostSystemTrustDir is the store's directory as upstream and this tree both name it.
const hostSystemTrustDir = "/usr/local/share/ca-certificates"

func TestWM31ExternalEnforcementLeavesTheSystemTrustStoreAlone(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux: the system trust store here is the host's")
	}
	// Checked by trying, not inferred from the uid.
	if probe, err := os.CreateTemp(hostSystemTrustDir, ".wm31-probe-*"); err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("the host's system trust store is writable here; this test would write to it")
	} else if _, statErr := os.Stat(hostSystemTrustDir); statErr != nil {
		t.Skip("the host has no system trust store directory; nothing here would fail as upstream does")
	}
	t.Setenv("OPENSANDBOX_EGRESS_ENFORCEMENT", "external")
	root := t.TempDir()
	home := filepath.Join(root, "mitmhome")
	confdir := filepath.Join(home, ".mitmproxy")
	require.NoError(t, os.MkdirAll(confdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(confdir, mitmCACertName), []byte("wm31-ca"), 0o644))
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	ran := filepath.Join(root, "update-ca-certificates.ran")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "update-ca-certificates"), []byte("#!/bin/sh\ntouch '"+ran+"'\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	rootDir := filepath.Join(root, "opt")

	require.NoError(t, exportRootCA(confdir, home, rootDir, true), "the export tried, and failed, to write the system trust store")
	content, err := os.ReadFile(filepath.Join(rootDir, mitmCACertName))
	require.NoError(t, err)
	require.Equal(t, "wm31-ca", string(content), "the sandbox's copy must be in place")
	_, err = os.Stat(ran)
	require.True(t, os.IsNotExist(err), "update-ca-certificates was run under external enforcement")
}
