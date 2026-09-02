// Copyright 2026 Google LLC
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

package observability

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestContainerdMetricsEndpoint_Listening(t *testing.T) {
	c := findCheck("observability/containerd-metrics-endpoint")
	if c == nil {
		t.Fatal("Check observability/containerd-metrics-endpoint not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ss -tlpn 2>/dev/null | grep -w '1338' || netstat -tlpn 2>/dev/null | grep -w '1338'": {
				Out: []byte("LISTEN 0 128 127.0.0.1:1338 0.0.0.0:*\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestContainerdMetricsEndpoint_Configured(t *testing.T) {
	c := findCheck("observability/containerd-metrics-endpoint")
	if c == nil {
		t.Fatal("Check observability/containerd-metrics-endpoint not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ss -tlpn 2>/dev/null | grep -w '1338' || netstat -tlpn 2>/dev/null | grep -w '1338'": {
				Out: nil,
				Err: errors.New("not listening"),
			},
			"grep -E 'address\\s*=\\s*\"(127\\.0\\.0\\.1|0\\.0\\.0\\.0):1338\"' /etc/containerd/config.toml /etc/containerd/config.d/*.toml 2>/dev/null": {
				Out: []byte("  address = \"127.0.0.1:1338\"\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestContainerdMetricsEndpoint_WritableDirectory(t *testing.T) {
	c := findCheck("observability/containerd-metrics-endpoint")
	if c == nil {
		t.Fatal("Check observability/containerd-metrics-endpoint not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ss -tlpn 2>/dev/null | grep -w '1338' || netstat -tlpn 2>/dev/null | grep -w '1338'": {
				Out: nil,
				Err: errors.New("not listening"),
			},
			"grep -E 'address\\s*=\\s*\"(127\\.0\\.0\\.1|0\\.0\\.0\\.0):1338\"' /etc/containerd/config.toml /etc/containerd/config.d/*.toml 2>/dev/null": {
				Out: nil,
				Err: errors.New("not in config"),
			},
		},
		RunErrMap: map[string]error{
			"test -d /etc/containerd || test -d /etc": nil,
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass for existing containerd dir, got: %v", err)
	}
}

func TestContainerdMetricsEndpoint_Failure(t *testing.T) {
	c := findCheck("observability/containerd-metrics-endpoint")
	if c == nil {
		t.Fatal("Check observability/containerd-metrics-endpoint not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ss -tlpn 2>/dev/null | grep -w '1338' || netstat -tlpn 2>/dev/null | grep -w '1338'": {
				Out: nil,
				Err: errors.New("not listening"),
			},
			"grep -E 'address\\s*=\\s*\"(127\\.0\\.0\\.1|0\\.0\\.0\\.0):1338\"' /etc/containerd/config.toml /etc/containerd/config.d/*.toml 2>/dev/null": {
				Out: nil,
				Err: errors.New("not in config"),
			},
		},
		RunErrMap: map[string]error{
			"test -d /etc/containerd || test -d /etc": errors.New("directory not found"),
		},
	}
	if err := c.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail when neither configured nor found, but it passed")
	}
}

func TestNetworkLoopbackUp_Success(t *testing.T) {
	c := findCheck("observability/network-loopback-up")
	if c == nil {
		t.Fatal("Check observability/network-loopback-up not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ip -br addr show lo | grep -E '^lo\\s+UNKNOWN|UP\\s+127\\.0\\.0\\.1'": {
				Out: []byte("lo               UNKNOWN        127.0.0.1/8 ::1/128 \n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}
