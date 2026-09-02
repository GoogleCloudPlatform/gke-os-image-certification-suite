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
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestSysctlInotifyMaxUserWatches_Success(t *testing.T) {
	c := findCheck("observability/sysctl-inotify-max-user-watches")
	if c == nil {
		t.Fatal("Check observability/sysctl-inotify-max-user-watches not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n fs.inotify.max_user_watches": {
				Out: []byte("524288\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestSysctlInotifyMaxUserWatches_Warning(t *testing.T) {
	c := findCheck("observability/sysctl-inotify-max-user-watches")
	if c == nil {
		t.Fatal("Check observability/sysctl-inotify-max-user-watches not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n fs.inotify.max_user_watches": {
				Out: []byte("8192\n"),
				Err: nil,
			},
		},
	}
	// Low value should pass with a warning, not fail
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass with warning for 8192, got error: %v", err)
	}
}

func TestSysctlInotifyMaxUserWatches_Invalid(t *testing.T) {
	c := findCheck("observability/sysctl-inotify-max-user-watches")
	if c == nil {
		t.Fatal("Check observability/sysctl-inotify-max-user-watches not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n fs.inotify.max_user_watches": {
				Out: []byte("0\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail when inotify watches is 0, but it passed")
	}
}

func TestSysctlUnprivilegedPortStart_Success(t *testing.T) {
	c := findCheck("observability/sysctl-unprivileged-port-start")
	if c == nil {
		t.Fatal("Check observability/sysctl-unprivileged-port-start not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n net.ipv4.ip_unprivileged_port_start": {
				Out: []byte("1024\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestSysctlUnprivilegedPortStart_TooHigh(t *testing.T) {
	c := findCheck("observability/sysctl-unprivileged-port-start")
	if c == nil {
		t.Fatal("Check observability/sysctl-unprivileged-port-start not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n net.ipv4.ip_unprivileged_port_start": {
				Out: []byte("8192\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail when ip_unprivileged_port_start > 2021, but it passed")
	}
}

func TestKernelConfigMemcg_Success(t *testing.T) {
	c := findCheck("observability/kernel-config-memcg")
	if c == nil {
		t.Fatal("Check observability/kernel-config-memcg not registered")
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"grep -E '^memory\\s' /proc/cgroups 2>/dev/null": {
				Out: []byte("memory\t1\t100\t1\n"),
				Err: nil,
			},
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}
