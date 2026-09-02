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

package networking

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestNetworkStackCheck_Sysctl_Success(t *testing.T) {
	check := &networkStackCheck{
		sysctlParam:   "net.ipv4.ip_forward",
		allowedValues: []string{"1"},
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -n net.ipv4.ip_forward": {
				Out: []byte("1\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected sysctl check to pass, got error: %v", err)
	}
}

func TestNetworkStackCheck_IPv6Disable_Success(t *testing.T) {
	check := &networkStackCheck{
		sysctlParam:   "net.ipv6.conf.all.disable_ipv6",
		allowedValues: []string{"0"},
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || sysctl -n net.ipv6.conf.all.disable_ipv6": {
				Out: []byte("0\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected disable_ipv6 check to pass, got error: %v", err)
	}
}

func TestNetworkStackCheck_Sysctl_Failure(t *testing.T) {
	check := &networkStackCheck{
		sysctlParam:   "net.ipv4.ip_forward",
		allowedValues: []string{"1"},
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -n net.ipv4.ip_forward": {
				Out: []byte("0\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected sysctl check to fail when parameter value is 0, got nil")
	}
}

func TestNetworkStackCheck_FunctionalProbes_Success(t *testing.T) {
	allChecks := validation.RegisteredChecks()
	probes := []struct {
		name string
		cmd  string
		out  string
	}{
		{
			name: "networking/systemd-networkd-foreign-rules",
			cmd:  "! systemctl is-active --quiet systemd-networkd || ! networkctl status 2>/dev/null | grep -q 'ManageForeignRoutingPolicyRules=yes'",
			out:  "",
		},
		{
			name: "networking/iptables-functional",
			cmd:  "sudo iptables -L -n",
			out:  "Chain INPUT (policy ACCEPT)\n",
		},
		{
			name: "networking/ip6tables-functional",
			cmd:  "sudo ip6tables -L -n",
			out:  "Chain INPUT (policy ACCEPT)\n",
		},
		{
			name: "networking/ipv6-policy-routing",
			cmd:  "ip -6 rule show",
			out:  "0: from all lookup local\n",
		},
	}

	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			var found validation.Check
			for _, c := range allChecks {
				if c.Name() == probe.name {
					found = c
					break
				}
			}
			if found == nil {
				t.Fatalf("Check %s not registered", probe.name)
			}

			runner := &testutil.MockSSHRunner{
				CombinedOutputResult: map[string]testutil.CombinedOutputVal{
					probe.cmd: {
						Out: []byte(probe.out),
						Err: nil,
					},
				},
			}

			if err := found.Run(context.Background(), runner); err != nil {
				t.Fatalf("Expected %s to pass, got error: %v", probe.name, err)
			}
		})
	}
}

func TestNetworkStackCheck_FunctionalProbes_Failure(t *testing.T) {
	check := &networkStackCheck{
		name:    "iptables-functional",
		command: "sudo iptables -L -n",
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"sudo iptables -L -n": {
				Out: []byte("iptables: Table does not exist (do you need to insmod?)\n"),
				Err: fmt.Errorf("exit status 1"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected functional probe check to fail, got nil")
	}
	if !strings.Contains(err.Error(), "iptables: Table does not exist") {
		t.Errorf("Expected error to contain failure output, got %v", err)
	}
}

func TestNetworkStackCheck_Metadata(t *testing.T) {
	check := &networkStackCheck{
		name:        "sysctl-net-ipv4-ip_forward",
		description: "Verifies that sysctl net.ipv4.ip_forward is set to 1 (IPv4 packet forwarding)",
	}

	if check.Name() != "networking/sysctl-net-ipv4-ip_forward" {
		t.Errorf("Expected name 'networking/sysctl-net-ipv4-ip_forward', got %q", check.Name())
	}
	if check.Description() != "Verifies that sysctl net.ipv4.ip_forward is set to 1 (IPv4 packet forwarding)" {
		t.Errorf("Expected description 'Verifies that sysctl net.ipv4.ip_forward is set to 1 (IPv4 packet forwarding)', got %q", check.Description())
	}
	if check.Tier() != validation.Tier1 {
		t.Errorf("Expected tier 1, got %v", check.Tier())
	}
	if check.Destructive() {
		t.Errorf("Expected Destructive to be false")
	}
}
