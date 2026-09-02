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
	"slices"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// SysctlSpec defines expected allowed values and description for a sysctl parameter
// under the GKE Dataplane V2 Conformance Contract.
type SysctlSpec struct {
	AllowedValues []string
	Description   string
}

// SysctlFeatures maps sysctl parameter strings (e.g. "net.ipv4.ip_forward")
// to their allowed values and descriptions.
var SysctlFeatures = map[string]SysctlSpec{
	"net.ipv4.ip_forward":                {AllowedValues: []string{"1"}, Description: "Verifies that sysctl net.ipv4.ip_forward is set to 1"},
	"net.core.bpf_jit_enable":            {AllowedValues: []string{"1"}, Description: "Verifies that sysctl net.core.bpf_jit_enable is set to 1"},
	"net.ipv6.conf.all.disable_ipv6":     {AllowedValues: []string{"0"}, Description: "Verifies that sysctl net.ipv6.conf.all.disable_ipv6 is set to 0"},
	"net.ipv6.conf.default.disable_ipv6": {AllowedValues: []string{"0"}, Description: "Verifies that sysctl net.ipv6.conf.default.disable_ipv6 is set to 0"},
}

// FunctionalProbeSpec defines the configuration for a functional network stack command probe.
type FunctionalProbeSpec struct {
	Description string
	Command     string
}

// FunctionalProbes maps custom CLI and subsystem functional probes under the GKE Dataplane V2 Contract.
var FunctionalProbes = map[string]FunctionalProbeSpec{
	"systemd-networkd-foreign-rules": {
		Description: "Verifies that systemd-networkd has ManageForeignRoutingPolicyRules=no to prevent deleting Cilium ip rules",
		Command:     "! systemctl is-active --quiet systemd-networkd || ! networkctl status 2>/dev/null | grep -q 'ManageForeignRoutingPolicyRules=yes'",
	},
	"iptables-functional": {
		Description: "Verifies that iptables CLI is working and can query kernel IPv4 Netfilter tables",
		Command:     "sudo iptables -L -n",
	},
	"ip6tables-functional": {
		Description: "Verifies that ip6tables CLI is working and can query kernel IPv6 Netfilter tables",
		Command:     "sudo ip6tables -L -n",
	},
	"ipv6-policy-routing": {
		Description: "Verifies that IPv6 FIB policy routing rules (ip -6 rule) are supported and responsive",
		Command:     "ip -6 rule show",
	},
}

// networkStackCheck is a unified check struct for network stack requirements,
// verifying either kernel sysctl parameters (/proc/sys/net/...) against allowed values
// or executing functional probe logic.
type networkStackCheck struct {
	name          string
	description   string
	sysctlParam   string
	allowedValues []string
	command       string
}

func (c *networkStackCheck) Name() string          { return "networking/" + c.name }
func (c *networkStackCheck) Description() string   { return c.description }
func (c *networkStackCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *networkStackCheck) Destructive() bool     { return false }

// Run executes the network stack check over SSH against the target VM or node.
func (c *networkStackCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if c.command != "" {
		out, err := runner.CombinedOutput(ctx, c.command)
		if err != nil {
			return fmt.Errorf("%s functional probe failed: %w\nOutput:\n%s", c.name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if c.sysctlParam != "" {
		procPath := "/proc/sys/" + strings.ReplaceAll(c.sysctlParam, ".", "/")
		cmd := fmt.Sprintf("cat %s 2>/dev/null || sysctl -n %s", procPath, c.sysctlParam)
		out, err := runner.CombinedOutput(ctx, cmd)
		if err != nil {
			return fmt.Errorf("failed to read sysctl parameter %s: %w", c.sysctlParam, err)
		}
		actual := strings.TrimSpace(string(out))
		if slices.Contains(c.allowedValues, actual) {
			return nil
		}
		return fmt.Errorf("sysctl parameter %s is set to %q, expected one of %v", c.sysctlParam, actual, c.allowedValues)
	}

	return nil
}

func init() {
	// Table-driven registration for sysctl parameters
	for param, spec := range SysctlFeatures {
		validation.Register(&networkStackCheck{
			name:          "sysctl-" + strings.ReplaceAll(param, ".", "-"),
			description:   spec.Description,
			sysctlParam:   param,
			allowedValues: spec.AllowedValues,
		})
	}

	// Table-driven registration for functional probes
	for name, probe := range FunctionalProbes {
		validation.Register(&networkStackCheck{
			name:        name,
			description: probe.Description,
			command:     probe.Command,
		})
	}
}
