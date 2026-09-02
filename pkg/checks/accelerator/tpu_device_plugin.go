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

package accelerator

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// tpuSysctlNetworkingCheck verifies that a required network tuning file exists and is writable.
//
// Justification:
// The TPU device plugin actively configures optimal TCP and core network settings
// on startup by writing to these files. The OS kernel must expose these tunable parameters.
type tpuSysctlNetworkingCheck struct {
	path string
}

func (c *tpuSysctlNetworkingCheck) Name() string {
	return "accelerator/tpu-sysctl-networking-" + c.path
}

func (c *tpuSysctlNetworkingCheck) Description() string {
	return fmt.Sprintf("Verifies that TPU networking kernel parameter %s exists and is writable by root", c.path)
}

func (c *tpuSysctlNetworkingCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuSysctlNetworkingCheck) Destructive() bool {
	return false
}

func (c *tpuSysctlNetworkingCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// Check if the file exists and is writable (as root)
	cmd := fmt.Sprintf("(test -f %[1]s && test -w %[1]s) || (sudo test -f %[1]s && sudo test -w %[1]s)", c.path)
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("required kernel network tuning file %s is missing or not writable: %w", c.path, err)
	}
	return nil
}

// tpuRequiredBinariesCheck verifies that standard Linux networking and system tools required by the TPU device plugin are installed.
//
// Justification:
// Init containers (like tpu-network-optimization) and device discovery rely on ethtool, iproute2, procps, and pciutils.
type tpuRequiredBinariesCheck struct{}

func (c *tpuRequiredBinariesCheck) Name() string {
	return "accelerator/tpu-required-binaries"
}

func (c *tpuRequiredBinariesCheck) Description() string {
	return "Verifies that required binaries (ethtool, ip, sysctl, lspci) are installed on the host"
}

func (c *tpuRequiredBinariesCheck) Tier() validation.Tier {
	return validation.Tier0
}

func (c *tpuRequiredBinariesCheck) Destructive() bool {
	return false
}

func (c *tpuRequiredBinariesCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	binaries := []string{"ethtool", "ip", "sysctl", "lspci"}

	for _, bin := range binaries {
		cmd := fmt.Sprintf("command -v %s", bin)
		if err := runner.Run(ctx, cmd); err != nil {
			return fmt.Errorf("required binary %s is not installed or not in PATH", bin)
		}
	}
	return nil
}

// tpuAbsentVbarAgentCheck verifies that pre-baked TPU agents (vbarcontrolagent and ai-telemetry-collector)
// are NOT installed on the host image.
//
// Justification:
// In GKE, the TPU device plugin dynamically manages and deploys the vbar agent during node bootstrap.
// Pre-installing vbarcontrolagent or ai-telemetry-collector on the base OS image conflicts with the GKE TPU daemonset.
type tpuAbsentVbarAgentCheck struct{}

func (c *tpuAbsentVbarAgentCheck) Name() string {
	return "accelerator/tpu-absent-vbar-agent"
}

func (c *tpuAbsentVbarAgentCheck) Description() string {
	return "Verifies that pre-baked vbar agent (vbarcontrolagent) and conflicting TPU agents are not installed on the host"
}

func (c *tpuAbsentVbarAgentCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuAbsentVbarAgentCheck) Destructive() bool {
	return false
}

func (c *tpuAbsentVbarAgentCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	disallowedAgents := []string{"vbarcontrolagent", "ai-telemetry-collector"}

	var foundAgents []string
	for _, agent := range disallowedAgents {
		// 1. Check if installed via snap
		if err := runner.Run(ctx, fmt.Sprintf("snap list %s", agent)); err == nil {
			foundAgents = append(foundAgents, fmt.Sprintf("%s (snap)", agent))
			continue
		}

		// 2. Check if installed as a systemd service
		cmd := fmt.Sprintf("systemctl list-unit-files '%s*' 'snap.%s*' 2>/dev/null | grep -E -q '(^|snap\\.)%s'", agent, agent, agent)
		if err := runner.Run(ctx, cmd); err == nil {
			foundAgents = append(foundAgents, fmt.Sprintf("%s (systemd service)", agent))
			continue
		}

		// 3. Check if binary is present in PATH
		if err := runner.Run(ctx, fmt.Sprintf("command -v %s", agent)); err == nil {
			foundAgents = append(foundAgents, fmt.Sprintf("%s (binary)", agent))
			continue
		}
	}

	// Also check for vbar_control_agent binary in PATH
	if err := runner.Run(ctx, "command -v vbar_control_agent"); err == nil {
		foundAgents = append(foundAgents, "vbar_control_agent (binary)")
	}

	if len(foundAgents) > 0 {
		return fmt.Errorf("disallowed TPU agent(s) found installed on the image: %s (must not be pre-installed; TPU device plugin installs vbar agent dynamically, see b/549734304)", strings.Join(foundAgents, ", "))
	}

	return nil
}

// tpuSysctlNetworkingFiles lists the kernel network tuning files the TPU device plugin configures.
var tpuSysctlNetworkingFiles = []string{
	"/proc/sys/net/ipv4/tcp_slow_start_after_idle",
	"/proc/sys/net/ipv4/tcp_no_metrics_save",
	"/sys/module/tcp_cubic/parameters/hystart_detect",
	"/proc/sys/net/core/somaxconn",
	"/proc/sys/net/ipv4/tcp_max_syn_backlog",
	"/proc/sys/net/ipv4/tcp_mtu_probing",
	"/proc/sys/net/core/optmem_max",
}

func init() {
	for _, f := range tpuSysctlNetworkingFiles {
		validation.Register(&tpuSysctlNetworkingCheck{path: f})
	}
	validation.Register(&tpuRequiredBinariesCheck{})
	validation.Register(&tpuAbsentVbarAgentCheck{})
}
