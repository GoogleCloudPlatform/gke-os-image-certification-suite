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
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// sysctlCheck implements validation.Check for kernel sysctl parameters and Kconfig requirements.
type sysctlCheck struct {
	name        string
	description string
	runFunc     func(ctx context.Context, runner validation.SSHRunner) error
}

func (c *sysctlCheck) Name() string          { return "observability/" + c.name }
func (c *sysctlCheck) Description() string   { return c.description }
func (c *sysctlCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *sysctlCheck) Destructive() bool     { return false }
func (c *sysctlCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	return c.runFunc(ctx, runner)
}

func readSysctl(ctx context.Context, runner validation.SSHRunner, param string) (string, error) {
	procPath := "/proc/sys/" + strings.ReplaceAll(param, ".", "/")
	cmd := fmt.Sprintf("cat %s 2>/dev/null || PATH=/sbin:/usr/sbin:$PATH sysctl -n %s", procPath, param)
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to read sysctl %s: %w", param, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func init() {
	// 1. fs.inotify.max_user_watches (warns if < 524288 for high-density logging)
	validation.Register(&sysctlCheck{
		name:        "sysctl-inotify-max-user-watches",
		description: "Verifies fs.inotify.max_user_watches is set (warns if < 524288 for high-density logging)",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			valStr, err := readSysctl(ctx, runner, "fs.inotify.max_user_watches")
			if err != nil {
				return err
			}
			val, err := strconv.ParseInt(valStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid fs.inotify.max_user_watches value %q: %w", valStr, err)
			}
			if val <= 0 {
				return fmt.Errorf("fs.inotify.max_user_watches must be positive, got %d", val)
			}
			recommendedWatches := int64(524288)
			if val < recommendedWatches {
				log.Printf("  WARNING: fs.inotify.max_user_watches is %d (recommended >= %d for high-density logging)", val, recommendedWatches)
			}
			return nil
		},
	})

	// 2. net.ipv4.ip_unprivileged_port_start <= 2021
	validation.Register(&sysctlCheck{
		name:        "sysctl-unprivileged-port-start",
		description: "Verifies net.ipv4.ip_unprivileged_port_start is <= 2021",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			valStr, err := readSysctl(ctx, runner, "net.ipv4.ip_unprivileged_port_start")
			if err != nil {
				return err
			}
			val, err := strconv.ParseInt(valStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid net.ipv4.ip_unprivileged_port_start value %q: %w", valStr, err)
			}
			maxAllowed := int64(2021)
			if val > maxAllowed {
				return fmt.Errorf("net.ipv4.ip_unprivileged_port_start is %d, expected <= %d", val, maxAllowed)
			}
			return nil
		},
	})

	// 4. Memory Cgroup Kernel Support (CONFIG_MEMCG=y)
	validation.Register(&sysctlCheck{
		name:        "kernel-config-memcg",
		description: "Verifies memory cgroup tracking is enabled in the kernel (CONFIG_MEMCG=y)",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			// Check /proc/cgroups first
			out, err := runner.CombinedOutput(ctx, "grep -E '^memory\\s' /proc/cgroups 2>/dev/null")
			if err == nil && len(strings.TrimSpace(string(out))) > 0 {
				return nil
			}
			// Check cgroup v2 controllers
			outV2, errV2 := runner.CombinedOutput(ctx, "grep -w 'memory' /sys/fs/cgroup/cgroup.controllers 2>/dev/null")
			if errV2 == nil && len(strings.TrimSpace(string(outV2))) > 0 {
				return nil
			}
			// Check kernel config files
			kconfCmd := "zgrep 'CONFIG_MEMCG=y' /proc/config.gz 2>/dev/null || grep 'CONFIG_MEMCG=y' /boot/config-$(uname -r) 2>/dev/null"
			outKconf, errKconf := runner.CombinedOutput(ctx, kconfCmd)
			if errKconf == nil && strings.Contains(string(outKconf), "CONFIG_MEMCG=y") {
				return nil
			}
			return fmt.Errorf("kernel memory cgroup support (CONFIG_MEMCG) is not enabled")
		},
	})
}
