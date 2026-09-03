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

package security

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type pathTarget struct {
	path       string
	testCmd    string
	permString string
}

type agentLsmAccessCheck struct{}

func (c *agentLsmAccessCheck) Name() string { return "security/lsm-policy-access" }
func (c *agentLsmAccessCheck) Description() string {
	return "Verifies that Linux Security Modules (AppArmor or SELinux) do not block GKE node-agents from accessing critical host paths"
}
func (c *agentLsmAccessCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *agentLsmAccessCheck) Destructive() bool     { return false }

func (c *agentLsmAccessCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	targets := []pathTarget{
		{
			path:       "/home/kubernetes/bin",
			testCmd:    "if [ -d /home/kubernetes/bin ]; then test -w /home/kubernetes/bin; else sudo test -d /home && sudo test -w /home; fi",
			permString: "READ/WRITE",
		},
		{
			path:       "/var/lib/kubelet",
			testCmd:    "if [ -d /var/lib/kubelet ]; then test -r /var/lib/kubelet; else test -d /var/lib && test -r /var/lib; fi",
			permString: "READ",
		},
		{
			path:       "/var/run",
			testCmd:    "test -e /var/run && test -r /var/run",
			permString: "READ",
		},
	}

	var failedPaths []string
	for _, target := range targets {
		if err := runner.Run(ctx, target.testCmd); err != nil {
			failedPaths = append(failedPaths, fmt.Sprintf("%s (%s)", target.path, target.permString))
		}
	}

	if len(failedPaths) == 0 {
		return nil
	}

	// Access failed on required paths; collect LSM enforcement status and audit log denials
	lsmStatus := c.collectLsmStatus(ctx, runner)
	auditLogs := c.collectAuditDenials(ctx, runner)

	return fmt.Errorf("required GKE node agent host path access failed for %v\nLSM Status:\n%s\nAudit/Kernel Denials:\n%s",
		failedPaths, lsmStatus, auditLogs)
}

func (c *agentLsmAccessCheck) collectLsmStatus(ctx context.Context, runner validation.SSHRunner) string {
	var sb strings.Builder

	seOut, err := runner.CombinedOutput(ctx, "sestatus 2>/dev/null || true")
	if err == nil && len(bytes.TrimSpace(seOut)) > 0 {
		sb.WriteString(fmt.Sprintf("  SELinux: %s\n", strings.TrimSpace(string(seOut))))
	} else {
		sb.WriteString("  SELinux: disabled/inactive\n")
	}

	aaOut, err := runner.CombinedOutput(ctx, "aa-status --enabled 2>/dev/null && aa-status 2>/dev/null || true")
	if err == nil && len(bytes.TrimSpace(aaOut)) > 0 {
		sb.WriteString(fmt.Sprintf("  AppArmor: %s\n", strings.TrimSpace(string(aaOut))))
	} else {
		sb.WriteString("  AppArmor: disabled/inactive\n")
	}

	return sb.String()
}

func (c *agentLsmAccessCheck) collectAuditDenials(ctx context.Context, runner validation.SSHRunner) string {
	cmd := "dmesg 2>/dev/null | grep -iE 'apparmor|selinux|avc|denied' | tail -n 10 || grep -iE 'apparmor|selinux|avc|denied' /var/log/audit/audit.log 2>/dev/null | tail -n 10 || echo 'No LSM audit denial entries found in kernel logs.'"
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil || len(bytes.TrimSpace(out)) == 0 {
		return "  No LSM audit denial entries found."
	}
	return fmt.Sprintf("  %s", strings.TrimSpace(string(out)))
}

func init() {
	validation.Register(&agentLsmAccessCheck{})
}
