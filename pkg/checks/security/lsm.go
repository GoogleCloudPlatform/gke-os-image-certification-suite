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

// lsmPathAccessCheck validates that Linux Security Modules permit GKE node-agents
// access to a specific required host path.
type lsmPathAccessCheck struct {
	path       string
	permString string
	testCmd    string
}

func (c *lsmPathAccessCheck) Name() string {
	return "security/lsm-access-" + c.path
}

func (c *lsmPathAccessCheck) Description() string {
	return fmt.Sprintf("Verifies that Linux Security Modules (AppArmor or SELinux) permit GKE node-agents %s access to %s", c.permString, c.path)
}

func (c *lsmPathAccessCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *lsmPathAccessCheck) Destructive() bool     { return false }

func (c *lsmPathAccessCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, c.testCmd); err != nil {
		lsmStatus := collectLsmStatus(ctx, runner)
		auditLogs := collectAuditDenials(ctx, runner)
		return fmt.Errorf("required GKE node agent host path access failed for %s (%s): %w\nLSM Status:\n%s\nAudit/Kernel Denials:\n%s",
			c.path, c.permString, err, lsmStatus, auditLogs)
	}
	return nil
}

func collectLsmStatus(ctx context.Context, runner validation.SSHRunner) string {
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

func collectAuditDenials(ctx context.Context, runner validation.SSHRunner) string {
	cmd := "dmesg 2>/dev/null | grep -iE 'apparmor|selinux|avc|denied' | tail -n 10 || grep -iE 'apparmor|selinux|avc|denied' /var/log/audit/audit.log 2>/dev/null | tail -n 10 || echo 'No LSM audit denial entries found in kernel logs.'"
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil || len(bytes.TrimSpace(out)) == 0 {
		return "  No LSM audit denial entries found."
	}
	return fmt.Sprintf("  %s", strings.TrimSpace(string(out)))
}

// RegisteredLsmPathAccess lists required host directory and symlink permission requirements for LSM evaluation.
var RegisteredLsmPathAccess = []*lsmPathAccessCheck{
	{
		path:       "/home/kubernetes/bin",
		permString: "READ/WRITE",
		testCmd:    "if [ -d /home/kubernetes/bin ]; then test -w /home/kubernetes/bin; else sudo test -d /home && sudo test -w /home; fi",
	},
	{
		path:       "/var/lib/kubelet",
		permString: "READ",
		testCmd:    "if [ -d /var/lib/kubelet ]; then test -r /var/lib/kubelet; else test -d /var/lib && test -r /var/lib; fi",
	},
	{
		path:       "/var/run",
		permString: "READ",
		testCmd:    "test -e /var/run && test -r /var/run",
	},
}

func init() {
	for _, check := range RegisteredLsmPathAccess {
		validation.Register(check)
	}
}
