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
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// serviceCheck implements validation.Check for system services and init configuration.
type serviceCheck struct {
	name        string
	description string
	runFunc     func(ctx context.Context, runner validation.SSHRunner) error
}

func (c *serviceCheck) Name() string          { return "observability/" + c.name }
func (c *serviceCheck) Description() string   { return c.description }
func (c *serviceCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *serviceCheck) Destructive() bool     { return false }
func (c *serviceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	return c.runFunc(ctx, runner)
}

func init() {
	// 1. Systemd Journal Persistence
	validation.Register(&serviceCheck{
		name:        "service-systemd-journald",
		description: "Verifies systemd-journald service is active",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := runner.Run(ctx, "systemctl is-active systemd-journald"); err != nil {
				return fmt.Errorf("systemd-journald service is not active: %w", err)
			}
			return nil
		},
	})
	validation.Register(&serviceCheck{
		name:        "journald-persistent-storage",
		description: "Verifies systemd journal logs are persisted under /var/log/journal/",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := runner.Run(ctx, "test -d /var/log/journal/"); err != nil {
				return fmt.Errorf("/var/log/journal/ does not exist; journald must be configured with Storage=persistent: %w", err)
			}
			// Verify journal files exist inside /var/log/journal
			out, err := runner.CombinedOutput(ctx, "find /var/log/journal/ -maxdepth 2 -type f 2>/dev/null | head -n 1")
			if err != nil || len(strings.TrimSpace(string(out))) == 0 {
				return fmt.Errorf("no persistent journal log files found under /var/log/journal/")
			}
			return nil
		},
	})

	// 2. Time Synchronization
	validation.Register(&serviceCheck{
		name:        "service-time-synchronization",
		description: "Verifies an NTP time synchronization daemon is active",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			// Check common NTP services: systemd-timesyncd, chronyd, ntpd, or timedatectl
			ntpServices := []string{"systemd-timesyncd", "chrony", "chronyd", "ntp", "ntpd"}
			for _, svc := range ntpServices {
				if err := runner.Run(ctx, "systemctl is-active "+svc); err == nil {
					return nil
				}
			}
			// Fallback: check timedatectl
			out, err := runner.CombinedOutput(ctx, "timedatectl show -p NTPSynchronized 2>/dev/null")
			if err == nil && strings.Contains(string(out), "NTPSynchronized=yes") {
				return nil
			}
			return fmt.Errorf("no active NTP synchronization service found (checked systemd-timesyncd, chronyd, ntpd, and timedatectl)")
		},
	})
}
