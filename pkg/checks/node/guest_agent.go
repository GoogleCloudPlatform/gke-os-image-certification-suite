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

package node

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type guestAgentServiceCheck struct {
	service      string
	expectActive bool // If true, assert ActiveState=active, otherwise only assert LoadState=loaded
}

func (c *guestAgentServiceCheck) Name() string {
	return "node/guest-agent-service-" + strings.TrimSuffix(c.service, ".service")
}

func (c *guestAgentServiceCheck) Description() string {
	if c.expectActive {
		return fmt.Sprintf("Verifies that the Google Guest Agent service %s is loaded and active", c.service)
	}
	return fmt.Sprintf("Verifies that the Google Guest Agent service %s is loaded on the guest OS", c.service)
}

func (c *guestAgentServiceCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *guestAgentServiceCheck) Destructive() bool     { return false }

func (c *guestAgentServiceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// Check LoadState
	out, err := runner.CombinedOutput(ctx, "systemctl show --property=LoadState "+c.service)
	if err != nil {
		return fmt.Errorf("failed to query load state of service %s: %w", c.service, err)
	}
	if !strings.Contains(string(out), "LoadState=loaded") {
		return fmt.Errorf("service %s is not loaded on the guest OS: %s", c.service, strings.TrimSpace(string(out)))
	}

	// Check ActiveState if expected active
	if c.expectActive {
		out, err = runner.CombinedOutput(ctx, "systemctl show --property=ActiveState "+c.service)
		if err != nil {
			return fmt.Errorf("failed to query active state of service %s: %w", c.service, err)
		}
		if !strings.Contains(string(out), "ActiveState=active") {
			return fmt.Errorf("service %s is loaded but not active: %s", c.service, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

func init() {
	// Universal Core Guest Services (Present on all images)
	validation.Register(&guestAgentServiceCheck{
		service:      "google-guest-agent.service",
		expectActive: true,
	})
	validation.Register(&guestAgentServiceCheck{
		service:      "google-startup-scripts.service",
		expectActive: false, // One-shot
	})
	validation.Register(&guestAgentServiceCheck{
		service:      "google-shutdown-scripts.service",
		expectActive: false, // Executes on shutdown
	})
}
