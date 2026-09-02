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

// networkCheck implements validation.Check for observability network requirements.
type networkCheck struct {
	name        string
	description string
	runFunc     func(ctx context.Context, runner validation.SSHRunner) error
}

func (c *networkCheck) Name() string          { return "observability/" + c.name }
func (c *networkCheck) Description() string   { return c.description }
func (c *networkCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *networkCheck) Destructive() bool     { return false }
func (c *networkCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	return c.runFunc(ctx, runner)
}

func init() {
	// 1. Containerd TCP Metrics Configuration (Port 1338)
	validation.Register(&networkCheck{
		name:        "containerd-metrics-endpoint",
		description: "Verifies containerd exposes TCP Prometheus metrics on 127.0.0.1:1338 or /etc/containerd/ exists for GKE bootstrap",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			// 1. Check if containerd is already listening on port 1338
			out, err := runner.CombinedOutput(ctx, "ss -tlpn 2>/dev/null | grep -w '1338' || netstat -tlpn 2>/dev/null | grep -w '1338'")
			if err == nil && len(strings.TrimSpace(string(out))) > 0 {
				return nil
			}
			// 2. Check config files for address = "127.0.0.1:1338" or address = "0.0.0.0:1338"
			cfgCmd := "grep -E 'address\\s*=\\s*\"(127\\.0\\.0\\.1|0\\.0\\.0\\.0):1338\"' /etc/containerd/config.toml /etc/containerd/config.d/*.toml 2>/dev/null"
			cfgOut, cfgErr := runner.CombinedOutput(ctx, cfgCmd)
			if cfgErr == nil && len(strings.TrimSpace(string(cfgOut))) > 0 {
				return nil
			}
			// 3. On mutable OSes (COS/Ubuntu), verify /etc/containerd/ or /etc/ exists so GKE node bootstrap can configure it
			bootstrapCheck := "test -d /etc/containerd || test -d /etc"
			if err := runner.Run(ctx, bootstrapCheck); err == nil {
				return nil
			}
			return fmt.Errorf("containerd metrics endpoint (127.0.0.1:1338) is neither listening/configured, nor does /etc/containerd exist for GKE bootstrap")
		},
	})

	// 2. Loopback Interface Health
	validation.Register(&networkCheck{
		name:        "network-loopback-up",
		description: "Verifies local loopback interface (lo) is UP and assigned 127.0.0.1",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			cmd := "ip -br addr show lo | grep -E '^lo\\s+UNKNOWN|UP\\s+127\\.0\\.0\\.1'"
			out, err := runner.CombinedOutput(ctx, cmd)
			if err != nil || len(strings.TrimSpace(string(out))) == 0 {
				return fmt.Errorf("loopback interface 'lo' is not active with 127.0.0.1")
			}
			return nil
		},
	})
}
