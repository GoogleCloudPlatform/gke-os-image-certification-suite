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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// PortConflictSpec defines the host port spec required by GKE
// Networking / Dataplane V2 components on worker nodes.
type PortConflictSpec struct {
	Port        int
	Component   string
	Description string
}

// RegisteredPortConflicts defines the list of host TCP ports reserved
// strictly by GKE Networking worker node daemons (Cilium/anetd, Hubble, netd,
// NodeLocal DNSCache, and networking-dra-driver) that must not be occupied
// by pre-existing host processes on custom OS images.
var RegisteredPortConflicts = []PortConflictSpec{
	// 1. Dataplane V2 & Hubble Agent (anetd)
	{
		Port:        4244,
		Component:   "hubble",
		Description: "Hubble server gRPC flow observer service",
	},
	{
		Port:        9879,
		Component:   "cilium",
		Description: "Cilium agent health & Prometheus metrics server (agent-health-port)",
	},
	{
		Port:        9965,
		Component:   "dpv2",
		Description: "Dataplane V2 anetd telemetry & Hubble metrics hostPort",
	},
	{
		Port:        9890,
		Component:   "dpv2",
		Description: "DPv2 anetd gops diagnostic profiling endpoint",
	},
	{
		Port:        9990,
		Component:   "cilium",
		Description: "Cilium Envoy admin & local proxy healthz endpoint",
	},
	{
		Port:        10256,
		Component:   "dpv2",
		Description: "Dataplane V2 eBPF kube-proxy replacement healthz server",
	},

	// 2. GKE Host Networking Daemon (netd)
	{
		Port:        10231,
		Component:   "netd",
		Description: "GKE host networking daemon (netd) metrics endpoint",
	},

	// 3. Dynamic Resource Allocation Driver (networking-dra-driver / dranet)
	{
		Port:        19950,
		Component:   "dranet",
		Description: "Dynamic Resource Allocation networking driver (dranet) health & metrics endpoint",
	},

	// 4. NodeLocal DNSCache
	{
		Port:        9253,
		Component:   "nodelocaldns",
		Description: "NodeLocal DNSCache CoreDNS Prometheus metrics endpoint",
	},
	{
		Port:        9353,
		Component:   "nodelocaldns",
		Description: "NodeLocal DNSCache healthz probe endpoint",
	},
}

// portCollisionCheck verifies that a specific reserved host port is not already bound
// by a host OS daemon before GKE networking components start up.
type portCollisionCheck struct {
	spec PortConflictSpec
}

func (c *portCollisionCheck) Name() string {
	return fmt.Sprintf("networking/port-collision-%d", c.spec.Port)
}

func (c *portCollisionCheck) Description() string {
	return fmt.Sprintf("Verifies that host TCP port %d (%s: %s) is free and not bound by pre-existing host processes",
		c.spec.Port, c.spec.Component, c.spec.Description)
}

func (c *portCollisionCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *portCollisionCheck) Destructive() bool     { return false }

func (c *portCollisionCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	cmd := fmt.Sprintf("ss -tlnH 'sport = :%d' 2>/dev/null || ss -tln 2>/dev/null | grep -E '[: ]%d\\b' || netstat -tlpn 2>/dev/null | grep -E '[: ]%d\\b'",
		c.spec.Port, c.spec.Port, c.spec.Port)

	out, err := runner.CombinedOutput(ctx, cmd)
	trimmed := strings.TrimSpace(string(out))
	if err == nil && len(trimmed) > 0 {
		return fmt.Errorf("host TCP port %d is already in use by a pre-existing host process (%s requirement: %s):\n%s",
			c.spec.Port, c.spec.Component, c.spec.Description, trimmed)
	}

	return nil
}

func init() {
	for _, spec := range RegisteredPortConflicts {
		validation.Register(&portCollisionCheck{
			spec: spec,
		})
	}
}
