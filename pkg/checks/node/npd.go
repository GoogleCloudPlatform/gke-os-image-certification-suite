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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type npdPathCheck struct {
	path string
}

func (c *npdPathCheck) Name() string { return "node/npd-path-readable-" + c.path }
func (c *npdPathCheck) Description() string {
	return fmt.Sprintf("Verifies that Node-Problem-Detector prerequisite path %s exists and is readable", c.path)
}
func (c *npdPathCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *npdPathCheck) Destructive() bool     { return false }

func (c *npdPathCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "test -r "+c.path); err != nil {
		return fmt.Errorf("path %s is not readable or does not exist: %w", c.path, err)
	}
	return nil
}

type npdServiceCheck struct {
	service string
}

func (c *npdServiceCheck) Name() string { return "node/npd-service-active-" + c.service }
func (c *npdServiceCheck) Description() string {
	return fmt.Sprintf("Verifies that Node-Problem-Detector prerequisite systemd service %s is active", c.service)
}
func (c *npdServiceCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *npdServiceCheck) Destructive() bool     { return false }

func (c *npdServiceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "systemctl is-active "+c.service); err != nil {
		return fmt.Errorf("service %s is not active: %w", c.service, err)
	}
	return nil
}

func init() {
	validation.Register(&npdPathCheck{path: "/dev/kmsg"})
	validation.Register(&npdPathCheck{path: "/var/log/journal"})
	validation.Register(&npdServiceCheck{service: "systemd-journald"})
}
