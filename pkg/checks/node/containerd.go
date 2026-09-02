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

type ContainerdExistsCheck struct{}

func init() {
	validation.Register(&ContainerdExistsCheck{})
}

func (c *ContainerdExistsCheck) Name() string { return "node/containerd-exists" }
func (c *ContainerdExistsCheck) Description() string {
	return "Verifies that the containerd binary exists"
}
func (c *ContainerdExistsCheck) Tier() validation.Tier { return validation.Tier0 }
func (c *ContainerdExistsCheck) Destructive() bool     { return false }

func (c *ContainerdExistsCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "which containerd"); err != nil {
		return fmt.Errorf("containerd binary not found in PATH: %w", err)
	}

	if err := runner.Run(ctx, "test -x /usr/bin/containerd"); err != nil {
		return fmt.Errorf("containerd is not installed or not executable at /usr/bin/containerd: %w", err)
	}

	if err := runner.Run(ctx, "systemctl is-active containerd"); err != nil {
		return fmt.Errorf("containerd service is not active: %w", err)
	}

	return nil
}
