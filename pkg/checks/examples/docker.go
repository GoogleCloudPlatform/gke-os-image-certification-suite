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

package examples

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type DockerExistsCheck struct{}

// func init() {
// 	// Docker is not required for core GKE certification anymore (replaced by containerd).
// 	// This is kept as an optional example, so registration is disabled by default.
// 	validation.Register(&DockerExistsCheck{})
// }

func (c *DockerExistsCheck) Name() string { return "examples/docker-exists" }
func (c *DockerExistsCheck) Description() string {
	return "Verifies that Docker is installed and service exists"
}
func (c *DockerExistsCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *DockerExistsCheck) Destructive() bool     { return false }
func (c *DockerExistsCheck) RequiredTools() []tools.Type {
	return []tools.Type{tools.Docker}
}

func (c *DockerExistsCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "which docker"); err != nil {
		return fmt.Errorf("docker binary not found in PATH: %w", err)
	}

	if err := runner.Run(ctx, "test -x /usr/bin/docker"); err != nil {
		return fmt.Errorf("docker is not installed or not executable at /usr/bin/docker: %w", err)
	}

	if err := runner.Run(ctx, "systemctl cat docker.service"); err != nil {
		return fmt.Errorf("docker.service not found: %w", err)
	}

	return nil
}
