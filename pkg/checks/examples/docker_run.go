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
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type DockerRunCheck struct{}

// func init() {
// 	// Docker is not required for core GKE certification anymore (replaced by containerd).
// 	// This is kept as an optional example, so registration is disabled by default.
// 	validation.Register(&DockerRunCheck{})
// }

const dockerHelloWorldImage = "hello-world"

func (c *DockerRunCheck) Name() string { return "examples/docker-run-hello" }
func (c *DockerRunCheck) Description() string {
	return "Verifies that Docker can run a hello-world container"
}
func (c *DockerRunCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *DockerRunCheck) Destructive() bool     { return true }
func (c *DockerRunCheck) RequiredTools() []tools.Type {
	return []tools.Type{tools.Docker}
}

func (c *DockerRunCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	output, err := runner.CombinedOutput(ctx, fmt.Sprintf("docker run --rm %s", dockerHelloWorldImage))
	if err != nil {
		return fmt.Errorf("docker run failed: %w (output: %s)", err, string(output))
	}

	if !strings.Contains(string(output), "Hello from Docker!") {
		return fmt.Errorf("docker run output did not contain expected message: %s", string(output))
	}

	return nil
}

func (c *DockerRunCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	_, err := runner.CombinedOutput(ctx, fmt.Sprintf("docker rmi -f %s", dockerHelloWorldImage))
	return err
}
