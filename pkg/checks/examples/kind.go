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

type KindClusterCheck struct{}

// func init() {
// 	// Docker and Kind are not required for core GKE certification anymore (replaced by containerd).
// 	// This is kept as an optional example, so registration is disabled by default.
// 	validation.Register(&KindClusterCheck{})
// }

const kindClusterName = "cert-validation"

func (c *KindClusterCheck) Name() string { return "examples/kind-cluster-up" }
func (c *KindClusterCheck) Description() string {
	return "Verifies that a Kind cluster can be created and accessed"
}
func (c *KindClusterCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *KindClusterCheck) Destructive() bool     { return true }
func (c *KindClusterCheck) RequiredTools() []tools.Type {
	return []tools.Type{
		tools.Docker,
		tools.Kind,
		tools.Kubectl,
	}
}

func (c *KindClusterCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Create Kind cluster
	out, err := runner.CombinedOutput(ctx, "kind create cluster --name "+kindClusterName)
	if err != nil {
		return fmt.Errorf("kind create cluster failed: %w (output: %s)", err, string(out))
	}

	// 2. Verify cluster access
	out, err = runner.CombinedOutput(ctx, "kubectl cluster-info")
	if err != nil {
		return fmt.Errorf("kubectl cluster-info failed: %w (output: %s)", err, string(out))
	}

	if !strings.Contains(string(out), "Kubernetes control plane is running") {
		return fmt.Errorf("kubectl output did not contain expected message: %s", string(out))
	}

	// 3. List nodes
	out, err = runner.CombinedOutput(ctx, "kubectl get nodes")
	if err != nil {
		return fmt.Errorf("kubectl get nodes failed: %w (output: %s)", err, string(out))
	}

	return nil
}

func (c *KindClusterCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	_, err := runner.CombinedOutput(ctx, "kind delete cluster --name "+kindClusterName)
	return err
}
