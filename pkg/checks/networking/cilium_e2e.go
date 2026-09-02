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
	_ "embed"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

const (
	kindClusterName  = "gke-os-cert-cilium"
	kindConfigFile   = "/tmp/kind-cilium-config.yaml"
	ciliumValuesFile = "/tmp/cilium-values.yaml"
	envPathPrefix    = `export PATH="$HOME/.local/bin:$PATH"; `
)

//go:embed manifests/kind-config.yaml
var kindConfigContent string

//go:embed manifests/cilium-values.yaml
var ciliumValuesContent string

// CiliumDatapathCheck verifies that the target OS kernel can bootstrap a local
// single-node cluster, run the Cilium eBPF dataplane agent, and pass core
// network datapath connectivity tests.
type CiliumDatapathCheck struct {
	CiliumVersion string
	constraints   validation.Constraint
}

// Until long-running checks are supported, we omit any test registration
func init() {}

func (c *CiliumDatapathCheck) Name() string {
	return "networking/cilium-dataplane-e2e"
}

func (c *CiliumDatapathCheck) Description() string {
	return "Bootstraps a local Kind cluster with Cilium CNI and verifies eBPF agent convergence and full network datapath connectivity"
}

func (c *CiliumDatapathCheck) Tier() validation.Tier              { return validation.Tier1 }
func (c *CiliumDatapathCheck) Destructive() bool                  { return true }
func (c *CiliumDatapathCheck) Constraints() validation.Constraint { return c.constraints }

func (c *CiliumDatapathCheck) RequiredTools() []tools.Type {
	return []tools.Type{
		tools.Docker,
		tools.Kind,
		tools.Kubectl,
		tools.Cilium,
	}
}

func (c *CiliumDatapathCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	fmt.Println("    Tearing down local Kind cluster and cleaning temporary files...")
	_, _ = runner.CombinedOutput(ctx, envPathPrefix+"kind delete cluster --name "+kindClusterName)
	_ = runner.Run(ctx, fmt.Sprintf("rm -f %s %s", kindConfigFile, ciliumValuesFile))
	return nil
}

func (c *CiliumDatapathCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// Ensure stateful mounts are executable (needed for hardened OS environments like COS)
	_ = runner.Run(ctx, "sudo mount -o remount,exec /mnt/disks/stateful_partition 2>/dev/null || sudo mount -o remount,exec /home 2>/dev/null || true")

	// Write Kind configuration
	writeKindConfigCmd := fmt.Sprintf("cat << 'EOF' > %s\n%s\nEOF", kindConfigFile, strings.TrimSpace(kindConfigContent))
	if err := runner.Run(ctx, writeKindConfigCmd); err != nil {
		return fmt.Errorf("failed to write Kind configuration: %w", err)
	}

	// Write Cilium ConfigMap values
	writeCiliumValuesCmd := fmt.Sprintf("cat << 'EOF' > %s\n%s\nEOF", ciliumValuesFile, strings.TrimSpace(ciliumValuesContent))
	if err := runner.Run(ctx, writeCiliumValuesCmd); err != nil {
		return fmt.Errorf("failed to write Cilium values: %w", err)
	}

	// Create Kind cluster
	fmt.Println("    [1/4] Creating Kind cluster 'gke-os-cert-cilium'...")
	createClusterCmd := fmt.Sprintf("%skind create cluster --name %s --config %s --wait 0s", envPathPrefix, kindClusterName, kindConfigFile)
	if out, err := runner.CombinedOutput(ctx, createClusterCmd); err != nil {
		return fmt.Errorf("failed to create Kind cluster: %w\nOutput:\n%s", err, string(out))
	}

	// Deploy Cilium agent
	fmt.Printf("    [2/4] Deploying Cilium agent v%s with values manifest...\n", c.CiliumVersion)
	installCiliumCmd := fmt.Sprintf("%scilium install --version %s --values %s --wait=false", envPathPrefix, c.CiliumVersion, ciliumValuesFile)
	if out, err := runner.CombinedOutput(ctx, installCiliumCmd); err != nil {
		return fmt.Errorf("failed to install Cilium: %w\nOutput:\n%s", err, string(out))
	}

	// Wait for healthy status
	fmt.Println("    [3/4] Waiting for Cilium agent readiness...")
	statusCmd := envPathPrefix + "cilium status --wait --wait-duration 3m"
	if out, err := runner.CombinedOutput(ctx, statusCmd); err != nil {
		return fmt.Errorf("cilium failed to reach healthy status: %w\nOutput:\n%s", err, string(out))
	}

	// Run Connectivity tests
	fmt.Println("    [4/4] Executing Cilium connectivity test suite (20m timeout)...")
	testCmd := envPathPrefix + "cilium connectivity test --test '!pod-to-world' --timeout 20m"
	if out, err := runner.CombinedOutput(ctx, testCmd); err != nil {
		return fmt.Errorf("cilium connectivity test suite failed: %w\nOutput:\n%s", err, string(out))
	}

	fmt.Println("    Cilium OSS connectivity suite passed successfully")
	return nil
}
