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

type kernelModuleCheck struct {
	moduleName  string
	shouldExist bool
	constraints validation.Constraint
}

func (c *kernelModuleCheck) Constraints() validation.Constraint {
	return c.constraints
}

func (c *kernelModuleCheck) Name() string {
	if c.shouldExist {
		return "node/kernel-module-" + c.moduleName
	}
	return "node/kernel-module-absent-" + c.moduleName
}

func (c *kernelModuleCheck) Description() string {
	if c.shouldExist {
		return fmt.Sprintf("Verifies that kernel module %s is available", c.moduleName)
	}
	return fmt.Sprintf("Verifies that kernel module %s is NOT available", c.moduleName)
}

func (c *kernelModuleCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *kernelModuleCheck) Destructive() bool     { return false }

func (c *kernelModuleCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	err := runner.Run(ctx, "modinfo "+c.moduleName)
	if c.shouldExist {
		if err != nil {
			return fmt.Errorf("kernel module %s is not available: %w", c.moduleName, err)
		}
	} else {
		if err == nil {
			return fmt.Errorf("kernel module %s is available but should NOT be", c.moduleName)
		}
	}
	return nil
}

func init() {
	modules := []string{
		"ip_vs", "ip_vs_rr", "ip_vs_wrr", "ip_vs_sh",
		"nf_conntrack",
	}

	for _, m := range modules {
		validation.Register(&kernelModuleCheck{moduleName: m, shouldExist: true})
	}

	// bfq I/O scheduler kernel module is supported starting from GKE v1.32
	validation.Register(&kernelModuleCheck{
		moduleName:  "bfq",
		shouldExist: true,
		constraints: validation.Constraint{
			MinGKEVersion: "1.32.0",
		},
	})

	validation.Register(&kernelModuleCheck{moduleName: "aufs", shouldExist: false})
}
