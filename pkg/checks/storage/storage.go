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

package storage

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type PDCSICheck struct {
	Project        string
	ServiceAccount string
	Zone           string
	SourceImage    string
	MachineType    string
    MinCpuPlatform string
	Subnetwork     string
}

var _ validation.ConstrainedCheck = &PDCSICheck{}

func (_ *PDCSICheck) Name() string { return "storage/pdcsi" }

func (_ *PDCSICheck) Description() string {
	return `Runs the PD CSI E2E Qualification suite.

This will create and delete GCE VM instances, and attach and detach disks
to them. If the machine type supports local SSD, they will be qualified as
well.`
}

func (_ *PDCSICheck) Constraints() validation.Constraint {
	return validation.Constraint{
		NoTargetVMNecessary: true,
	}
}

func (_ *PDCSICheck) Tier() validation.Tier {
	return validation.Tier1
}

func (_ *PDCSICheck) Destructive() bool {
	return false
}

func (c *PDCSICheck) Validate() error {
	if c.Project == "" || c.ServiceAccount == "" {
		return fmt.Errorf("PD CSI qualification requires project and service account")
	}
	// The other parameters have defaults.
	return nil
}

func (c *PDCSICheck) Run(ctx context.Context, _ validation.SSHRunner) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("PD CSI check not intitialized correctly: %w", err)
	}
	cmd := exec.CommandContext(ctx, "bash", "./storage/run-gke-pd-qualification.sh")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PROJECT=%s", c.Project),
		fmt.Sprintf("IAM_NAME=%s", c.ServiceAccount),
	)
	if c.Zone != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("ZONE=%s", c.Zone))
	}
	if c.SourceImage != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("IMAGE_URL=%s", c.SourceImage))
	}
	if c.MachineType != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("MACHINE_TYPE=%s", c.MachineType))
	}
	if c.MinCpuPlatform != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("MIN_CPU_PLATFORM=%s", c.MinCpuPlatform))
	}
	if c.Subnetwork != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SUBNETWORK=%s", c.Subnetwork))
	}
	// Stream stdout/err so user sees real-time progress.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("PD CSI qualification failed: %w", err)
	}
	return nil
}
