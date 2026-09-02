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

package gkemetadataserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// mdsPathCheck implements validation.Check for MDS path requirements.
type mdsPathCheck struct {
	name        string
	description string
	runFunc     func(ctx context.Context, runner validation.SSHRunner) error
}

func (c *mdsPathCheck) Name() string          { return "gke-metadata-server/" + c.name }
func (c *mdsPathCheck) Description() string   { return c.description }
func (c *mdsPathCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *mdsPathCheck) Destructive() bool     { return false }
func (c *mdsPathCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	return c.runFunc(ctx, runner)
}

func init() {
	validation.Register(&mdsPathCheck{
		name:        "path-var-run",
		description: "Verifies /var/run/ exists and is Read-Write",
		runFunc:     verifyVarRun,
	})
	validation.Register(&mdsPathCheck{
		name:        "path-tpm-device",
		description: "Verifies /dev/tpm0 exists and has correct permissions if TPM is enabled",
		runFunc:     verifyTPMDevice,
	})
	validation.Register(&mdsPathCheck{
		name:        "path-efi-vars",
		description: "Verifies /sys/firmware/efi/efivars/ exists and is readable (if UEFI boot is used)",
		runFunc:     verifyEFIVars,
	})
}

func verifyVarRun(ctx context.Context, runner validation.SSHRunner) error {
	path := "/var/run"
	if err := runner.Run(ctx, fmt.Sprintf("sudo test -d %s", path)); err != nil {
		return fmt.Errorf("path %s does not exist: %w", path, err)
	}
	cmd := fmt.Sprintf("sudo findmnt -o OPTIONS -n -T %s", path)
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to check mount options for %s: %w", path, err)
	}
	opts := strings.Split(strings.TrimSpace(string(out)), ",")
	isRW := false
	for _, opt := range opts {
		if opt == "rw" {
			isRW = true
			break
		}
	}
	if !isRW {
		return fmt.Errorf("path %s must be Read-Write (rw), but mount options are: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

func verifyTPMDevice(ctx context.Context, runner validation.SSHRunner) error {
	// Only check if TPM is enabled on the instance (Shielded VM)
	if err := runner.Run(ctx, "test -d /sys/class/tpm/tpm0"); err != nil {
		// TPM not enabled/present on this instance, skip check
		return nil
	}

	path := "/dev/tpm0"
	if err := runner.Run(ctx, fmt.Sprintf("test -c %s", path)); err != nil {
		return fmt.Errorf("TPM device %s not found: %w", path, err)
	}

	// Verify permissions (owner must have rw)
	out, err := runner.CombinedOutput(ctx, fmt.Sprintf("stat -c '%%a' %s", path))
	if err != nil {
		return fmt.Errorf("failed to check permissions of %s: %w", path, err)
	}
	permsStr := strings.TrimSpace(string(out))
	perms, err := strconv.ParseUint(permsStr, 8, 32)
	if err != nil {
		return fmt.Errorf("failed to parse permissions %q: %w", permsStr, err)
	}
	if (perms & 0600) != 0600 {
		return fmt.Errorf("TPM device %s permissions %s are too restrictive, owner must have rw", path, permsStr)
	}
	return nil
}

func verifyEFIVars(ctx context.Context, runner validation.SSHRunner) error {
	// Check if UEFI boot is used
	if err := runner.Run(ctx, "test -d /sys/firmware/efi"); err != nil {
		// Not UEFI boot, skip check
		return nil
	}

	path := "/sys/firmware/efi/efivars/"
	if err := runner.Run(ctx, fmt.Sprintf("test -d %s", path)); err != nil {
		return fmt.Errorf("EFI vars directory %s does not exist: %w", path, err)
	}
	if err := runner.Run(ctx, fmt.Sprintf("test -r %s", path)); err != nil {
		return fmt.Errorf("EFI vars directory %s is not readable: %w", path, err)
	}

	// Verify filesystem type is efivarfs
	cmd := fmt.Sprintf("stat -f -c '%%T' %s", path)
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to check filesystem type for %s: %w", path, err)
	}
	fsType := strings.TrimSpace(string(out))
	if fsType != "efivarfs" {
		return fmt.Errorf("EFI vars directory %s must be mounted with efivarfs, got: %s", path, fsType)
	}
	return nil
}
