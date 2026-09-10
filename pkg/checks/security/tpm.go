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

package security

import (
	"bytes"
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type tpmDeviceCheck struct{}

func (c *tpmDeviceCheck) Name() string { return "security/tpm-device-availability" }
func (c *tpmDeviceCheck) Description() string {
	return "Verifies that the guest OS exposes TPM 2.0 driver (/sys/class/tpm/tpm0) and character device (/dev/tpm0 or /dev/tpmrm0) with valid permissions"
}
func (c *tpmDeviceCheck) Tier() validation.Tier { return validation.Tier0 }
func (c *tpmDeviceCheck) Destructive() bool     { return false }

func (c *tpmDeviceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Verify TPM driver in sysfs
	if err := runner.Run(ctx, "ls /sys/class/tpm/tpm0"); err != nil {
		return fmt.Errorf("TPM 2.0 driver not found at /sys/class/tpm/tpm0: %w", err)
	}

	// 2. Verify device files exist (/dev/tpm0 or /dev/tpmrm0)
	errTpm0 := runner.Run(ctx, "test -c /dev/tpm0")
	errTpmrm0 := runner.Run(ctx, "test -c /dev/tpmrm0")
	if errTpm0 != nil && errTpmrm0 != nil {
		return fmt.Errorf("neither /dev/tpm0 nor /dev/tpmrm0 character device exists on host")
	}

	// 3. Verify permissions on existing device file(s)
	if errTpm0 == nil {
		if err := verifyTpmPermissions(ctx, runner, "/dev/tpm0"); err != nil {
			return err
		}
	}
	if errTpmrm0 == nil {
		if err := verifyTpmPermissions(ctx, runner, "/dev/tpmrm0"); err != nil {
			return err
		}
	}

	return nil
}

func verifyTpmPermissions(ctx context.Context, runner validation.SSHRunner, path string) error {
	out, err := runner.CombinedOutput(ctx, "stat -c '%A' "+path)
	if err != nil {
		return fmt.Errorf("failed to stat permissions for %s: %w", path, err)
	}
	actual := string(bytes.TrimSpace(out))
	if actual != "crw-------" && actual != "crw-rw----" {
		return fmt.Errorf("unexpected permissions for %s: got %s, expected crw------- or crw-rw----", path, actual)
	}
	return nil
}

func init() {
	validation.Register(&tpmDeviceCheck{})
}
