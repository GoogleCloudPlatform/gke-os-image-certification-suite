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
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type bootstrapDirectoryCheck struct{}

func (c *bootstrapDirectoryCheck) Name() string { return "security/bootstrap-directory-writable" }
func (c *bootstrapDirectoryCheck) Description() string {
	return "Verifies that the GKE bootstrap directory (/home/kubernetes/bin) can be created and is writable by the bootstrap script"
}
func (c *bootstrapDirectoryCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *bootstrapDirectoryCheck) Destructive() bool     { return true }

func (c *bootstrapDirectoryCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Ensure directory exists or can be created (using sudo)
	if err := runner.Run(ctx, "sudo mkdir -p /home/kubernetes/bin"); err != nil {
		return fmt.Errorf("failed to create /home/kubernetes/bin directory: %w", err)
	}

	// 2. Attempt to write a test file to check write permissions and clean up
	testFile := "/home/kubernetes/bin/.gke_security_write_test"
	if err := runner.Run(ctx, fmt.Sprintf("sudo touch %s && sudo rm -f %s", testFile, testFile)); err != nil {
		return fmt.Errorf("directory /home/kubernetes/bin is not writable: %w", err)
	}

	return nil
}

func (c *bootstrapDirectoryCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	testFile := "/home/kubernetes/bin/.gke_security_write_test"
	return runner.Run(ctx, fmt.Sprintf("sudo rm -f %s", testFile))
}

func init() {
	validation.Register(&bootstrapDirectoryCheck{})
}
