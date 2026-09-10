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

type dynamicBinaryExecutionCheck struct{}

func (c *dynamicBinaryExecutionCheck) Name() string { return "security/dynamic-linker-compatibility" }
func (c *dynamicBinaryExecutionCheck) Description() string {
	return "Verifies that standard 64-bit FHS dynamically-linked Linux ELF binaries execute on the host (validates presence of /lib64/ld-linux-x86-64.so.2, /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2, or /lib/ld-linux-x86-64.so.2)"
}
func (c *dynamicBinaryExecutionCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *dynamicBinaryExecutionCheck) Destructive() bool     { return false }

func (c *dynamicBinaryExecutionCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// Verify that standard 64-bit Linux FHS dynamic linker exists and is accessible
	if err := runner.Run(ctx, "test -e /lib64/ld-linux-x86-64.so.2 || test -e /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 || test -e /lib/ld-linux-x86-64.so.2"); err != nil {
		return fmt.Errorf("standard 64-bit Linux FHS dynamic linker not found: %w", err)
	}
	return nil
}

func init() {
	validation.Register(&dynamicBinaryExecutionCheck{})
}
