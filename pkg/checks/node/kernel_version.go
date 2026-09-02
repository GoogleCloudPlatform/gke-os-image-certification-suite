// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses///LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type kernelVersionCheck struct{}

func init() {
	validation.Register(&kernelVersionCheck{})
}

func (c *kernelVersionCheck) Name() string          { return "node/kernel-version" }
func (c *kernelVersionCheck) Description() string   { return "Verifies that the Linux kernel version is at least 6.8.0" }
func (c *kernelVersionCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *kernelVersionCheck) Destructive() bool     { return false }

func (c *kernelVersionCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	out, err := runner.CombinedOutput(ctx, "uname -r")
	if err != nil {
		return fmt.Errorf("failed to check kernel version: %w", err)
	}
	actualStr := string(bytes.TrimSpace(out))
	actualStr = strings.TrimSuffix(actualStr, "+")
	actualVer, err := utils.ParseSemVer(actualStr)
	if err != nil {
		return fmt.Errorf("failed to parse kernel version %q: %w", actualStr, err)
	}

	minMajor := 6
	minMinor := 8

	if actualVer.Major < minMajor || (actualVer.Major == minMajor && actualVer.Minor < minMinor) {
		return fmt.Errorf("expected Linux kernel version to be at least 6.8.0, but got %s", actualVer)
	}

	return nil
}
