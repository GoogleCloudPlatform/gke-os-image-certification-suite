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
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

var glibcVersionRegex = regexp.MustCompile(`(\d+)\.(\d+)`)

type glibcCheck struct{}

func init() {
	validation.Register(&glibcCheck{})
}

func (c *glibcCheck) Name() string          { return "node/glibc-version" }
func (c *glibcCheck) Description() string   { return "Verifies that the system glibc version is >= 2.35" }
func (c *glibcCheck) Tier() validation.Tier { return validation.Tier0 }
func (c *glibcCheck) Destructive() bool     { return false }

func (c *glibcCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	cmd := "ldd --version 2>/dev/null || /lib64/libc.so.6 2>/dev/null || /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || /lib/libc.so.6 2>/dev/null"
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to execute glibc query: %w", err)
	}

	outputStr := string(bytes.TrimSpace(out))
	matches := glibcVersionRegex.FindStringSubmatch(outputStr)
	if len(matches) < 3 {
		return fmt.Errorf("glibc version not found in output: %q", outputStr)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return fmt.Errorf("invalid glibc major version %q: %w", matches[1], err)
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return fmt.Errorf("invalid glibc minor version %q: %w", matches[2], err)
	}

	if major < 2 || (major == 2 && minor < 35) {
		return fmt.Errorf("glibc version %d.%d is older than required minimum 2.35", major, minor)
	}

	return nil
}
