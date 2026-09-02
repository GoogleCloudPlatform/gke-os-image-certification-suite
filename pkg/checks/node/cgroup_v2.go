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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type cgroupV2Check struct{}

func init() {
	validation.Register(&cgroupV2Check{})
}

func (c *cgroupV2Check) Name() string          { return "node/cgroup-v2" }
func (c *cgroupV2Check) Description() string   { return "Verifies that the system is running cgroup v2" }
func (c *cgroupV2Check) Tier() validation.Tier { return validation.Tier0 }
func (c *cgroupV2Check) Destructive() bool     { return false }

func (c *cgroupV2Check) Run(ctx context.Context, runner validation.SSHRunner) error {
	out, err := runner.CombinedOutput(ctx, "stat -fc %T /sys/fs/cgroup/")
	if err != nil {
		return fmt.Errorf("failed to check cgroup filesystem type: %w", err)
	}
	actual := string(bytes.TrimSpace(out))
	if actual != "cgroup2fs" {
		return fmt.Errorf("expected cgroup filesystem type to be 'cgroup2fs', got %q", actual)
	}
	return nil
}
