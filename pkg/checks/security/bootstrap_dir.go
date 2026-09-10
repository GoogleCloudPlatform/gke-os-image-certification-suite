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
	return "Verifies non-destructively that the GKE bootstrap directory (/home/kubernetes/bin) or its nearest parent directory exists, is writable, and resides on a read-write mount"
}
func (c *bootstrapDirectoryCheck) Tier() validation.Tier { return validation.Tier0 }
func (c *bootstrapDirectoryCheck) Destructive() bool     { return false }

func (c *bootstrapDirectoryCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	cmd := `p="/home/kubernetes/bin"; while [ ! -d "$p" ] && [ "$p" != "/" ]; do p=$(dirname "$p"); done; test -d "$p" && (test -w "$p" || sudo test -w "$p") && ! findmnt -no OPTIONS -T "$p" | grep -qw "ro"`
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("failed to verify that /home/kubernetes/bin or its nearest parent directory is writable on a read-write mount: %w", err)
	}
	return nil
}

func init() {
	validation.Register(&bootstrapDirectoryCheck{})
}
