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

package checklib

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// PathExistenceCheck validates the existence of paths (supporting both static paths and wildcards).
type PathExistenceCheck struct {
	Component string
	Pattern   string
	CheckName string
}

func (c *PathExistenceCheck) Name() string {
	return fmt.Sprintf("%s/exists-%s", c.Component, c.CheckName)
}

func (c *PathExistenceCheck) Description() string {
	return "Verifies that path(s) matching " + c.Pattern + " exist"
}

func (c *PathExistenceCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *PathExistenceCheck) Destructive() bool     { return false }

func (c *PathExistenceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "ls "+c.Pattern); err != nil {
		return fmt.Errorf("no paths matching pattern %s found: %w", c.Pattern, err)
	}
	return nil
}
