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

package networking

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// virtualMountCheck verifies virtual filesystem mount type and write access.
type virtualMountCheck struct {
	path          string
	expectedTypes []string // e.g. []string{"bpf", "bpf_fs"}
	description   string
}

func (c *virtualMountCheck) Name() string {
	return "networking/mount-" + c.path
}

func (c *virtualMountCheck) Description() string {
	typesStr := strings.Join(c.expectedTypes, "/")
	if c.description != "" {
		return fmt.Sprintf("Verifies that %s is mounted as filesystem type %s (%s)", c.path, typesStr, c.description)
	}
	return fmt.Sprintf("Verifies that %s is mounted as filesystem type %s", c.path, typesStr)
}

func (c *virtualMountCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *virtualMountCheck) Destructive() bool     { return false }

func (c *virtualMountCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Verify directory exists
	if err := runner.Run(ctx, "test -d "+c.path); err != nil {
		return fmt.Errorf("virtual mount directory %s does not exist: %w", c.path, err)
	}

	// 2. Verify VFS superblock filesystem type via stat -fc %T
	out, err := runner.CombinedOutput(ctx, "stat -fc %T "+c.path)
	if err != nil {
		return fmt.Errorf("failed to check filesystem type for %s: %w", c.path, err)
	}
	actual := string(bytes.TrimSpace(out))

	valid := false
	for _, expected := range c.expectedTypes {
		if actual == expected {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("path %s is mounted as type %q, expected one of %v", c.path, actual, c.expectedTypes)
	}

	// 3. Verify writeability (tries sudo if unprivileged SSH user)
	if err := runner.Run(ctx, "test -w "+c.path+" || sudo test -w "+c.path); err != nil {
		return fmt.Errorf("virtual mount directory %s is not writable: %w", c.path, err)
	}

	return nil
}

// pathPermissionCheck validates exact permissions of a path, and optionally its symlink target.
type pathPermissionCheck struct {
	path              string
	permissions       string
	targetPermissions string // Optional. If set, path must be a symlink matching 'permissions', and its target must match 'targetPermissions'.
}

func (c *pathPermissionCheck) Name() string {
	return "networking/permission-" + c.path
}

func (c *pathPermissionCheck) Description() string {
	if c.targetPermissions != "" {
		return fmt.Sprintf("Verifies that symlink %s has permissions %s and its target has permissions %s", c.path, c.permissions, c.targetPermissions)
	}
	return fmt.Sprintf("Verifies that %s has permissions %s", c.path, c.permissions)
}

func (c *pathPermissionCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *pathPermissionCheck) Destructive() bool     { return false }

func (c *pathPermissionCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Verify the path itself (without following symlinks)
	out, err := runner.CombinedOutput(ctx, "stat -c '%A' "+c.path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", c.path, err)
	}
	actual := string(bytes.TrimSpace(out))
	if actual != c.permissions {
		return fmt.Errorf("path %s has permissions %s, expected %s", c.path, actual, c.permissions)
	}

	// 2. If this is a symlink, verify that the target exists and has correct permissions
	if c.targetPermissions != "" {
		targetOut, err := runner.CombinedOutput(ctx, "stat -L -c '%A' "+c.path)
		if err != nil {
			return fmt.Errorf("failed to stat symlink target for %s (broken link?): %w", c.path, err)
		}
		actualTarget := string(bytes.TrimSpace(targetOut))
		if actualTarget != c.targetPermissions {
			return fmt.Errorf("symlink target of %s has permissions %s, expected %s", c.path, actualTarget, c.targetPermissions)
		}
	}

	return nil
}

// RegisteredVirtualMounts lists virtual filesystem mount requirements.
var RegisteredVirtualMounts = []*virtualMountCheck{
	{
		path:          "/sys/fs/bpf",
		expectedTypes: []string{"bpf", "bpf_fs"},
		description:   "eBPF filesystem (bpffs) pinning directory",
	},
	{
		path:          "/sys/fs/cgroup",
		expectedTypes: []string{"cgroup2", "cgroup2fs"},
		description:   "Cgroup v2 unified hierarchy mount",
	},
	{
		path:          "/proc",
		expectedTypes: []string{"proc", "procfs"},
		description:   "Process information and sysctl kernel parameter filesystem",
	},
}

// RegisteredPathAccess lists required host directory and symlink permission requirements.
var RegisteredPathAccess = []*pathPermissionCheck{
	{path: "/run/", permissions: "drwxr-xr-x"},
	{path: "/var/run", permissions: "lrwxrwxrwx", targetPermissions: "drwxr-xr-x"},
	{path: "/etc/", permissions: "drwxr-xr-x"},
	{path: "/var/lib/", permissions: "drwxr-xr-x"},
	{path: "/var/log/", permissions: "drwxr-xr-x"},
	{path: "/home/", permissions: "drwxr-xr-x"},
	{path: "/lib/modules/", permissions: "drwxr-xr-x"},
}

func init() {
	for _, m := range RegisteredVirtualMounts {
		validation.Register(m)
	}
	for _, p := range RegisteredPathAccess {
		validation.Register(p)
	}
}
