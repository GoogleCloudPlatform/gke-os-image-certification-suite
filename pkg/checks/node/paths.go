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

// socketExistsCheck validates that a Unix domain socket exists.
type socketExistsCheck struct {
	path string
}

func (c *socketExistsCheck) Name() string {
	return "node/exists-socket-" + c.path
}

func (c *socketExistsCheck) Description() string {
	return fmt.Sprintf("Verifies that Unix socket %s exists", c.path)
}

func (c *socketExistsCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *socketExistsCheck) Destructive() bool     { return false }

func (c *socketExistsCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "test -S "+c.path); err != nil {
		return fmt.Errorf("socket %s does not exist: %w", c.path, err)
	}
	return nil
}

// pathExistenceCheck validates the existence of paths (supporting both static paths and wildcards).
type pathExistenceCheck struct {
	pattern string
	name    string
}

func (c *pathExistenceCheck) Name() string { return "node/exists-" + c.name }

func (c *pathExistenceCheck) Description() string {
	return "Verifies that path(s) matching " + c.pattern + " exist"
}

func (c *pathExistenceCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *pathExistenceCheck) Destructive() bool     { return false }

func (c *pathExistenceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "ls "+c.pattern); err != nil {
		return fmt.Errorf("no paths matching pattern %s found: %w", c.pattern, err)
	}
	return nil
}

// pathPermissionCheck validates exact permissions of a path, and optionally its symlink target
type pathPermissionCheck struct {
	path              string
	permissions       string
	targetPermissions string // Optional. If set, path must be a symlink matching 'permissions', and its target must match 'targetPermissions'.
}

func (c *pathPermissionCheck) Name() string {
	return "node/permission-" + c.path
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

	ok, err := validation.IsPermissiveSuperset(actual, c.permissions)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("path %s has permissions %s (insufficient), expected at least %s", c.path, actual, c.permissions)
	}

	// 2. If this is a symlink, verify that the target exists and has correct permissions
	if c.targetPermissions != "" {
		targetOut, err := runner.CombinedOutput(ctx, "stat -L -c '%A' "+c.path)
		if err != nil {
			return fmt.Errorf("failed to stat symlink target for %s (broken link?): %w", c.path, err)
		}
		actualTarget := string(bytes.TrimSpace(targetOut))

		ok, err := validation.IsPermissiveSuperset(actualTarget, c.targetPermissions)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("symlink target of %s has permissions %s (insufficient), expected at least %s", c.path, actualTarget, c.targetPermissions)
		}
	}

	return nil
}

// fileReadabilityCheck validates that a file exists, is readable, and is non-empty.
type fileReadabilityCheck struct {
	path string
	tier validation.Tier
}

func (c *fileReadabilityCheck) Name() string {
	return "node/readability-" + c.path
}

func (c *fileReadabilityCheck) Description() string {
	return fmt.Sprintf("Verifies that %s exists, is readable, and contains data", c.path)
}

func (c *fileReadabilityCheck) Tier() validation.Tier { return c.tier }
func (c *fileReadabilityCheck) Destructive() bool     { return false }

func (c *fileReadabilityCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	out, err := runner.CombinedOutput(ctx, "cat "+c.path)
	if err != nil {
		return fmt.Errorf("%s is not readable: %w", c.path, err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return fmt.Errorf("%s is empty", c.path)
	}
	return nil
}

func init() {
	// 1. Wildcard Paths Existence
	validation.Register(&pathExistenceCheck{pattern: "/sys/class/net/*/mtu", name: "sys-class-net-nic-mtu"})
	validation.Register(&pathExistenceCheck{pattern: "/sys/block/*/queue/scheduler", name: "sys-block-disk-queue-scheduler"})

	// 2. Path Permissions (non-symlinks)
	permissions := map[string]string{
		// Directories
		"/home/":                               "drwxr-xr-x",
		"/tmp/":                                "drwxrwxrwt",
		"/etc/":                                "drwxr-xr-x",
		"/etc/systemd/system/":                 "drwxr-xr-x",
		"/etc/default/":                        "drwxr-xr-x",
		"/etc/docker/":                         "drwxr-xr-x",
		"/etc/modprobe.d/":                     "drwxr-xr-x",
		"/etc/sysctl.d/":                       "drwxr-xr-x",
		"/etc/profile.d/":                      "drwxr-xr-x",
		"/etc/sudoers.d/":                      "drwxr-x---",
		"/dev/":                                "drwxr-xr-x",
		"/sys/":                                "dr-xr-xr-x",
		"/proc/sys/":                           "dr-xr-xr-x",
		"/var/lib/":                            "drwxr-xr-x",
		"/var/log/":                            "drwxr-xr-x",
		"/run/":                                "drwxr-xr-x",
		"/mnt/":                                "drwxr-xr-x",
		"/dev/disk/by-uuid/":                   "drwxr-xr-x",
		"/sys/fs/cgroup/":                      "dr-xr-xr-x",
		"/sys/kernel/mm/hugepages/":            "drwxr-xr-x",
		"/sys/kernel/mm/transparent_hugepage/": "drwxr-xr-x",
		"/lib/modules/":                        "drwxr-xr-x",
		"/etc/ssl/certs/":                      "drwxr-xr-x",
		"/sys/fs/bpf/":                         "drwx-----T",

		// Files
		"/sys/devices/system/cpu/smt/control":   "-rw-r--r--",
		"/proc/sys/kernel/core_pattern":         "-rw-r--r--",
		"/proc/sys/kernel/pid_max":              "-rw-r--r--",
		"/proc/sys/fs/inotify/max_user_watches": "-rw-r--r--",
		"/etc/hosts":                            "-rw-r--r--",
		"/etc/group":                            "-rw-r--r--",
		"/etc/iproute2/rt_tables":               "-rw-r--r--",
		"/dev/ttyS0":                            "crw--w----",
		"/dev/ttyS2":                            "crw--w----",
		"/usr/lib/systemd/systemd-sysctl":       "-rwxr-xr-x",
	}
	for path, perm := range permissions {
		validation.Register(&pathPermissionCheck{path: path, permissions: perm})
	}

	// 3. Symlink Path Permissions (with target verification)
	validation.Register(&pathPermissionCheck{
		path:              "/var/run",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "drwxr-xr-x",
	})
	validation.Register(&pathPermissionCheck{
		path:              "/etc/resolv.conf",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "-rw-r--r--",
	})
	validation.Register(&fileReadabilityCheck{
		path: "/etc/os-release",
		tier: validation.Tier0,
	})
	validation.Register(&pathExistenceCheck{
		pattern: "/etc/ssh/sshd_config",
		name:    "etc-ssh-sshd_config",
	})
	validation.Register(&pathExistenceCheck{
		pattern: "/dev/tpm0",
		name:    "dev-tpm0",
	})

	// 4. Host Resource Validation Checks (General Node validations)
	validation.Register(&fileReadabilityCheck{
		path: "/etc/ssl/certs/ca-certificates.crt",
		tier: validation.Tier1,
	})
	validation.Register(&socketExistsCheck{path: "/run/dbus/system_bus_socket"})
}
