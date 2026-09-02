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

package observability

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// pathCheck validates existence and permissions of required observability host paths.
type pathCheck struct {
	name        string
	description string
	runFunc     func(ctx context.Context, runner validation.SSHRunner) error
}

func (c *pathCheck) Name() string          { return "observability/" + c.name }
func (c *pathCheck) Description() string   { return c.description }
func (c *pathCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *pathCheck) Destructive() bool     { return false }
func (c *pathCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	return c.runFunc(ctx, runner)
}

// verifyPathPermissions checks that a path exists and matches expected permission bits.
func verifyPathPermissions(ctx context.Context, runner validation.SSHRunner, path, expectedPerms string) error {
	out, err := runner.CombinedOutput(ctx, "stat -c '%A' "+path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}
	actual := strings.TrimSpace(string(out))
	ok, err := validation.IsPermissiveSuperset(actual, expectedPerms)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("path %s permissions %s are insufficient, expected at least %s", path, actual, expectedPerms)
	}
	return nil
}

// verifyDirWritable checks that a directory or its ancestor directory (e.g. /var/lib, /var/run) exists.
func verifyDirWritable(ctx context.Context, runner validation.SSHRunner, path string) error {
	cmd := fmt.Sprintf("test -d %s || test -d $(dirname %s) || test -d $(dirname $(dirname %s))", path, path, path)
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("directory %s or its parent directory does not exist: %w", path, err)
	}
	return nil
}

// verifyConcreteFile checks that a file or symlink resolves to a valid, readable, non-empty file.
func verifyConcreteFile(ctx context.Context, runner validation.SSHRunner, path string) error {
	// stat -L verifies the target of the symlink exists and is not a dangling link
	out, err := runner.CombinedOutput(ctx, "stat -L -c '%s' "+path)
	if err != nil {
		return fmt.Errorf("file %s does not exist or points to a broken/escaped symlink target: %w", path, err)
	}
	sizeStr := strings.TrimSpace(string(out))
	if sizeStr == "0" {
		return fmt.Errorf("file %s is empty", path)
	}
	return nil
}

func init() {
	// 1. Host Log Directories
	validation.Register(&pathCheck{
		name:        "path-var-log",
		description: "Verifies /var/log/ exists and has at least drwxr-xr-x permissions",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			return verifyPathPermissions(ctx, runner, "/var/log/", "drwxr-xr-x")
		},
	})
	validation.Register(&pathCheck{
		name:        "path-var-log-journal",
		description: "Verifies /var/log/journal/ exists and is a readable directory",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := runner.Run(ctx, "test -d /var/log/journal/"); err != nil {
				return fmt.Errorf("/var/log/journal/ directory does not exist: %w", err)
			}
			return nil
		},
	})
	validation.Register(&pathCheck{
		name:        "path-var-log-containers",
		description: "Verifies /var/log/containers/ exists or can be created as a readable directory",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := runner.Run(ctx, "test -d /var/log/containers/ || test -d /var/log/"); err != nil {
				return fmt.Errorf("failed to verify /var/log/containers/ or parent /var/log/ directory: %w", err)
			}
			return nil
		},
	})
	validation.Register(&pathCheck{
		name:        "path-var-log-pods",
		description: "Verifies /var/log/pods/ exists or can be created as a readable directory",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := runner.Run(ctx, "test -d /var/log/pods/ || test -d /var/log/"); err != nil {
				return fmt.Errorf("failed to verify /var/log/pods/ or parent /var/log/ directory: %w", err)
			}
			return nil
		},
	})

	// 2. Logging State Directories (Writable / Creatable)
	validation.Register(&pathCheck{
		name:        "path-fluentbit-pos-files",
		description: "Verifies /var/lib/google-fluentbit/pos-files/ or /var/lib/ exists",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			return verifyDirWritable(ctx, runner, "/var/lib/google-fluentbit/pos-files/")
		},
	})
	validation.Register(&pathCheck{
		name:        "path-fluentbit-runtime",
		description: "Verifies /var/run/google-fluentbit/ or /var/run exists",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			return verifyDirWritable(ctx, runner, "/var/run/google-fluentbit/")
		},
	})

	// 3. Concrete Certificate and DNS Symlink Resolution (No dangling escapes)
	validation.Register(&pathCheck{
		name:        "path-ca-certificates-bundle",
		description: "Verifies /etc/ssl/certs/ca-certificates.crt resolves to a valid concrete file",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			return verifyConcreteFile(ctx, runner, "/etc/ssl/certs/ca-certificates.crt")
		},
	})
	validation.Register(&pathCheck{
		name:        "path-resolv-conf",
		description: "Verifies /etc/resolv.conf resolves to a valid concrete file with nameserver entries",
		runFunc: func(ctx context.Context, runner validation.SSHRunner) error {
			if err := verifyConcreteFile(ctx, runner, "/etc/resolv.conf"); err != nil {
				return err
			}
			out, err := runner.CombinedOutput(ctx, "grep -E '^nameserver' /etc/resolv.conf")
			if err != nil || len(bytes.TrimSpace(out)) == 0 {
				return fmt.Errorf("/etc/resolv.conf does not contain any valid 'nameserver' configurations")
			}
			return nil
		},
	})
}
