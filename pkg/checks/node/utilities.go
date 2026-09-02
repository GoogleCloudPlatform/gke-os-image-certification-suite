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
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type utilityCheck struct {
	name        string
	constraints validation.Constraint
}

func (c *utilityCheck) Constraints() validation.Constraint {
	return c.constraints
}

func (c *utilityCheck) Name() string { return "node/utility-" + c.name }
func (c *utilityCheck) Description() string {
	return "Verifies that utility " + c.name + " is installed"
}
func (c *utilityCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *utilityCheck) Destructive() bool     { return false }

func (c *utilityCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, "which "+c.name); err != nil {
		return fmt.Errorf("utility binary not found: %w", err)
	}
	return nil
}

func init() {
	utilities := []string{
		// System
		"systemctl", "journalctl", "logrotate", "sysctl", "modprobe", "lsmod", "reboot", "mkdir", "chmod", "nologin", "stat", "timeout",
		// Network
		"iptables", "ip6tables", "ip", "conntrack",
		// Storage (excluding cryptsetup which is versioned separately)
		"mount", "umount", "mountpoint", "mkfs.ext4", "tune2fs", "mdadm", "udevadm", "fallocate", "mkswap", "swapon", "swapoff", "mount.nfs",
		// Container infra
		"containerd", "ctr", "runc", "docker",
		// Others
		"python3", "tar", "gunzip", "jq", "curl", "uuidgen", "base64", "xxd", "sha1sum", "sha256sum", "sha512sum", "bash", "sh", "sed", "awk", "grep", "cat", "xargs", "sos",
	}

	for _, util := range utilities {
		validation.Register(&utilityCheck{name: util})
	}

	// cryptsetup utility package is pre-installed starting from GKE v1.33
	validation.Register(&utilityCheck{
		name: "cryptsetup",
		constraints: validation.Constraint{
			MinGKEVersion: "1.33.0",
		},
	})
}
