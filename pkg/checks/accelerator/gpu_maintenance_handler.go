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

package accelerator

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// getRequiredCertMounts inspects /etc/ssl/certs and /etc/ssl/certs/ca-certificates.crt
// on the host to dynamically discover any external top-level directories required to resolve
// symlinks across any Linux operating system (e.g., /nix/store and /etc/static on NixOS, /usr/share on Debian/Ubuntu).
func getRequiredCertMounts(ctx context.Context, runner validation.SSHRunner) ([]string, error) {
	mountMap := map[string]bool{"/etc/ssl/certs": true}

	// Inspect both immediate readlink and canonical realpath of cert paths to capture intermediate and final symlink hops.
	cmd := `for p in /etc/ssl/certs /etc/ssl/certs/ca-certificates.crt; do
		if [ -L "$p" ]; then readlink "$p"; fi
		readlink -f "$p" 2>/dev/null || realpath "$p" 2>/dev/null
	done`
	out, err := runner.CombinedOutput(ctx, cmd)
	if err != nil {
		// If resolution fails, default to just /etc/ssl/certs
		return []string{"/etc/ssl/certs"}, nil
	}

	for _, line := range strings.Split(string(out), "\n") {
		target := strings.TrimSpace(line)
		if target == "" || !strings.HasPrefix(target, "/") {
			continue
		}
		if !strings.HasPrefix(target, "/etc/ssl/certs") {
			parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
			if len(parts) >= 2 {
				mountPoint := "/" + parts[0] + "/" + parts[1]
				if err := runner.Run(ctx, fmt.Sprintf("test -d %s", mountPoint)); err == nil {
					mountMap[mountPoint] = true
				}
			} else if len(parts) == 1 {
				mountPoint := "/" + parts[0]
				if err := runner.Run(ctx, fmt.Sprintf("test -d %s", mountPoint)); err == nil {
					mountMap[mountPoint] = true
				}
			}
		}
	}

	var mounts []string
	for m := range mountMap {
		mounts = append(mounts, m)
	}
	return mounts, nil
}

const certCheckImage = "docker.io/library/alpine:latest"

// containerCertsAccessCheck runs a container sanity check to verify cert resolution.
type containerCertsAccessCheck struct{}

func (c *containerCertsAccessCheck) Name() string {
	return "gpu-maintenance-handler/container-certs-access"
}

func (c *containerCertsAccessCheck) Description() string {
	return "Verifies that host CA certificates can be mounted and read from inside a container via containerd (ctr)"
}

func (c *containerCertsAccessCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *containerCertsAccessCheck) Destructive() bool {
	return true
}

func (c *containerCertsAccessCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// 1. Verify containerd CLI (ctr) is available on the node
	if err := runner.Run(ctx, "which ctr"); err != nil {
		return fmt.Errorf("containerd CLI is required for container certs access check: %w", err)
	}

	// 2. Discover all host directories required to resolve CA certificates inside a container.
	mounts, err := getRequiredCertMounts(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to determine required certificate mount paths: %w", err)
	}

	// 3. Execute container verification using native containerd (ctr)
	ctrPrefix := "ctr"
	if runner.Run(ctx, "ctr images list") != nil && runner.Run(ctx, "sudo ctr images list") == nil {
		ctrPrefix = "sudo ctr"
	}

	var ctrMounts strings.Builder
	for _, m := range mounts {
		ctrMounts.WriteString(fmt.Sprintf(" --mount type=bind,src=%s,dst=%s,options=rbind:ro", m, m))
	}
	if err := runner.Run(ctx, fmt.Sprintf("%s images pull %s", ctrPrefix, certCheckImage)); err != nil {
		// If online pull fails, check if alpine already exists locally in containerd
		if runner.Run(ctx, fmt.Sprintf("%s images check | grep -q %s", ctrPrefix, certCheckImage)) != nil {
			return fmt.Errorf("containerd (ctr) available but failed to pull or find image %s: %w", certCheckImage, err)
		}
	}

	ctrCmd := fmt.Sprintf(`%s run --rm%s %s certcheck sh -c "test -f /etc/ssl/certs/ca-certificates.crt"`, ctrPrefix, ctrMounts.String(), certCheckImage)
	if err := runner.Run(ctx, ctrCmd); err != nil {
		return fmt.Errorf("failed to verify certs accessibility via containerd (ctr) container: %w", err)
	}
	return nil
}

func (c *containerCertsAccessCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	ctrPrefix := "ctr"
	if runner.Run(ctx, "ctr images list") != nil && runner.Run(ctx, "sudo ctr images list") == nil {
		ctrPrefix = "sudo ctr"
	}
	// Ensure residual test container images are removed from the host.
	return runner.Run(ctx, fmt.Sprintf("%s images rm %s", ctrPrefix, certCheckImage))
}

func (c *containerCertsAccessCheck) RequiredTools() []tools.Type {
	return nil
}

func init() {
	validation.Register(&containerCertsAccessCheck{})
}
