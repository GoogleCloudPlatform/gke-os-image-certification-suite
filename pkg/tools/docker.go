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

package tools

import (
	"bytes"
	"context"
	"fmt"
)

type DockerInstaller struct{}

func init() {
	Register(Docker, &DockerInstaller{})
}

func (i *DockerInstaller) Name() string { return "Docker" }

func (i *DockerInstaller) Exists(ctx context.Context, runner SSHRunner, osID string) (bool, error) {
	// docker info checks if the daemon is running and accessible by the current user
	err := runner.Run(ctx, "docker info")
	return err == nil, nil
}

func (i *DockerInstaller) Install(ctx context.Context, runner SSHRunner, osID string) error {
	switch osID {
	case "cos":
		// COS has Docker pre-installed. Verify it is running.
		if err := runner.Run(ctx, "docker info"); err != nil {
			return fmt.Errorf("docker is not running on COS: %w", err)
		}
		return nil

	case "nixos":
		// NixOS requires declarative service activation. We write a temporary
		// Nix configuration wrapper that imports the system config and enables Docker.
		usernameOut, err := runner.CombinedOutput(ctx, "whoami")
		if err != nil {
			return fmt.Errorf("failed to detect current username on NixOS: %w", err)
		}
		username := string(bytes.TrimSpace(usernameOut))

		configContent := fmt.Sprintf(`cat << 'EOF' > /tmp/gke-docker-config.nix
{ config, pkgs, ... }:
{
  imports = [ /etc/nixos/configuration.nix ];
  virtualisation.docker.enable = true;
  users.users."%s".extraGroups = [ "docker" ];
}
EOF`, username)

		if err := runner.Run(ctx, configContent); err != nil {
			return fmt.Errorf("failed to write temporary Nix configuration: %w", err)
		}
		defer func() {
			_ = runner.Run(ctx, "rm -f /tmp/gke-docker-config.nix")
		}()

		if err := runner.Run(ctx, "sudo nixos-rebuild switch -I nixos-config=/tmp/gke-docker-config.nix"); err != nil {
			return fmt.Errorf("failed to rebuild NixOS configuration to enable Docker: %w", err)
		}
		return nil

	case "ubuntu", "debian":
		// Standard Debian/Ubuntu apt-get installation using native docker.io package to avoid conflicts with GKE containerd
		commands := []string{
			"sudo apt-get update",
			"sudo apt-get install -y docker.io",
			"sudo systemctl start docker",
			"sudo systemctl enable docker",
			"sudo usermod -aG docker $(whoami)",
		}

		for _, cmd := range commands {
			if err := runner.Run(ctx, cmd); err != nil {
				return fmt.Errorf("command %q failed: %w", cmd, err)
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS for Docker installation: %s", osID)
	}
}

func (i *DockerInstaller) RequiresReconnect() bool { return true }
