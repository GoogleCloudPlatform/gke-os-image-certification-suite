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
	"context"
	"fmt"
)

type CiliumInstaller struct{}

func init() {
	Register(Cilium, &CiliumInstaller{})
}

func (i *CiliumInstaller) Name() string { return "Cilium CLI" }

func (i *CiliumInstaller) Exists(ctx context.Context, runner SSHRunner, _ string) (bool, error) {
	absPath := getCiliumPath()
	// Check if the binary exists, is executable, and runs version successfully
	err := runner.Run(ctx, fmt.Sprintf("%s version --client", absPath))
	return err == nil, nil
}

func (i *CiliumInstaller) Install(ctx context.Context, runner SSHRunner, _ string) error {
	installDir := getCiliumInstallDir()
	absPath := getCiliumPath()

	resolveVersionCmd := fmt.Sprintf("CILIUM_CLI_VERSION=$(curl -s %q)", "https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt")
	downloadArchiveCmd := fmt.Sprintf("curl -L --fail %q -o /tmp/cilium.tar.gz", "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz")

	commands := []string{
		fmt.Sprintf("mkdir -p %s", installDir),
		fmt.Sprintf("%s; %s", resolveVersionCmd, downloadArchiveCmd),
		fmt.Sprintf("tar -xzf /tmp/cilium.tar.gz -C %s cilium", installDir),
		fmt.Sprintf("chmod +x %s", absPath),
		"rm -f /tmp/cilium.tar.gz",
	}

	for _, cmd := range commands {
		if err := runner.Run(ctx, cmd); err != nil {
			return fmt.Errorf("command %q failed: %w", cmd, err)
		}
	}
	return nil
}

func getCiliumInstallDir() string {
	return "$HOME/.local/bin"
}

func getCiliumPath() string {
	return fmt.Sprintf("%s/cilium", getCiliumInstallDir())
}

func (i *CiliumInstaller) RequiresReconnect() bool { return false }
