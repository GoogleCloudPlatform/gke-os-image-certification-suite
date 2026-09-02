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

type KindInstaller struct{}

func init() {
	Register(Kind, &KindInstaller{})
}

func (i *KindInstaller) Name() string { return "Kind" }

func (i *KindInstaller) Exists(ctx context.Context, runner SSHRunner, osID string) (bool, error) {
	absPath := getKindPath(osID)
	// Check if the binary exists, is executable, and runs --version successfully
	err := runner.Run(ctx, fmt.Sprintf("%s --version", absPath))
	return err == nil, nil
}

func (i *KindInstaller) Install(ctx context.Context, runner SSHRunner, osID string) error {
	installDir := getKindInstallDir(osID)
	absPath := getKindPath(osID)

	commands := []string{
		fmt.Sprintf("mkdir -p %s", installDir),
		fmt.Sprintf("curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64"),
		"chmod +x ./kind",
		fmt.Sprintf("mv ./kind %s", absPath),
	}

	for _, cmd := range commands {
		if err := runner.Run(ctx, cmd); err != nil {
			return fmt.Errorf("command %q failed: %w", cmd, err)
		}
	}
	return nil
}

func getKindInstallDir(osID string) string {
	return "$HOME/.local/bin"
}

func getKindPath(osID string) string {
	return fmt.Sprintf("%s/kind", getKindInstallDir(osID))
}

func (i *KindInstaller) RequiresReconnect() bool { return false }
