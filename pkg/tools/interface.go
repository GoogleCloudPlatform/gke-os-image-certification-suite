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
	"sync"
)

// Type represents an external binary dependency required by a check.
type Type string

const (
	Cilium  Type = "cilium"
	Docker  Type = "docker"
	Kind    Type = "kind"
	Kubectl Type = "kubectl"
)

// Installer defines the contract for installing a tool on the GCE VM.
type Installer interface {
	// Name returns the human-readable name of the tool (e.g., "Docker")
	Name() string
	// Exists checks if the tool is already installed and functional on the target VM.
	Exists(ctx context.Context, runner SSHRunner, osID string) (bool, error)
	// Install dynamically installs the tool on the target OS.
	Install(ctx context.Context, runner SSHRunner, osID string) error
	// RequiresReconnect returns true if the tool's installation requires a connection reset.
	RequiresReconnect() bool
}

// SSHRunner defines the minimal interface required by installers to run commands.
type SSHRunner interface {
	Run(ctx context.Context, cmd string) error
	CombinedOutput(ctx context.Context, cmd string) ([]byte, error)
}

var (
	registryMu sync.Mutex
	installers = make(map[Type]Installer)
)

// Register adds a tool installer to the global registry.
// This is typically called from the init() block of each tool file.
func Register(t Type, i Installer) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := installers[t]; dup {
		panic("tool installer already registered: " + string(t))
	}
	installers[t] = i
}

// Get retrieves a registered installer for a tool type.
func Get(t Type) (Installer, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	i, ok := installers[t]
	return i, ok
}
