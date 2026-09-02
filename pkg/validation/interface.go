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

package validation

import (
	"context"
	"sync"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
)

type Tier int

const (
	Tier0 Tier = iota // Basic validation (Gatekeeper)
	Tier1             // Subteam-specific verification
)

type SSHRunner interface {
	Run(ctx context.Context, cmd string) error
	CombinedOutput(ctx context.Context, cmd string) ([]byte, error)
}

type Check interface {
	Name() string
	Description() string
	Tier() Tier
	// Destructive returns true if the check modifies global system state
	// and requires sequential execution in isolation.
	Destructive() bool
	Run(ctx context.Context, runner SSHRunner) error
}

// DependentCheck is an optional interface that checks can implement
// to declare their external tool dependencies.
type DependentCheck interface {
	Check
	// RequiredTools returns a slice of tools that must be installed on the VM
	// before this check can run.
	RequiredTools() []tools.Type
}

// CleanableCheck is an interface for checks that mutate the host environment
// and require active teardown logic after execution to leave the host in a clean state.
type CleanableCheck interface {
	Check
	// Cleanup restores the host VM to its state prior to running the check.
	// It is called after Run() completes, regardless of whether Run() succeeded or failed.
	//
	// Implementations must be idempotent. Missing resources or "not found" errors
	// should be treated as a successful no-op rather than returning an error.
	Cleanup(ctx context.Context, runner SSHRunner) error
}

var (
	registryMu sync.Mutex
	checks     []Check
)

func Register(c Check) {
	registryMu.Lock()
	defer registryMu.Unlock()
	checks = append(checks, c)
}

func RegisteredChecks() []Check {
	registryMu.Lock()
	defer registryMu.Unlock()
	cp := make([]Check, len(checks))
	copy(cp, checks)
	return cp
}
