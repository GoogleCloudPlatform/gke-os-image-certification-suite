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
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
)

// TargetEnvironment holds the runtime properties of the target VM and GKE release under test.
type TargetEnvironment struct {
	OSID             string       // e.g., "cos", "ubuntu", "nixos", "rhel"
	GKEVersion       utils.SemVer // Parsed SemVer representation
	HasVersion       bool         // True if a valid GKE version was provided
	Runner           SSHRunner
	ReconnectClosure func() (SSHRunner, error)
}

// Constraint defines declarative rules governing when a check should execute.
// All non-zero fields are evaluated as a logical AND.
type Constraint struct {
	// OnlyOS restricts execution to the listed OS IDs. If empty, all OSes are allowed.
	OnlyOS []string
	// SkipOS excludes execution on the listed OS IDs.
	SkipOS []string
	// MinGKEVersion specifies the minimum inclusive GKE version (e.g. "1.33.0" or "1.37").
	MinGKEVersion string
	// MaxGKEVersion specifies the maximum inclusive GKE version (e.g. "1.36.99").
	MaxGKEVersion string
	// MatrixRules allows composite OS + Version constraints.
	MatrixRules []MatrixRule
	// NoTargetVMNecessary means the check does not use the target VM (but can run in environments where there is one).
	NoTargetVMNecessary bool
}

// MatrixRule allows conditional version constraints applied only to a specific OS.
type MatrixRule struct {
	OSID          string
	MinGKEVersion string
	MaxGKEVersion string
	Skip          bool // If true, skips this OS when within the version range
}

// ConstrainedCheck is an optional interface that checks implement to expose their constraints.
type ConstrainedCheck interface {
	Check
	Constraints() Constraint
}
