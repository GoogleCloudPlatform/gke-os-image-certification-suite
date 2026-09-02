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
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
)

// mockCheck implements ConstrainedCheck for testing.
type mockCheck struct {
	name        string
	constraints Constraint
}

func (m *mockCheck) Name() string            { return m.name }
func (m *mockCheck) Description() string     { return "mock check" }
func (m *mockCheck) Tier() Tier              { return Tier1 }
func (m *mockCheck) Destructive() bool       { return false }
func (m *mockCheck) Run(ctx context.Context, runner SSHRunner) error { return nil }
func (m *mockCheck) Constraints() Constraint { return m.constraints }

func TestIsApplicable(t *testing.T) {
	tests := []struct {
		name       string
		check      Check
		env        TargetEnvironment
		wantActive bool
	}{
		{
			name: "unconstrained check always runs",
			check: &mockCheck{
				name: "test-unconstrained",
			},
			env: TargetEnvironment{
				OSID: "ubuntu",
			},
			wantActive: true,
		},
		{
			name: "OnlyOS matches target OS",
			check: &mockCheck{
				name: "test-onlyos",
				constraints: Constraint{
					OnlyOS: []string{"cos", "nixos"},
				},
			},
			env: TargetEnvironment{
				OSID: "cos",
			},
			wantActive: true,
		},
		{
			name: "OnlyOS mismatches target OS",
			check: &mockCheck{
				name: "test-onlyos-fail",
				constraints: Constraint{
					OnlyOS: []string{"cos", "nixos"},
				},
			},
			env: TargetEnvironment{
				OSID: "ubuntu",
			},
			wantActive: false,
		},
		{
			name: "SkipOS matches target OS",
			check: &mockCheck{
				name: "test-skipos",
				constraints: Constraint{
					SkipOS: []string{"ubuntu"},
				},
			},
			env: TargetEnvironment{
				OSID: "ubuntu",
			},
			wantActive: false,
		},
		{
			name: "SkipOS mismatches target OS",
			check: &mockCheck{
				name: "test-skipos-pass",
				constraints: Constraint{
					SkipOS: []string{"ubuntu"},
				},
			},
			env: TargetEnvironment{
				OSID: "cos",
			},
			wantActive: true,
		},
		{
			name: "MinGKEVersion matches newer",
			check: &mockCheck{
				name: "test-mingke",
				constraints: Constraint{
					MinGKEVersion: "1.33.0",
				},
			},
			env: TargetEnvironment{
				OSID:       "cos",
				HasVersion: true,
				GKEVersion: utils.SemVer{Major: 1, Minor: 34, Patch: 0},
			},
			wantActive: true,
		},
		{
			name: "MinGKEVersion mismatches older",
			check: &mockCheck{
				name: "test-mingke-fail",
				constraints: Constraint{
					MinGKEVersion: "1.33.0",
				},
			},
			env: TargetEnvironment{
				OSID:       "cos",
				HasVersion: true,
				GKEVersion: utils.SemVer{Major: 1, Minor: 32, Patch: 0},
			},
			wantActive: false,
		},
		{
			name: "MatrixRule skip matches GKE version range",
			check: &mockCheck{
				name: "test-matrix-skip",
				constraints: Constraint{
					MatrixRules: []MatrixRule{
						{
							OSID:          "ubuntu",
							MaxGKEVersion: "1.32.99",
							Skip:          true,
						},
					},
				},
			},
			env: TargetEnvironment{
				OSID:       "ubuntu",
				HasVersion: true,
				GKEVersion: utils.SemVer{Major: 1, Minor: 32, Patch: 5},
			},
			wantActive: false,
		},
		{
			name: "MatrixRule skip matches higher GKE version range",
			check: &mockCheck{
				name: "test-matrix-no-skip",
				constraints: Constraint{
					MatrixRules: []MatrixRule{
						{
							OSID:          "ubuntu",
							MaxGKEVersion: "1.32.99",
							Skip:          true,
						},
					},
				},
			},
			env: TargetEnvironment{
				OSID:       "ubuntu",
				HasVersion: true,
				GKEVersion: utils.SemVer{Major: 1, Minor: 33, Patch: 0},
			},
			wantActive: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := IsApplicable(tc.check, tc.env)
			if got != tc.wantActive {
				t.Errorf("IsApplicable() = %v, want %v", got, tc.wantActive)
			}
		})
	}
}
