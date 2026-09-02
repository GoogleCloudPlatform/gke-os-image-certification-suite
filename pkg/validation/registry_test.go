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

package validation_test

import (
	"context"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"testing"
)

type mockCheck struct {
	name        string
	tier        validation.Tier
	destructive bool
	runCalled   bool
	runErr      error
}

func (m *mockCheck) Name() string          { return m.name }
func (m *mockCheck) Description() string   { return "mock" }
func (m *mockCheck) Tier() validation.Tier { return m.tier }
func (m *mockCheck) Destructive() bool     { return m.destructive }
func (m *mockCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	m.runCalled = true
	return m.runErr
}

func TestRegisterAndRetrieve(t *testing.T) {
	check := &mockCheck{name: "test/mock-check", tier: validation.Tier1}
	validation.Register(check)

	all := validation.RegisteredChecks()
	found := false
	for _, c := range all {
		if c.Name() == "test/mock-check" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Registered check not found in registry")
	}
}

type mockCleanableCheck struct {
	mockCheck
	cleanupCalled bool
	cleanupErr    error
}

func (m *mockCleanableCheck) Cleanup(ctx context.Context, runner validation.SSHRunner) error {
	m.cleanupCalled = true
	return m.cleanupErr
}

func TestCleanableCheckInterface(t *testing.T) {
	cleanable := &mockCleanableCheck{
		mockCheck: mockCheck{name: "test/cleanable-check", tier: validation.Tier1, destructive: true},
	}

	var check validation.Check = cleanable
	if c, ok := check.(validation.CleanableCheck); !ok {
		t.Fatalf("Expected check to implement CleanableCheck")
	} else {
		if err := c.Cleanup(context.Background(), nil); err != nil {
			t.Errorf("Unexpected cleanup error: %v", err)
		}
		if !cleanable.cleanupCalled {
			t.Errorf("Expected cleanup to be called")
		}
	}
}

