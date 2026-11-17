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

package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
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

type mockDependentCheck struct {
	mockCheck
	requiredTools []tools.Type
}

func (m *mockDependentCheck) RequiredTools() []tools.Type {
	return m.requiredTools
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

type mockConstrainedCheck struct {
	mockCheck
	constraints validation.Constraint
}

func (m *mockConstrainedCheck) Constraints() validation.Constraint {
	return m.constraints
}

type mockCleanableConstrainedCheck struct {
	mockCleanableCheck
	constraints validation.Constraint
}

func (m *mockCleanableConstrainedCheck) Constraints() validation.Constraint {
	return m.constraints
}

func TestRunTier0_FailureHalts(t *testing.T) {
	err1 := errors.New("t0 fail 1")
	err2 := errors.New("t0 fail 2")
	t0Fail1 := &mockCheck{name: "t0-fail-1", tier: validation.Tier0, runErr: err1}
	t0Pass := &mockCheck{name: "t0-pass", tier: validation.Tier0}
	t0Fail2 := &mockCheck{name: "t0-fail-2", tier: validation.Tier0, runErr: err2}

	checks := []validation.Check{t0Fail1, t0Pass, t0Fail2}
	stats := &suiteStats{}

	err := runTier0(context.Background(), nil, validation.TargetEnvironment{}, checks, stats)
	if err == nil {
		t.Fatalf("Expected error from runTier0 due to check failures, got nil")
	}

	if !t0Fail1.runCalled || !t0Pass.runCalled || !t0Fail2.runCalled {
		t.Errorf("Expected all Tier 0 checks to run and accumulate failures before halting")
	}
	if !errors.Is(err, err1) || !errors.Is(err, err2) {
		t.Errorf("Expected aggregated error to wrap both err1 and err2, got: %v", err)
	}
	if stats.failed != 2 || stats.passed != 1 {
		t.Errorf("Expected stats.failed == 2 and stats.passed == 1, got failed=%d, passed=%d", stats.failed, stats.passed)
	}
}

func TestRunTier0_Success(t *testing.T) {
	t0_1 := &mockCheck{name: "t0-1", tier: validation.Tier0}
	t0_2 := &mockCheck{name: "t0-2", tier: validation.Tier0}

	checks := []validation.Check{t0_1, t0_2}
	stats := &suiteStats{}

	err := runTier0(context.Background(), nil, validation.TargetEnvironment{}, checks, stats)
	if err != nil {
		t.Errorf("Expected no error from runTier0, got %v", err)
	}

	if !t0_1.runCalled || !t0_2.runCalled {
		t.Errorf("Expected all Tier 0 checks to be run")
	}
	if stats.passed != 2 {
		t.Errorf("Expected stats.passed == 2, got %d", stats.passed)
	}
}

func TestRunTier0_CheckStatuses(t *testing.T) {
	t0Pass := &mockCheck{name: "t0-pass", tier: validation.Tier0}
	t0SkipConstraint := &mockConstrainedCheck{
		mockCheck: mockCheck{name: "t0-skip-constraint", tier: validation.Tier0},
		constraints: validation.Constraint{
			OnlyOS: []string{"rhel"},
		},
	}
	t0SkipCondition := &mockConstrainedCheck{
		mockCheck: mockCheck{name: "t0-skip-condition", tier: validation.Tier0},
		constraints: validation.Constraint{
			Condition: func(ctx context.Context, runner validation.SSHRunner) (bool, string, error) {
				return false, "hardware not available", nil
			},
		},
	}

	checks := []validation.Check{t0Pass, t0SkipConstraint, t0SkipCondition}
	stats := &suiteStats{}

	err := runTier0(context.Background(), &testutil.MockSSHRunner{}, validation.TargetEnvironment{OSID: "ubuntu"}, checks, stats)
	if err != nil {
		t.Fatalf("Expected no error from runTier0 with skips and passes, got %v", err)
	}
	if stats.passed != 1 {
		t.Errorf("Expected stats.passed == 1, got %d", stats.passed)
	}
	if stats.skipped != 2 {
		t.Errorf("Expected stats.skipped == 2, got %d", stats.skipped)
	}
	if stats.failed != 0 {
		t.Errorf("Expected stats.failed == 0, got %d", stats.failed)
	}
}

func TestRunTier1_FailuresAccumulate(t *testing.T) {
	t1Fail := &mockCheck{name: "t1-fail", tier: validation.Tier1, runErr: errors.New("t1 failed")}
	t1Pass := &mockCheck{name: "t1-pass", tier: validation.Tier1}

	checks := []validation.Check{t1Fail, t1Pass}
	stats := &suiteStats{}

	err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, stats)
	if err == nil {
		t.Errorf("Expected error from runTier1 due to check failure, got nil")
	}

	if !t1Fail.runCalled {
		t.Errorf("Expected failing Tier 1 check to be run")
	}
	if !t1Pass.runCalled {
		t.Errorf("Expected subsequent Tier 1 checks to run even after a previous failure")
	}
	if stats.failed != 1 || stats.passed != 1 {
		t.Errorf("Expected stats.failed == 1 and stats.passed == 1, got failed=%d, passed=%d", stats.failed, stats.passed)
	}
}

func TestRunTier1_Success(t *testing.T) {
	t1_1 := &mockCheck{name: "t1-1", tier: validation.Tier1}
	t1_2 := &mockCheck{name: "t1-2", tier: validation.Tier1}

	checks := []validation.Check{t1_1, t1_2}
	stats := &suiteStats{}

	err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, stats)
	if err != nil {
		t.Errorf("Expected no error from runTier1, got %v", err)
	}

	if !t1_1.runCalled || !t1_2.runCalled {
		t.Errorf("Expected all Tier 1 checks to be run")
	}
	if stats.passed != 2 {
		t.Errorf("Expected stats.passed == 2, got %d", stats.passed)
	}
}

func TestRunTier1_CheckStatuses_PassedSkippedFailed(t *testing.T) {
	t1Pass := &mockCheck{name: "t1-pass", tier: validation.Tier1}
	t1SkipConstraint := &mockConstrainedCheck{
		mockCheck: mockCheck{name: "t1-skip-constraint", tier: validation.Tier1},
		constraints: validation.Constraint{
			OnlyOS: []string{"ubuntu"},
		},
	}
	t1SkipCondition := &mockConstrainedCheck{
		mockCheck: mockCheck{name: "t1-skip-condition", tier: validation.Tier1},
		constraints: validation.Constraint{
			Condition: func(ctx context.Context, runner validation.SSHRunner) (bool, string, error) {
				return false, "TPU device not present", nil
			},
		},
	}
	t1Fail := &mockCheck{name: "t1-fail", tier: validation.Tier1, runErr: errors.New("check failed")}

	// Also add a destructive check that passes
	t1DestructivePass := &mockCleanableCheck{
		mockCheck: mockCheck{name: "t1-dest-pass", tier: validation.Tier1, destructive: true},
	}
	// And a destructive check that skips
	t1DestructiveSkip := &mockCleanableConstrainedCheck{
		mockCleanableCheck: mockCleanableCheck{
			mockCheck: mockCheck{name: "t1-dest-skip", tier: validation.Tier1, destructive: true},
		},
		constraints: validation.Constraint{
			SkipOS: []string{"cos"},
		},
	}

	checks := []validation.Check{t1Pass, t1SkipConstraint, t1SkipCondition, t1Fail, t1DestructivePass, t1DestructiveSkip}
	stats := &suiteStats{}

	err := runTier1(context.Background(), &testutil.MockSSHRunner{}, validation.TargetEnvironment{OSID: "cos"}, checks, stats)
	if err == nil {
		t.Fatal("Expected error from runTier1 due to t1Fail, got nil")
	}

	if stats.passed != 2 {
		t.Errorf("Expected stats.passed == 2 (1 non-destructive, 1 destructive), got %d", stats.passed)
	}
	if stats.skipped != 3 {
		t.Errorf("Expected stats.skipped == 3, got %d", stats.skipped)
	}
	if stats.failed != 1 {
		t.Errorf("Expected stats.failed == 1, got %d", stats.failed)
	}
}

func TestRunTier1_DestructiveCleanup_Success(t *testing.T) {
	destructiveCleanable := &mockCleanableCheck{
		mockCheck: mockCheck{name: "t1-destructive-cleanable", tier: validation.Tier1, destructive: true},
	}

	checks := []validation.Check{destructiveCleanable}

	err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, nil)
	if err != nil {
		t.Fatalf("Unexpected error from runTier1: %v", err)
	}

	if !destructiveCleanable.runCalled {
		t.Errorf("Expected destructive check Run() to be called")
	}
	if !destructiveCleanable.cleanupCalled {
		t.Errorf("Expected destructive check Cleanup() to be called")
	}
}

func TestRunTier1_DestructiveCleanup_CalledOnFailure(t *testing.T) {
	destructiveCleanable := &mockCleanableCheck{
		mockCheck:  mockCheck{name: "t1-destructive-fail", tier: validation.Tier1, destructive: true, runErr: errors.New("check failed")},
		cleanupErr: nil,
	}

	checks := []validation.Check{destructiveCleanable}

	err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, nil)
	if err == nil {
		t.Fatal("Expected error from runTier1 due to check failure, got nil")
	}

	if !destructiveCleanable.runCalled {
		t.Errorf("Expected destructive check Run() to be called")
	}
	if !destructiveCleanable.cleanupCalled {
		t.Errorf("Expected destructive check Cleanup() to be called even after Run() failure")
	}
}

func TestRunTier1_DestructiveCleanup_CleanupFailure(t *testing.T) {
	destructiveCleanable := &mockCleanableCheck{
		mockCheck:  mockCheck{name: "t1-destructive-cleanup-fail", tier: validation.Tier1, destructive: true},
		cleanupErr: errors.New("cleanup failed"),
	}

	checks := []validation.Check{destructiveCleanable}

	err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, nil)
	if err == nil {
		t.Fatal("Expected error from runTier1 due to cleanup failure, got nil")
	}

	if !destructiveCleanable.runCalled {
		t.Errorf("Expected destructive check Run() to be called")
	}
	if !destructiveCleanable.cleanupCalled {
		t.Errorf("Expected destructive check Cleanup() to be called")
	}
}

func TestPrintSummary(t *testing.T) {
	// Simple smoke test ensuring printSummary does not panic
	printSummary(suiteStats{passed: 5, skipped: 3, failed: 1})
}


func TestValidateChecks_Tier0DependencyViolation(t *testing.T) {
	// 1. Valid Tier 0 Check (no tools)
	t0Valid := &mockCheck{name: "t0-valid", tier: validation.Tier0}

	// 2. Valid Tier 0 Dependent Check (implements DependentCheck but returns empty tools)
	t0ValidDep := &mockDependentCheck{
		mockCheck:     mockCheck{name: "t0-valid-dep", tier: validation.Tier0},
		requiredTools: []tools.Type{},
	}

	// 3. Invalid Tier 0 Dependent Check (implements DependentCheck and declares a tool!)
	t0Invalid := &mockDependentCheck{
		mockCheck:     mockCheck{name: "t0-invalid", tier: validation.Tier0},
		requiredTools: []tools.Type{tools.Docker},
	}

	// 4. Valid Tier 1 Dependent Check (declaring tools is perfectly fine for Tier 1!)
	t1Valid := &mockDependentCheck{
		mockCheck:     mockCheck{name: "t1-valid-dep", tier: validation.Tier1},
		requiredTools: []tools.Type{tools.Kind},
	}

	// Test passing case
	validChecks := []validation.Check{t0Valid, t0ValidDep, t1Valid}
	if err := validateChecks(validChecks); err != nil {
		t.Errorf("Expected valid checks to pass validation, got error: %v", err)
	}

	// Test failing case (contains the invalid Tier 0 check)
	invalidChecks := []validation.Check{t0Valid, t0Invalid, t1Valid}
	if err := validateChecks(invalidChecks); err == nil {
		t.Error("Expected validation error due to Tier 0 tool dependency violation, got nil")
	}
}

func TestValidateChecks_DestructiveMustBeCleanable(t *testing.T) {
	// 1. Valid non-destructive check
	nonDestructive := &mockCheck{name: "t1-nondestructive", tier: validation.Tier1, destructive: false}

	// 2. Valid destructive check that implements CleanableCheck
	destructiveValid := &mockCleanableCheck{
		mockCheck: mockCheck{name: "t1-destructive-valid", tier: validation.Tier1, destructive: true},
	}

	// 3. Invalid destructive check that DOES NOT implement CleanableCheck
	destructiveInvalid := &mockCheck{name: "t1-destructive-invalid", tier: validation.Tier1, destructive: true}

	// Passing case
	validChecks := []validation.Check{nonDestructive, destructiveValid}
	if err := validateChecks(validChecks); err != nil {
		t.Errorf("Expected valid checks to pass validation, got error: %v", err)
	}

	// Failing case
	invalidChecks := []validation.Check{nonDestructive, destructiveValid, destructiveInvalid}
	if err := validateChecks(invalidChecks); err == nil {
		t.Error("Expected validation error due to destructive check not implementing CleanableCheck, got nil")
	}
}

func TestAllRegisteredChecksConform(t *testing.T) {
	allChecks := validation.RegisteredChecks()
	if len(allChecks) == 0 {
		t.Fatal("Expected registered checks in global registry, got 0")
	}
	if err := validateChecks(allChecks); err != nil {
		t.Fatalf("Registered check suite failed architectural validation: %v", err)
	}
}

type mockTier0Check struct {
	name  string
	runFn func(ctx context.Context, runner validation.SSHRunner) error
}

func (m *mockTier0Check) Name() string          { return m.name }
func (m *mockTier0Check) Description() string   { return "mock tier 0 gatekeeper check" }
func (m *mockTier0Check) Tier() validation.Tier { return validation.Tier0 }
func (m *mockTier0Check) Destructive() bool     { return false }
func (m *mockTier0Check) Run(ctx context.Context, runner validation.SSHRunner) error {
	if m.runFn != nil {
		return m.runFn(ctx, runner)
	}
	return nil
}

func TestRunTier0_BoundedConcurrency(t *testing.T) {
	var inFlight atomic.Int32
	var maxObserved atomic.Int32

	var checks []validation.Check
	for i := 0; i < 15; i++ {
		checks = append(checks, &mockTier0Check{
			name: fmt.Sprintf("gatekeeper-%d", i),
			runFn: func(ctx context.Context, runner validation.SSHRunner) error {
				cur := inFlight.Add(1)
				for {
					prev := maxObserved.Load()
					if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
						break
					}
				}
				time.Sleep(30 * time.Millisecond)
				inFlight.Add(-1)
				return nil
			},
		})
	}

	if err := runTier0(context.Background(), nil, validation.TargetEnvironment{}, checks, nil); err != nil {
		t.Fatalf("expected runTier0 to succeed, got: %v", err)
	}

	if maxObserved.Load() <= 1 {
		t.Errorf("expected Tier 0 checks to run concurrently (maxObserved > 1), got %d", maxObserved.Load())
	}
	if maxObserved.Load() > defaultConcurrency {
		t.Errorf("expected concurrency <= %d, got %d", defaultConcurrency, maxObserved.Load())
	}
}

func TestRunTier1_NonDestructiveBoundedConcurrency(t *testing.T) {
	var inFlight atomic.Int32
	var maxObserved atomic.Int32

	var checks []validation.Check
	for i := 0; i < 15; i++ {
		checks = append(checks, &mockTier0Check{
			name: fmt.Sprintf("tier1-nondestructive-%d", i),
			runFn: func(ctx context.Context, runner validation.SSHRunner) error {
				cur := inFlight.Add(1)
				for {
					prev := maxObserved.Load()
					if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
						break
					}
				}
				time.Sleep(30 * time.Millisecond)
				inFlight.Add(-1)
				return nil
			},
		})
	}

	if err := runTier1(context.Background(), nil, validation.TargetEnvironment{}, checks, nil); err != nil {
		t.Fatalf("expected runTier1 to succeed, got: %v", err)
	}

	if maxObserved.Load() <= 1 {
		t.Errorf("expected Tier 1 non-destructive checks to run concurrently (maxObserved > 1), got %d", maxObserved.Load())
	}
	if maxObserved.Load() > defaultConcurrency {
		t.Errorf("expected concurrency <= %d, got %d", defaultConcurrency, maxObserved.Load())
	}
}

func TestValidateConcurrency(t *testing.T) {
	for _, valid := range []int{1, 5, 9} {
		if err := validateConcurrency(valid); err != nil {
			t.Errorf("expected concurrency %d to be valid, got error: %v", valid, err)
		}
	}
	for _, invalid := range []int{-1, 0, 10, 15} {
		if err := validateConcurrency(invalid); err == nil {
			t.Errorf("expected concurrency %d to be rejected (< 1 or >= 10), got nil", invalid)
		}
	}
}

func TestRunChecksConcurrently_ContextCanceledShortCircuits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel context before running checks

	c1 := &mockCheck{name: "should-not-run-1", tier: validation.Tier0}
	c2 := &mockCheck{name: "should-not-run-2", tier: validation.Tier0}

	errs := runChecksConcurrently(ctx, nil, validation.TargetEnvironment{}, []validation.Check{c1, c2}, "Gatekeeper", nil)
	if len(errs) == 0 || !errors.Is(errors.Join(errs...), context.Canceled) {
		t.Fatalf("expected context.Canceled error, got: %v", errs)
	}
	if c1.runCalled || c2.runCalled {
		t.Errorf("expected checks to be short-circuited when ctx is already done")
	}
}
