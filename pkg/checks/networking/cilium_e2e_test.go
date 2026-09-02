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

package networking

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestCiliumDatapathCheck_Metadata(t *testing.T) {
	check := &CiliumDatapathCheck{}
	if check.Name() != "networking/cilium-dataplane-e2e" {
		t.Errorf("Unexpected check name: %s", check.Name())
	}
	if check.Tier() != validation.Tier1 {
		t.Errorf("Expected Tier1 check, got %v", check.Tier())
	}
	if !check.Destructive() {
		t.Errorf("Expected Destructive to be true")
	}

	// Verify it implements CleanableCheck
	if _, ok := any(check).(validation.CleanableCheck); !ok {
		t.Errorf("Expected CiliumDatapathCheck to implement validation.CleanableCheck")
	}

	// Verify it implements ConstrainedCheck
	if _, ok := any(check).(validation.ConstrainedCheck); !ok {
		t.Errorf("Expected CiliumDatapathCheck to implement validation.ConstrainedCheck")
	}

	required := check.RequiredTools()
	expectedTools := map[tools.Type]bool{
		tools.Docker:  true,
		tools.Kind:    true,
		tools.Kubectl: true,
		tools.Cilium:  true,
	}
	for _, tool := range required {
		delete(expectedTools, tool)
	}
	if len(expectedTools) > 0 {
		t.Errorf("Missing expected required tools: %v", expectedTools)
	}
}

func TestCiliumDatapathCheck_Cleanup(t *testing.T) {
	check := &CiliumDatapathCheck{}
	deleteCmd := `export PATH="$HOME/.local/bin:$PATH"; kind delete cluster --name gke-os-cert-cilium`
	rmCmd := `rm -f /tmp/kind-cilium-config.yaml /tmp/cilium-values.yaml`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			deleteCmd: {
				Out: []byte("Deleting cluster 'gke-os-cert-cilium'..."),
				Err: nil,
			},
		},
		RunErrMap: map[string]error{
			rmCmd: nil,
		},
	}

	err := check.Cleanup(context.Background(), runner)
	if err != nil {
		t.Fatalf("Expected cleanup to succeed, got: %v", err)
	}

	deleteCalled := false
	for _, cmd := range runner.CombinedOutputCmds {
		if cmd == deleteCmd {
			deleteCalled = true
			break
		}
	}
	if !deleteCalled {
		t.Errorf("Expected kind delete cluster command to be invoked during Cleanup()")
	}

	rmCalled := false
	for _, cmd := range runner.RunCmds {
		if cmd == rmCmd {
			rmCalled = true
			break
		}
	}
	if !rmCalled {
		t.Errorf("Expected rm temporary files command to be invoked during Cleanup()")
	}
}

func TestCiliumDatapathCheck_Success(t *testing.T) {
	check := &CiliumDatapathCheck{
		CiliumVersion: "1.19.4",
	}

	createCmd := `export PATH="$HOME/.local/bin:$PATH"; kind create cluster --name gke-os-cert-cilium --config /tmp/kind-cilium-config.yaml --wait 0s`
	installCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium install --version 1.19.4 --values /tmp/cilium-values.yaml --wait=false`
	statusCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium status --wait --wait-duration 3m`
	testCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium connectivity test --test '!pod-to-world' --timeout 20m`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			createCmd: {
				Out: []byte("Creating cluster 'gke-os-cert-cilium'... Done!"),
				Err: nil,
			},
			installCmd: {
				Out: []byte("ℹ️  Installing Cilium..."),
				Err: nil,
			},
			statusCmd: {
				Out: []byte("    /¯¯\\\n /¯¯\\__/¯¯\\    Cilium:             OK\n \\__/\\__/      NodeHandler:        OK"),
				Err: nil,
			},
			testCmd: {
				Out: []byte("✅ All 12 tests successful!"),
				Err: nil,
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Expected check to succeed, got: %v", err)
	}
}

func TestCiliumDatapathCheck_CreateClusterFailure(t *testing.T) {
	check := &CiliumDatapathCheck{
		CiliumVersion: "1.19.4",
	}
	createCmd := `export PATH="$HOME/.local/bin:$PATH"; kind create cluster --name gke-os-cert-cilium --config /tmp/kind-cilium-config.yaml --wait 0s`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			createCmd: {
				Out: []byte("failed to start node daemon"),
				Err: errors.New("exit status 1"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatalf("Expected check to fail when cluster creation fails")
	}
	if !strings.Contains(err.Error(), "failed to create Kind cluster") {
		t.Errorf("Expected error to mention cluster creation failure, got: %v", err)
	}
}

func TestCiliumDatapathCheck_StatusFailure(t *testing.T) {
	check := &CiliumDatapathCheck{
		CiliumVersion: "1.19.4",
	}
	createCmd := `export PATH="$HOME/.local/bin:$PATH"; kind create cluster --name gke-os-cert-cilium --config /tmp/kind-cilium-config.yaml --wait 0s`
	installCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium install --version 1.19.4 --values /tmp/cilium-values.yaml --wait=false`
	statusCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium status --wait --wait-duration 3m`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			createCmd:  {Out: []byte("Created"), Err: nil},
			installCmd: {Out: []byte("Installed"), Err: nil},
			statusCmd: {
				Out: []byte("Error: timed out waiting for condition"),
				Err: errors.New("exit status 1"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatalf("Expected check to fail when cilium status fails")
	}
	if !strings.Contains(err.Error(), "cilium failed to reach healthy status") {
		t.Errorf("Expected error to mention health status failure, got: %v", err)
	}
}

func TestCiliumDatapathCheck_ConnectivityFailure(t *testing.T) {
	check := &CiliumDatapathCheck{
		CiliumVersion: "1.19.4",
	}
	createCmd := `export PATH="$HOME/.local/bin:$PATH"; kind create cluster --name gke-os-cert-cilium --config /tmp/kind-cilium-config.yaml --wait 0s`
	installCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium install --version 1.19.4 --values /tmp/cilium-values.yaml --wait=false`
	statusCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium status --wait --wait-duration 3m`
	testCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium connectivity test --test '!pod-to-world' --timeout 20m`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			createCmd:  {Out: []byte("Created"), Err: nil},
			installCmd: {Out: []byte("Installed"), Err: nil},
			statusCmd:  {Out: []byte("OK"), Err: nil},
			testCmd: {
				Out: []byte("❌ [FAIL] pod-to-pod: connection timed out"),
				Err: errors.New("exit status 1"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatalf("Expected check to fail when connectivity test fails")
	}
	if !strings.Contains(err.Error(), "cilium connectivity test suite failed") {
		t.Errorf("Expected error to mention connectivity test failure, got: %v", err)
	}
}

func TestCiliumDatapathCheck_CustomGKEVersion(t *testing.T) {
	check := &CiliumDatapathCheck{
		CiliumVersion: "1.17.6",
	}
	createCmd := `export PATH="$HOME/.local/bin:$PATH"; kind create cluster --name gke-os-cert-cilium --config /tmp/kind-cilium-config.yaml --wait 0s`
	// GKE 1.34 maps to Cilium 1.17.6
	installCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium install --version 1.17.6 --values /tmp/cilium-values.yaml --wait=false`
	statusCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium status --wait --wait-duration 3m`
	testCmd := `export PATH="$HOME/.local/bin:$PATH"; cilium connectivity test --test '!pod-to-world' --timeout 20m`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			createCmd:  {Out: []byte("Created"), Err: nil},
			installCmd: {Out: []byte("Installed"), Err: nil},
			statusCmd:  {Out: []byte("OK"), Err: nil},
			testCmd:    {Out: []byte("✅ All tests passed!"), Err: nil},
		},
	}

	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Expected check to succeed with GKE 1.34 context, got: %v", err)
	}
}

func TestCiliumDatapathCheck_Constraints(t *testing.T) {
	ciliumChecks := []validation.Check{
		&CiliumDatapathCheck{
			CiliumVersion: "1.17.6",
			constraints: validation.Constraint{
				MinGKEVersion: "1.34.0",
				MaxGKEVersion: "1.34.99",
			},
		},
		&CiliumDatapathCheck{
			CiliumVersion: "1.18.4",
			constraints: validation.Constraint{
				MinGKEVersion: "1.35.0",
				MaxGKEVersion: "1.35.99",
			},
		},
		&CiliumDatapathCheck{
			CiliumVersion: "1.19.4",
			constraints: validation.Constraint{
				MinGKEVersion: "1.36.0",
			},
		},
	}

	tests := []struct {
		name          string
		gkeVer        utils.SemVer
		expectedCount int
	}{
		{
			name:          "GKE 1.34 matches 1 check (1.34)",
			gkeVer:        utils.SemVer{Major: 1, Minor: 34, Patch: 2},
			expectedCount: 1,
		},
		{
			name:          "GKE 1.35 matches 1 check (1.35)",
			gkeVer:        utils.SemVer{Major: 1, Minor: 35, Patch: 0},
			expectedCount: 1,
		},
		{
			name:          "GKE 1.36 matches 1 check (1.36+)",
			gkeVer:        utils.SemVer{Major: 1, Minor: 36, Patch: 1},
			expectedCount: 1,
		},
		{
			name:          "GKE 1.37 matches 1 check (1.36+)",
			gkeVer:        utils.SemVer{Major: 1, Minor: 37, Patch: 0},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchCount := 0
			env := validation.TargetEnvironment{
				OSID:       "ubuntu",
				GKEVersion: tt.gkeVer,
				HasVersion: true,
			}
			for _, c := range ciliumChecks {
				applicable, _ := validation.IsApplicable(c, env)
				if applicable {
					matchCount++
				}
			}
			if matchCount != tt.expectedCount {
				t.Errorf("For GKE %v, expected %d applicable checks, got %d", tt.gkeVer, tt.expectedCount, matchCount)
			}
		})
	}
}
