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

package examples_test

import (
	"context"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/examples"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestKindClusterCheck_Success(t *testing.T) {
	check := &examples.KindClusterCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"kind create cluster --name cert-validation": {
				Out: []byte("Creating cluster... Done!"),
				Err: nil,
			},
			"kubectl cluster-info": {
				Out: []byte("Kubernetes control plane is running at..."),
				Err: nil,
			},
			"kubectl get nodes": {
				Out: []byte("kind-control-plane Ready..."),
				Err: nil,
			},
			"kind delete cluster --name cert-validation": {
				Out: []byte("Deleting cluster..."),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
}

func TestKindClusterCheck_Metadata(t *testing.T) {
	check := &examples.KindClusterCheck{}
	if check.Name() != "examples/kind-cluster-up" {
		t.Errorf("Unexpected name: %s", check.Name())
	}
	if !check.Destructive() {
		t.Errorf("Expected KindClusterCheck to be marked Destructive: true")
	}
}

func TestKindClusterCheck_Cleanup(t *testing.T) {
	check := &examples.KindClusterCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"kind delete cluster --name cert-validation": {
				Out: []byte("Deleting cluster..."),
				Err: nil,
			},
		},
	}
	err := check.Cleanup(context.Background(), runner)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	cleanupCalled := false
	for _, cmd := range runner.CombinedOutputCmds {
		if cmd == "kind delete cluster --name cert-validation" {
			cleanupCalled = true
			break
		}
	}
	if !cleanupCalled {
		t.Error("Expected kind delete cluster to be called in Cleanup()")
	}
}

