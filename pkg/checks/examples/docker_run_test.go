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
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/examples"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestDockerRunCheck_Success(t *testing.T) {
	check := &examples.DockerRunCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"docker run --rm hello-world": {
				Out: []byte("Hello from Docker!\nThis message shows..."),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
}

func TestDockerRunCheck_Failure(t *testing.T) {
	check := &examples.DockerRunCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"docker run --rm hello-world": {
				Out: []byte("docker daemon not running"),
				Err: errors.New("exit code 1"),
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestDockerRunCheck_Metadata(t *testing.T) {
	check := &examples.DockerRunCheck{}
	if check.Name() != "examples/docker-run-hello" {
		t.Errorf("Unexpected name: %s", check.Name())
	}
	if !check.Destructive() {
		t.Errorf("Expected DockerRunCheck to be marked Destructive: true")
	}
}

func TestDockerRunCheck_Cleanup(t *testing.T) {
	check := &examples.DockerRunCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"docker rmi -f hello-world": {
				Out: []byte("Untagged: hello-world:latest\nDeleted: sha256:..."),
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
		if cmd == "docker rmi -f hello-world" {
			cleanupCalled = true
			break
		}
	}
	if !cleanupCalled {
		t.Error("Expected docker rmi -f hello-world to be called in Cleanup()")
	}
}
