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

package node

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestContainerdExistsCheck_Success(t *testing.T) {
	check := &ContainerdExistsCheck{}
	runner := &testutil.MockSSHRunner{}

	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	expectedCmds := []string{
		"which containerd",
		"test -x /usr/bin/containerd",
		"systemctl is-active containerd",
	}

	if len(runner.RunCmds) != len(expectedCmds) {
		t.Fatalf("Expected %d commands, got %d: %v", len(expectedCmds), len(runner.RunCmds), runner.RunCmds)
	}

	for i, cmd := range runner.RunCmds {
		if cmd != expectedCmds[i] {
			t.Errorf("Expected cmd %d to be %q, got %q", i, expectedCmds[i], cmd)
		}
	}
}

func TestContainerdExistsCheck_Failure_Which(t *testing.T) {
	check := &ContainerdExistsCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"which containerd": errors.New("not found"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error when containerd not in PATH, got nil")
	}
}

func TestContainerdExistsCheck_Failure_Path(t *testing.T) {
	check := &ContainerdExistsCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -x /usr/bin/containerd": errors.New("not executable"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error when containerd not at /usr/bin/containerd, got nil")
	}
}

func TestContainerdExistsCheck_Failure_Service(t *testing.T) {
	check := &ContainerdExistsCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"systemctl is-active containerd": errors.New("service inactive"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error when containerd service is inactive, got nil")
	}
}
