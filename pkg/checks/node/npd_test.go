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

func TestNpdPathCheck_Success(t *testing.T) {
	check := &npdPathCheck{path: "/my/path"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "test -r /my/path" {
		t.Errorf("Unexpected command: %v", runner.RunCmds)
	}
}

func TestNpdPathCheck_Failure(t *testing.T) {
	check := &npdPathCheck{path: "/my/path"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -r /my/path": errors.New("not readable"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail when test -r fails")
	}
}

func TestNpdServiceCheck_Success(t *testing.T) {
	check := &npdServiceCheck{service: "my-service"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "systemctl is-active my-service" {
		t.Errorf("Unexpected command: %v", runner.RunCmds)
	}
}

func TestNpdServiceCheck_Failure(t *testing.T) {
	check := &npdServiceCheck{service: "my-service"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"systemctl is-active my-service": errors.New("inactive"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail when service is not active")
	}
}
