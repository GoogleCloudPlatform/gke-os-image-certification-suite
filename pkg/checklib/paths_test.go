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

package checklib

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestPathExistenceCheck_Wildcard(t *testing.T) {
	check := &PathExistenceCheck{Component: "node", Pattern: "/sys/class/net/*/mtu", CheckName: "nic-mtu"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "ls /sys/class/net/*/mtu" {
		t.Errorf("Unexpected command: %v", runner.RunCmds)
	}
	if check.Name() != "node/exists-nic-mtu" {
		t.Errorf("Unexpected name: %s", check.Name())
	}
}

func TestPathExistenceCheck_Success(t *testing.T) {
	check := &PathExistenceCheck{Component: "node", Pattern: "/etc/ssh/sshd_config", CheckName: "sshd-config"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "ls /etc/ssh/sshd_config" {
		t.Errorf("Unexpected command: %v", runner.RunCmds)
	}
}

func TestPathExistenceCheck_Failure(t *testing.T) {
	check := &PathExistenceCheck{Component: "node", Pattern: "/etc/ssh/sshd_config", CheckName: "sshd-config"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"ls /etc/ssh/sshd_config": errors.New("ls: no such file or directory"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error due to missing path, got nil")
	}
}
