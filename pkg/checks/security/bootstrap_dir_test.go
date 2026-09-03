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

package security

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestBootstrapDirectoryCheck_Success(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	runner := &testutil.MockSSHRunner{}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
	if len(runner.RunCmds) != 2 {
		t.Fatalf("expected 2 commands run, got %d", len(runner.RunCmds))
	}
}

func TestBootstrapDirectoryCheck_MkdirFailure(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"sudo mkdir -p /home/kubernetes/bin": errors.New("read-only file system"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when mkdir fails, got nil")
	}
}

func TestBootstrapDirectoryCheck_WriteFailure(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"sudo touch /home/kubernetes/bin/.gke_security_write_test && sudo rm -f /home/kubernetes/bin/.gke_security_write_test": errors.New("permission denied"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when writing to directory fails, got nil")
	}
}

func TestBootstrapDirectoryCheck_Cleanup(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	runner := &testutil.MockSSHRunner{}

	if err := check.Cleanup(context.Background(), runner); err != nil {
		t.Fatalf("expected cleanup success, got err: %v", err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "sudo rm -f /home/kubernetes/bin/.gke_security_write_test" {
		t.Fatalf("unexpected cleanup command: %v", runner.RunCmds)
	}
}
