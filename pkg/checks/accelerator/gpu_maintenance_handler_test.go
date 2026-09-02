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

package accelerator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type mockRunner struct {
	runFunc            func(cmd string) error
	combinedOutputFunc func(cmd string) ([]byte, error)
}

func (m *mockRunner) Run(ctx context.Context, cmd string) error {
	if m.runFunc != nil {
		return m.runFunc(cmd)
	}
	return nil
}

func (m *mockRunner) CombinedOutput(ctx context.Context, cmd string) ([]byte, error) {
	if m.combinedOutputFunc != nil {
		return m.combinedOutputFunc(cmd)
	}
	return nil, nil
}

func TestContainerCertsAccessCheck_CtrSuccess(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "readlink") {
				return []byte("/etc/static/ssl/certs/ca-certificates.crt\n/nix/store/abc-certs/ca-certificates.crt"), nil
			}
			return nil, fmt.Errorf("unexpected combinedOutput command: %s", cmd)
		},
		runFunc: func(cmd string) error {
			if cmd == "test -d /etc/static" || cmd == "test -d /nix/store" {
				return nil
			}
			if cmd == "which ctr" || cmd == "ctr images list" {
				return nil
			}
			if cmd == "ctr images pull docker.io/library/alpine:latest" {
				return nil
			}
			if cmd == "ctr images rm docker.io/library/alpine:latest" {
				return nil
			}
			if strings.HasPrefix(cmd, "ctr run --rm") && strings.Contains(cmd, "test -f /etc/ssl/certs/ca-certificates.crt") {
				if !strings.Contains(cmd, "src=/etc/ssl/certs") || !strings.Contains(cmd, "src=/etc/static") || !strings.Contains(cmd, "src=/nix/store") {
					return fmt.Errorf("missing expected mount points in ctr command: %s", cmd)
				}
				return nil
			}
			return fmt.Errorf("unexpected run command: %s", cmd)
		},
	}
	check := &containerCertsAccessCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
}

func TestContainerCertsAccessCheck_MissingCtr(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if cmd == "which ctr" {
				return errors.New("ctr not found")
			}
			return fmt.Errorf("unexpected run command: %s", cmd)
		},
	}
	check := &containerCertsAccessCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure due to missing ctr, got nil")
	} else if !strings.Contains(err.Error(), "containerd CLI is required") {
		t.Fatalf("expected missing ctr error message, got: %v", err)
	}
}

func TestContainerCertsAccessCheck_CtrFailure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(""), nil
		},
		runFunc: func(cmd string) error {
			if cmd == "which ctr" {
				return nil
			}
			if cmd == "ctr images pull docker.io/library/alpine:latest" {
				return nil
			}
			if cmd == "ctr images rm docker.io/library/alpine:latest" {
				return nil
			}
			if strings.HasPrefix(cmd, "ctr run --rm") {
				return errors.New("container execution error")
			}
			return nil
		},
	}
	check := &containerCertsAccessCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure due to ctr execution error, got nil")
	} else if !strings.Contains(err.Error(), "failed to verify certs accessibility via containerd (ctr)") {
		t.Fatalf("expected ctr error message, got: %v", err)
	}
}

func TestCheckMetadata(t *testing.T) {
	certsAccess := &containerCertsAccessCheck{}
	if certsAccess.Name() != "gpu-maintenance-handler/container-certs-access" || certsAccess.Tier() != validation.Tier1 || certsAccess.Destructive() != true {
		t.Errorf("unexpected certsAccess check metadata: Name=%s, Tier=%v, Destructive=%v", certsAccess.Name(), certsAccess.Tier(), certsAccess.Destructive())
	}
	if _, ok := any(certsAccess).(validation.CleanableCheck); !ok {
		t.Errorf("expected containerCertsAccessCheck to implement CleanableCheck")
	}
}

func TestContainerCertsAccessCheck_Cleanup(t *testing.T) {
	var executedCmds []string
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			executedCmds = append(executedCmds, cmd)
			return nil
		},
	}
	check := &containerCertsAccessCheck{}
	if err := check.Cleanup(context.Background(), runner); err != nil {
		t.Fatalf("unexpected cleanup error: %v", err)
	}

	foundRm := false
	for _, cmd := range executedCmds {
		if strings.Contains(cmd, "images rm") && strings.Contains(cmd, "alpine:latest") {
			foundRm = true
			break
		}
	}
	if !foundRm {
		t.Errorf("expected cleanup to remove alpine image, got executed commands: %v", executedCmds)
	}
}

func TestContainerCertsAccessCheck_Cleanup_Error(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "images rm") {
				return errors.New("image is in use")
			}
			return nil
		},
	}
	check := &containerCertsAccessCheck{}
	if err := check.Cleanup(context.Background(), runner); err == nil {
		t.Errorf("expected cleanup error when rm fails, got nil")
	}
}
