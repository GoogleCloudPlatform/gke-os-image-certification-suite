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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestPathExistenceCheck_Wildcard(t *testing.T) {
	check := &pathExistenceCheck{pattern: "/sys/class/net/*/mtu", name: "nic-mtu"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "ls /sys/class/net/*/mtu" {
		t.Errorf("Unexpected command: %v", runner.RunCmds)
	}
}

func TestPathPermissionCheck_Success(t *testing.T) {
	check := &pathPermissionCheck{path: "/etc/foo", permissions: "drwxr-xr-x"}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /etc/foo": {
				Out: []byte("drwxr-xr-x\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPathPermissionCheck_Mismatch(t *testing.T) {
	check := &pathPermissionCheck{path: "/etc/foo", permissions: "drwxr-xr-x"}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /etc/foo": {
				Out: []byte("drwx------\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error due to permissions mismatch, got nil")
	}
}

func TestPathPermissionCheck_Symlink_Success(t *testing.T) {
	check := &pathPermissionCheck{
		path:              "/etc/resolv.conf",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "-rw-r--r--",
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /etc/resolv.conf": {
				Out: []byte("lrwxrwxrwx\n"),
				Err: nil,
			},
			"stat -L -c '%A' /etc/resolv.conf": {
				Out: []byte("-rw-r--r--\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Expected symlink check to pass, got error: %v", err)
	}
}

func TestPathPermissionCheck_Symlink_BrokenTarget(t *testing.T) {
	check := &pathPermissionCheck{
		path:              "/etc/resolv.conf",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "-rw-r--r--",
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /etc/resolv.conf": {
				Out: []byte("lrwxrwxrwx\n"),
				Err: nil,
			},
			"stat -L -c '%A' /etc/resolv.conf": {
				Out: []byte(""),
				Err: errors.New("stat: no such file or directory"),
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error due to broken symlink target, got nil")
	}
}

func TestPathPermissionCheck_Symlink_TargetMismatch(t *testing.T) {
	check := &pathPermissionCheck{
		path:              "/etc/resolv.conf",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "-rw-r--r--",
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /etc/resolv.conf": {
				Out: []byte("lrwxrwxrwx\n"),
				Err: nil,
			},
			"stat -L -c '%A' /etc/resolv.conf": {
				Out: []byte("-r--------\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error due to symlink target permissions mismatch, got nil")
	}
}

func TestFileReadabilityCheck_Success(t *testing.T) {
	check := &fileReadabilityCheck{path: "/etc/os-release", tier: validation.Tier0}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /etc/os-release": {
				Out: []byte("NAME=\"Container-Optimized OS\"\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFileReadabilityCheck_Empty(t *testing.T) {
	check := &fileReadabilityCheck{path: "/etc/os-release", tier: validation.Tier0}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /etc/os-release": {
				Out: []byte("  \n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error for empty file, got nil")
	}
}

func TestFileReadabilityCheck_Error(t *testing.T) {
	check := &fileReadabilityCheck{path: "/etc/os-release", tier: validation.Tier0}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"cat /etc/os-release": {
				Out: nil,
				Err: errors.New("cat: /etc/os-release: Permission denied"),
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error for unreadable file, got nil")
	}
}

func TestPathExistenceCheck_Success(t *testing.T) {
	check := &pathExistenceCheck{pattern: "/etc/ssh/sshd_config", name: "sshd-config"}
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
	check := &pathExistenceCheck{pattern: "/etc/ssh/sshd_config", name: "sshd-config"}
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
func TestPathPermissionCheck_PermissiveSuperset(t *testing.T) {
	tests := []struct {
		name      string
		expected  string
		actual    string
		expectErr bool
	}{
		{"exact match", "crw--w----", "crw--w----", false},
		{"higher group read permissions", "crw--w----", "crw-rw----", false}, // GKE COS / GKE Ubuntu 24.04
		{"insufficient group write permissions", "crw--w----", "crw-------", true},
		{"completely mismatched permissions", "-rwxr-xr-x", "drwx-----T", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := &pathPermissionCheck{
				path:        "/dev/ttyS0",
				permissions: tc.expected,
			}
			runner := &testutil.MockSSHRunner{
				CombinedOutputResult: map[string]testutil.CombinedOutputVal{
					"stat -c '%A' /dev/ttyS0": {
						Out: []byte(tc.actual + "\n"),
					},
				},
			}

			err := check.Run(context.Background(), runner)
			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected failure for actual %q with expected %q, but passed", tc.actual, tc.expected)
				}
			} else {
				if err != nil {
					t.Errorf("Expected success for actual %q with expected %q, but failed: %v", tc.actual, tc.expected, err)
				}
			}
		})
	}
}

func TestSocketExistsCheck_Success(t *testing.T) {
	check := &socketExistsCheck{path: "/run/sock"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -S /run/sock": nil,
		},
	}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected success, got err: %v", err)
	}
	if check.Name() != "node/exists-socket-/run/sock" {
		t.Errorf("Unexpected name: %s", check.Name())
	}
}

func TestSocketExistsCheck_Failure(t *testing.T) {
	check := &socketExistsCheck{path: "/run/sock"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -S /run/sock": errors.New("test failed"),
		},
	}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected failure, got nil")
	}
}
