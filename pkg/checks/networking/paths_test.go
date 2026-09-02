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
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestVirtualMountCheck_Success(t *testing.T) {
	check := &virtualMountCheck{
		path:          "/sys/fs/bpf",
		expectedTypes: []string{"bpf", "bpf_fs"},
	}

	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/fs/bpf":                             nil,
			"test -w /sys/fs/bpf || sudo test -w /sys/fs/bpf": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /sys/fs/bpf": {
				Out: []byte("bpf\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected mount check to pass, got error: %v", err)
	}
}

func TestVirtualMountCheck_BPF_FS_Synonym(t *testing.T) {
	check := &virtualMountCheck{
		path:          "/sys/fs/bpf",
		expectedTypes: []string{"bpf", "bpf_fs"},
	}

	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/fs/bpf":                             nil,
			"test -w /sys/fs/bpf || sudo test -w /sys/fs/bpf": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /sys/fs/bpf": {
				Out: []byte("bpf_fs\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected mount check to pass for bpf_fs synonym, got error: %v", err)
	}
}

func TestVirtualMountCheck_Proc_Success(t *testing.T) {
	check := &virtualMountCheck{
		path:          "/proc",
		expectedTypes: []string{"proc", "procfs"},
	}

	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /proc":                       nil,
			"test -w /proc || sudo test -w /proc": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /proc": {
				Out: []byte("proc\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected proc mount check to pass, got error: %v", err)
	}
}

func TestVirtualMountCheck_Failure(t *testing.T) {
	check := &virtualMountCheck{
		path:          "/sys/fs/bpf",
		expectedTypes: []string{"bpf", "bpf_fs"},
	}

	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/fs/bpf": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /sys/fs/bpf": {
				Out: []byte("tmpfs\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected mount check to fail when filesystem type is tmpfs, got nil")
	}
}

func TestPathPermissionCheck_Success(t *testing.T) {
	check := &pathPermissionCheck{
		path:        "/opt/",
		permissions: "drwxr-xr-x",
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /opt/": {
				Out: []byte("drwxr-xr-x\n"),
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected path check to pass, got error: %v", err)
	}
}

func TestPathPermissionCheck_Failure(t *testing.T) {
	check := &pathPermissionCheck{
		path:        "/opt/",
		permissions: "drwxr-xr-x",
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /opt/": {
				Out: []byte("dr-xr-xr-x\n"),
			},
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected path check to fail when permissions do not match, got nil")
	}
}

func TestPathPermissionCheck_Symlink(t *testing.T) {
	check := &pathPermissionCheck{
		path:              "/var/run",
		permissions:       "lrwxrwxrwx",
		targetPermissions: "drwxr-xr-x",
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /var/run": {
				Out: []byte("lrwxrwxrwx\n"),
			},
			"stat -L -c '%A' /var/run": {
				Out: []byte("drwxr-xr-x\n"),
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected symlink check to pass, got error: %v", err)
	}
}

func TestCheckNames(t *testing.T) {
	vm := &virtualMountCheck{path: "/sys/fs/bpf"}
	if got := vm.Name(); got != "networking/mount-/sys/fs/bpf" {
		t.Errorf("virtualMountCheck.Name() = %q, want %q", got, "networking/mount-/sys/fs/bpf")
	}

	pa := &pathPermissionCheck{path: "/home/"}
	if got := pa.Name(); got != "networking/permission-/home/" {
		t.Errorf("pathPermissionCheck.Name() = %q, want %q", got, "networking/permission-/home/")
	}
}
