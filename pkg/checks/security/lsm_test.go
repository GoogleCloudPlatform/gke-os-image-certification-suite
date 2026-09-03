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
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestRegisteredLsmPathAccess_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{} // all commands succeed

	for _, check := range RegisteredLsmPathAccess {
		if err := check.Run(context.Background(), runner); err != nil {
			t.Errorf("expected success for check %s, got: %v", check.Name(), err)
		}
	}
}

func TestLsmPathAccessCheck_Failure(t *testing.T) {
	check := RegisteredLsmPathAccess[0] // /home/kubernetes/bin
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"if [ -d /home/kubernetes/bin ]; then test -w /home/kubernetes/bin; else sudo test -d /home && sudo test -w /home; fi": errors.New("permission denied"),
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"sestatus 2>/dev/null || true": {
				Out: []byte("SELinux status: enabled\nCurrent mode: enforcing\n"),
			},
			"dmesg 2>/dev/null | grep -iE 'apparmor|selinux|avc|denied' | tail -n 10 || grep -iE 'apparmor|selinux|avc|denied' /var/log/audit/audit.log 2>/dev/null | tail -n 10 || echo 'No LSM audit denial entries found in kernel logs.'": {
				Out: []byte("type=AVC msg=audit(1723330000.123:45): avc: denied { write } for pid=1234 comm=\"kubelet\" path=\"/home/kubernetes/bin/test_file\""),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatalf("expected error when path permission fails, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "/home/kubernetes/bin (READ/WRITE)") {
		t.Errorf("expected error message to contain failed path details, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "SELinux: SELinux status: enabled") {
		t.Errorf("expected error message to contain LSM status, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "avc: denied") {
		t.Errorf("expected error message to contain audit log denial entry, got: %s", errMsg)
	}
}
