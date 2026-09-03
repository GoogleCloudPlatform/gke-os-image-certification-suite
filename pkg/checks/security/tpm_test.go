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

func TestTpmDeviceCheck_Success_StandardGce(t *testing.T) {
	check := &tpmDeviceCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -c /dev/tpmrm0": errors.New("not found"),
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /dev/tpm0": {
				Out: []byte("crw-------\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success with crw-------, got err: %v", err)
	}
}

func TestTpmDeviceCheck_Success_TssGroup(t *testing.T) {
	check := &tpmDeviceCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -c /dev/tpmrm0": errors.New("not found"),
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /dev/tpm0": {
				Out: []byte("crw-rw----\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success with crw-rw----, got err: %v", err)
	}
}

func TestTpmDeviceCheck_MissingDriver(t *testing.T) {
	check := &tpmDeviceCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"ls /sys/class/tpm/tpm0": errors.New("no such file or directory"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when TPM driver is missing, got nil")
	}
}

func TestTpmDeviceCheck_MissingDevices(t *testing.T) {
	check := &tpmDeviceCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -c /dev/tpm0":   errors.New("not found"),
			"test -c /dev/tpmrm0": errors.New("not found"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when no TPM character devices exist, got nil")
	}
}

func TestTpmDeviceCheck_WrongPermissions(t *testing.T) {
	check := &tpmDeviceCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /dev/tpm0": {
				Out: []byte("crw-r--r--\n"),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when TPM device permissions are wrong, got nil")
	}
}
