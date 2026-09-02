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

package gkemetadataserver

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestVerifyVarRun_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"sudo findmnt -o OPTIONS -n -T /var/run": {
				Out: []byte("rw,nosuid,nodev,noexec,relatime,size=1633516k,mode=755\n"),
				Err: nil,
			},
		},
	}
	if err := verifyVarRun(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyVarRun_Missing(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"sudo test -d /var/run": errors.New("not found"),
		},
	}
	if err := verifyVarRun(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because /var/run is missing, but it passed")
	}
}

func TestVerifyVarRun_ReadOnly(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"sudo findmnt -o OPTIONS -n -T /var/run": {
				Out: []byte("ro,nosuid,nodev,noexec,relatime,size=1633516k,mode=755\n"),
				Err: nil,
			},
		},
	}
	if err := verifyVarRun(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because /var/run is read-only, but it passed")
	}
}

func TestVerifyTPMDevice_NotEnabled(t *testing.T) {
	// Not shielded VM (sysfs path doesn't exist)
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/class/tpm/tpm0": errors.New("no such file or directory"),
		},
	}
	if err := verifyTPMDevice(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to skip/pass when TPM is not enabled, got: %v", err)
	}
}

func TestVerifyTPMDevice_Enabled_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/class/tpm/tpm0": nil,
			"test -c /dev/tpm0":           nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%a' /dev/tpm0": {
				Out: []byte("660\n"),
				Err: nil,
			},
		},
	}
	if err := verifyTPMDevice(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyTPMDevice_Enabled_DeviceMissing(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/class/tpm/tpm0": nil,
			"test -c /dev/tpm0":           errors.New("not found"),
		},
	}
	if err := verifyTPMDevice(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because /dev/tpm0 is missing, but it passed")
	}
}

func TestVerifyTPMDevice_Enabled_WrongPerms(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/class/tpm/tpm0": nil,
			"test -c /dev/tpm0":           nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%a' /dev/tpm0": {
				Out: []byte("400\n"), // Only read, missing write
				Err: nil,
			},
		},
	}
	if err := verifyTPMDevice(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because of wrong permissions, but it passed")
	}
}

func TestVerifyTPMDevice_Enabled_InvalidPermsFormat(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/class/tpm/tpm0": nil,
			"test -c /dev/tpm0":           nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%a' /dev/tpm0": {
				Out: []byte("invalid\n"),
				Err: nil,
			},
		},
	}
	if err := verifyTPMDevice(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because of invalid permissions format, but it passed")
	}
}

func TestVerifyEFIVars_NotUEFI(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi": errors.New("no such directory"),
		},
	}
	if err := verifyEFIVars(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to skip/pass when not UEFI boot, got: %v", err)
	}
}

func TestVerifyEFIVars_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi":          nil,
			"test -d /sys/firmware/efi/efivars/": nil,
			"test -r /sys/firmware/efi/efivars/": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -f -c '%T' /sys/firmware/efi/efivars/": {
				Out: []byte("efivarfs\n"),
				Err: nil,
			},
		},
	}
	if err := verifyEFIVars(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyEFIVars_DirMissing(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi":          nil,
			"test -d /sys/firmware/efi/efivars/": errors.New("not found"),
		},
	}
	if err := verifyEFIVars(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because efivars dir is missing, but it passed")
	}
}

func TestVerifyEFIVars_NotReadable(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi":          nil,
			"test -d /sys/firmware/efi/efivars/": nil,
			"test -r /sys/firmware/efi/efivars/": errors.New("not readable"),
		},
	}
	if err := verifyEFIVars(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because efivars dir is not readable, but it passed")
	}
}

func TestVerifyEFIVars_WrongMountType(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi":          nil,
			"test -d /sys/firmware/efi/efivars/": nil,
			"test -r /sys/firmware/efi/efivars/": nil,
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -f -c '%T' /sys/firmware/efi/efivars/": {
				Out: []byte("sysfs\n"),
				Err: nil,
			},
		},
	}
	if err := verifyEFIVars(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because filesystem type is not efivarfs, but it passed")
	}
}
