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

package acceleratorutil

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestHasGoogleTPUV7x_True(t *testing.T) {
	mockOutput := `0000:00:04.0 0x1ae0 0x0076 0x120000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasV7x, err := HasGoogleTPUV7x(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasV7x {
		t.Fatalf("expected hasV7x to be true for 0x0076, got false")
	}
}

func TestHasGoogleTPUV7x_False_V6eAndV5p(t *testing.T) {
	// 0x006f is TPU v6e, 0x0062 is TPU v5p
	mockOutput := `0000:00:04.0 0x1ae0 0x006f 0x120000
0000:00:05.0 0x1ae0 0x0062 0x120000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasV7x, err := HasGoogleTPUV7x(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasV7x {
		t.Fatalf("expected hasV7x to be false for v6e (0x006f) and v5p (0x0062), got true")
	}

	// General HasGoogleTPU should still be true for v6e/v5p
	hasTPU, err := HasGoogleTPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTPU {
		t.Fatalf("expected general hasTPU to be true for v6e/v5p, got false")
	}
}

func TestHasGoogleTPU_True(t *testing.T) {
	mockOutput := `0000:00:04.0 0x1ae0 0x0076 0x120000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasTPU, err := HasGoogleTPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTPU {
		t.Fatalf("expected hasTPU to be true, got false")
	}
}

func TestHasGoogleTPU_False(t *testing.T) {
	mockOutput := `0000:00:03.0 0x1af4 0x1000 0x020000
0000:00:04.0 0x10de 0x2330 0x030200`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasTPU, err := HasGoogleTPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasTPU {
		t.Fatalf("expected hasTPU to be false, got true")
	}
}

func TestHasGoogleTPU_False_NonAcceleratorClass(t *testing.T) {
	// Google vendor ID (0x1ae0) but network class (0x020000) instead of accelerator (0x120000)
	mockOutput := `0000:00:04.0 0x1ae0 0x0076 0x020000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasTPU, err := HasGoogleTPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasTPU {
		t.Fatalf("expected hasTPU to be false for non-accelerator class, got true")
	}
}

func TestHasNvidiaGPU_True(t *testing.T) {
	mockOutput := `0000:00:04.0 0x10de 0x20b0 0x030200`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasNvidia, err := HasNvidiaGPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasNvidia {
		t.Fatalf("expected hasNvidia to be true, got false")
	}
}

func TestHasNvidiaGPU_False(t *testing.T) {
	mockOutput := `0000:00:04.0 0x1ae0 0x0076 0x120000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasNvidia, err := HasNvidiaGPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasNvidia {
		t.Fatalf("expected hasNvidia to be false, got true")
	}
}

func TestHasAMDGPU_True(t *testing.T) {
	mockOutput := `0000:00:04.0 0x1002 0x74a0 0x030000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasAMD, err := HasAMDGPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasAMD {
		t.Fatalf("expected hasAMD to be true, got false")
	}
}

func TestHasAMDGPU_False(t *testing.T) {
	mockOutput := `0000:00:04.0 0x1ae0 0x0076 0x120000`

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: []byte(mockOutput), Err: nil},
		},
	}

	hasAMD, err := HasAMDGPU(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasAMD {
		t.Fatalf("expected hasAMD to be false, got true")
	}
}

func TestGetPCIDevices_Error(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			pciScanScript: {Out: nil, Err: errors.New("ssh connection lost")},
		},
	}

	_, err := GetPCIDevices(context.Background(), runner)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
