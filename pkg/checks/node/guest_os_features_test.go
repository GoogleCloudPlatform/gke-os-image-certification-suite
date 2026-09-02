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

func TestGuestOSFeatureCheck_Success(t *testing.T) {
	check := &guestOSFeatureCheck{featureName: "UEFI_COMPATIBLE", cmd: "test -d /sys/firmware/efi"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "test -d /sys/firmware/efi" {
		t.Errorf("Unexpected command run: %v", runner.RunCmds)
	}
}

func TestGuestOSFeatureCheck_Failure(t *testing.T) {
	check := &guestOSFeatureCheck{featureName: "UEFI_COMPATIBLE", cmd: "test -d /sys/firmware/efi"}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /sys/firmware/efi": errors.New("exit status 1"),
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail")
	}
}
