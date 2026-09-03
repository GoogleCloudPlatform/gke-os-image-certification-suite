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

func TestDynamicBinaryExecutionCheck_Success(t *testing.T) {
	check := &dynamicBinaryExecutionCheck{}
	runner := &testutil.MockSSHRunner{} // all commands succeed

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success when dynamic linker exists, got: %v", err)
	}
}

func TestDynamicBinaryExecutionCheck_MissingLinker(t *testing.T) {
	check := &dynamicBinaryExecutionCheck{}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -e /lib64/ld-linux-x86-64.so.2 || test -e /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 || test -e /lib/ld-linux-x86-64.so.2": errors.New("not found"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when dynamic linker is missing, got nil")
	}
}
