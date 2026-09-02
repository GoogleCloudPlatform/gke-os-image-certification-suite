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
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestUtilityCheck(t *testing.T) {
	check := &utilityCheck{name: "test-util"}
	runner := &testutil.MockSSHRunner{}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.RunCmds) != 1 || runner.RunCmds[0] != "which test-util" {
		t.Errorf("Expected 'which test-util', got %v", runner.RunCmds)
	}
}
