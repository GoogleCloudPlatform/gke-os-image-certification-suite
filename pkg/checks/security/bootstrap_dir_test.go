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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestBootstrapDirectoryCheck_TierAndDestructive(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	if check.Tier() != validation.Tier0 {
		t.Errorf("expected Tier0, got %v", check.Tier())
	}
	if check.Destructive() {
		t.Errorf("expected Destructive to be false, got true")
	}
}

func TestBootstrapDirectoryCheck_Success(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	runner := &testutil.MockSSHRunner{}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
	if len(runner.RunCmds) != 1 {
		t.Fatalf("expected 1 command run, got %d", len(runner.RunCmds))
	}
}

func TestBootstrapDirectoryCheck_Failure(t *testing.T) {
	check := &bootstrapDirectoryCheck{}
	cmd := `p="/home/kubernetes/bin"; while [ ! -d "$p" ] && [ "$p" != "/" ]; do p=$(dirname "$p"); done; test -d "$p" && (test -w "$p" || sudo test -w "$p") && ! findmnt -no OPTIONS -T "$p" | grep -qw "ro"`
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			cmd: errors.New("read-only file system"),
		},
	}

	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatalf("expected error when command fails, got nil")
	}
}
