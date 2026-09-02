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

func TestCgroupV2Check_Success(t *testing.T) {
	check := &cgroupV2Check{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /sys/fs/cgroup/": {
				Out: []byte("cgroup2fs\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCgroupV2Check_Failure(t *testing.T) {
	check := &cgroupV2Check{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -fc %T /sys/fs/cgroup/": {
				Out: []byte("tmpfs\n"),
				Err: nil,
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected error when cgroup is not v2, got nil")
	}
}
