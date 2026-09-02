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

func TestCiliumKernelCheck(t *testing.T) {
	check := &ciliumKernelCheck{
		configSymbol: "CONFIG_BPF_SYSCALL",
	}

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null) | grep -E '^CONFIG_BPF_SYSCALL=(y|m)$'": {
				Out: []byte("CONFIG_BPF_SYSCALL=y\n"),
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to succeed, got: %v", err)
	}
}
