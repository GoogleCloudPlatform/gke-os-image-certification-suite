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

func TestKernelVersionCheck_Success(t *testing.T) {
	check := &kernelVersionCheck{}
	cases := []string{
		"6.8.0-1042-gke\n",
		"6.8.0\n",
		"6.12.55+\n",
		"6.12.94+\n",
	}

	for _, tc := range cases {
		runner := &testutil.MockSSHRunner{
			CombinedOutputResult: map[string]testutil.CombinedOutputVal{
				"uname -r": {
					Out: []byte(tc),
					Err: nil,
				},
			},
		}
		err := check.Run(context.Background(), runner)
		if err != nil {
			t.Fatalf("Expected check to pass for kernel version %q, but got error: %v", tc, err)
		}
	}
}

func TestKernelVersionCheck_Failure(t *testing.T) {
	check := &kernelVersionCheck{}
	cases := []string{
		"5.15.0-1084-gke\n",
		"6.1.141+\n",
		"6.6.72+\n",
		"4.19.0\n",
	}

	for _, tc := range cases {
		runner := &testutil.MockSSHRunner{
			CombinedOutputResult: map[string]testutil.CombinedOutputVal{
				"uname -r": {
					Out: []byte(tc),
					Err: nil,
				},
			},
		}
		err := check.Run(context.Background(), runner)
		if err == nil {
			t.Fatalf("Expected check to fail for kernel version %q, but got no error", tc)
		}
	}
}
