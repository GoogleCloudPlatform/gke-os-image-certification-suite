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

package accelerator

import (
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"testing"
)

func TestRegisteredChecksCount(t *testing.T) {
	all := validation.RegisteredChecks()
	expected := 15 // 1 gpu-maintenance-handler + 5 tpu-v7x + 7 tpu-sysctl-networking + 1 tpu-required-binaries + 1 tpu-absent-vbar-agent
	if len(all) != expected {
		t.Errorf("Expected %d registered checks in accelerator package, got %d", expected, len(all))
	}
}
