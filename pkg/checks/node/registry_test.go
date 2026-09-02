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
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"testing"
)

func TestRegisteredChecksCount(t *testing.T) {
	all := validation.RegisteredChecks()
	expected := 116 // 52 utilities + 42 configs (2 wildcard + 39 permissions + 1 CA readability) + 1 socket + 7 modules + 1 cgroup + 1 containerd + 3 npd + 1 glibc + 4 guest OS features + 3 guest agents + 1 kernel version
	if len(all) != expected {
		t.Errorf("Expected %d registered checks, got %d", expected, len(all))
	}
}
