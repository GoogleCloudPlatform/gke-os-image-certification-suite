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

package observability

import (
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

func TestObservabilityChecksRegistration(t *testing.T) {
	checks := validation.RegisteredChecks()
	var o11yChecks []validation.Check

	for _, c := range checks {
		if strings.HasPrefix(c.Name(), "observability/") {
			o11yChecks = append(o11yChecks, c)
		}
	}

	expectedCount := 16
	if len(o11yChecks) != expectedCount {
		t.Errorf("Expected %d registered checks under 'observability/' namespace, got %d", expectedCount, len(o11yChecks))
	}

	for _, c := range o11yChecks {
		if c.Name() == "" {
			t.Errorf("Registered check has empty Name()")
		}
		if c.Description() == "" {
			t.Errorf("Check %s has empty Description()", c.Name())
		}
		if c.Tier() != validation.Tier1 {
			t.Errorf("Check %s has tier %v, expected Tier1", c.Name(), c.Tier())
		}
	}
}
