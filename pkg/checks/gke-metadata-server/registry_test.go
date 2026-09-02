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

package gkemetadataserver

import (
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

func TestChecksRegistration(t *testing.T) {
	checks := validation.RegisteredChecks()
	var mdsChecks []validation.Check

	for _, c := range checks {
		if strings.HasPrefix(c.Name(), "gke-metadata-server/") {
			mdsChecks = append(mdsChecks, c)
		}
	}

	// 3 path checks (path-var-run, path-tpm-device, path-efi-vars)
	expectedCount := 3
	if len(mdsChecks) != expectedCount {
		t.Errorf("Expected %d registered checks under 'gke-metadata-server/' namespace, got %d", expectedCount, len(mdsChecks))
	}

	for _, c := range mdsChecks {
		if c.Name() == "" {
			t.Errorf("Registered check has empty Name()")
		}
		if c.Description() == "" {
			t.Errorf("Check %s has empty Description()", c.Name())
		}
	}
}
