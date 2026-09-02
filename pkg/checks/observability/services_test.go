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
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func findCheck(name string) validation.Check {
	for _, c := range validation.RegisteredChecks() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func TestServiceSystemdJournald_Active(t *testing.T) {
	c := findCheck("observability/service-systemd-journald")
	if c == nil {
		t.Fatal("Check observability/service-systemd-journald not registered")
	}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"systemctl is-active systemd-journald": nil,
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestServiceSystemdJournald_Inactive(t *testing.T) {
	c := findCheck("observability/service-systemd-journald")
	if c == nil {
		t.Fatal("Check observability/service-systemd-journald not registered")
	}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"systemctl is-active systemd-journald": errors.New("inactive"),
		},
	}
	if err := c.Run(context.Background(), runner); err == nil {
		t.Fatal("Expected check to fail because service is inactive, but it passed")
	}
}

func TestServiceTimeSync_Success(t *testing.T) {
	c := findCheck("observability/service-time-synchronization")
	if c == nil {
		t.Fatal("Check observability/service-time-synchronization not registered")
	}
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"systemctl is-active systemd-timesyncd": nil,
		},
	}
	if err := c.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}
