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
	"fmt"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestPortCollisionCheck_Metadata(t *testing.T) {
	for _, spec := range RegisteredPortConflicts {
		check := &portCollisionCheck{spec: spec}

		expectedName := fmt.Sprintf("networking/port-collision-%d", spec.Port)
		if check.Name() != expectedName {
			t.Errorf("Check Name() = %q, expected %q", check.Name(), expectedName)
		}

		if check.Description() == "" {
			t.Errorf("Check %q has empty Description()", check.Name())
		}

		if check.Tier() != validation.Tier1 {
			t.Errorf("Check %q has Tier = %v, expected Tier1", check.Name(), check.Tier())
		}

		if check.Destructive() {
			t.Errorf("Check %q marked as Destructive, expected false", check.Name())
		}
	}
}

func TestPortCollisionCheck_PortFree(t *testing.T) {
	spec := PortConflictSpec{
		Port:        9879,
		Component:   "cilium",
		Description: "Cilium agent health & Prometheus metrics server",
	}
	check := &portCollisionCheck{spec: spec}

	cmd := fmt.Sprintf("ss -tlnH 'sport = :%d' 2>/dev/null || ss -tln 2>/dev/null | grep -E '[: ]%d\\b' || netstat -tlpn 2>/dev/null | grep -E '[: ]%d\\b'",
		spec.Port, spec.Port, spec.Port)

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			cmd: {
				Out: []byte(""),
				Err: nil,
			},
		},
	}

	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("Expected port check to pass when port %d is free, got error: %v", spec.Port, err)
	}
}

func TestPortCollisionCheck_PortInUse(t *testing.T) {
	spec := PortConflictSpec{
		Port:        10256,
		Component:   "dpv2",
		Description: "Dataplane V2 eBPF kube-proxy replacement healthz server",
	}
	check := &portCollisionCheck{spec: spec}

	cmd := fmt.Sprintf("ss -tlnH 'sport = :%d' 2>/dev/null || ss -tln 2>/dev/null | grep -E '[: ]%d\\b' || netstat -tlpn 2>/dev/null | grep -E '[: ]%d\\b'",
		spec.Port, spec.Port, spec.Port)

	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			cmd: {
				Out: []byte("LISTEN 0 128 0.0.0.0:10256 0.0.0.0:*\n"),
				Err: nil,
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatalf("Expected port check to fail when port %d is in use, but it passed", spec.Port)
	}

	if !strings.Contains(err.Error(), "10256 is already in use") {
		t.Errorf("Expected error to mention '10256 is already in use', got: %v", err)
	}
}
