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
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestGuestAgentServiceCheck_Success(t *testing.T) {
	check := &guestAgentServiceCheck{
		service:      "google-guest-agent.service",
		expectActive: true,
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"systemctl show --property=LoadState google-guest-agent.service": {
				Out: []byte("LoadState=loaded\n"),
			},
			"systemctl show --property=ActiveState google-guest-agent.service": {
				Out: []byte("ActiveState=active\n"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err != nil {
		t.Fatalf("Expected check to pass, got error: %v", err)
	}
}

func TestGuestAgentServiceCheck_LoadState_Failure(t *testing.T) {
	check := &guestAgentServiceCheck{
		service:      "non-existent.service",
		expectActive: false,
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"systemctl show --property=LoadState non-existent.service": {
				Out: []byte("LoadState=not-found\n"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail due to LoadState=not-found, got nil")
	}
}

func TestGuestAgentServiceCheck_ActiveState_Failure(t *testing.T) {
	check := &guestAgentServiceCheck{
		service:      "google-guest-agent.service",
		expectActive: true,
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"systemctl show --property=LoadState google-guest-agent.service": {
				Out: []byte("LoadState=loaded\n"),
			},
			"systemctl show --property=ActiveState google-guest-agent.service": {
				Out: []byte("ActiveState=inactive\n"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail due to ActiveState=inactive, got nil")
	}
}

func TestGuestAgentServiceCheck_SSH_Error(t *testing.T) {
	check := &guestAgentServiceCheck{
		service: "google-guest-agent.service",
	}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"systemctl show --property=LoadState google-guest-agent.service": {
				Err: errors.New("ssh connection lost"),
			},
		},
	}

	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail due to SSH runner error, got nil")
	}
}
