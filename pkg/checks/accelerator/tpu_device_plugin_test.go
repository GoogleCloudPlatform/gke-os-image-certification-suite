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
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

func TestTpuSysctlNetworkingCheck_Success(t *testing.T) {
	for _, f := range tpuSysctlNetworkingFiles {
		t.Run(f, func(t *testing.T) {
			runner := &mockRunner{
				runFunc: func(cmd string) error {
					if strings.Contains(cmd, f) {
						return nil
					}
					return fmt.Errorf("unexpected command: %s", cmd)
				},
			}
			check := &tpuSysctlNetworkingCheck{path: f}
			if err := check.Run(context.Background(), runner); err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			expectedName := "accelerator/tpu-sysctl-networking-" + f
			if check.Name() != expectedName {
				t.Errorf("expected Name() %q, got %q", expectedName, check.Name())
			}
			expectedDesc := fmt.Sprintf("Verifies that TPU networking kernel parameter %s exists and is writable by root", f)
			if check.Description() != expectedDesc {
				t.Errorf("expected Description() %q, got %q", expectedDesc, check.Description())
			}
			if check.Tier() != validation.Tier1 {
				t.Errorf("expected Tier1, got %v", check.Tier())
			}
			if check.Destructive() {
				t.Errorf("expected Destructive() false")
			}
		})
	}
}

func TestTpuSysctlNetworkingCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			return errors.New("permission denied")
		},
	}
	check := &tpuSysctlNetworkingCheck{path: "/proc/sys/net/ipv4/tcp_slow_start_after_idle"}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil")
	}
}

func TestTpuRequiredBinariesCheck_Success(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if strings.HasPrefix(cmd, "command -v") {
				return nil
			}
			return nil
		},
	}
	check := &tpuRequiredBinariesCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuRequiredBinariesCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			return errors.New("command not found")
		},
	}
	check := &tpuRequiredBinariesCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil")
	}
}

func TestTpuAbsentVbarAgentCheck_Success(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			return errors.New("not found")
		},
	}
	check := &tpuAbsentVbarAgentCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success when agents are absent, got %v", err)
	}
	if check.Name() != "accelerator/tpu-absent-vbar-agent" {
		t.Errorf("expected Name() accelerator/tpu-absent-vbar-agent, got %q", check.Name())
	}
	if check.Tier() != validation.Tier1 {
		t.Errorf("expected Tier1, got %v", check.Tier())
	}
	if check.Destructive() {
		t.Errorf("expected Destructive() false")
	}
	if !strings.Contains(check.Description(), "vbarcontrolagent") {
		t.Errorf("expected description to mention vbarcontrolagent, got %q", check.Description())
	}
}

func TestTpuAbsentVbarAgentCheck_Failure_SnapVbar(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if cmd == "snap list vbarcontrolagent" {
				return nil
			}
			return errors.New("not found")
		},
	}
	check := &tpuAbsentVbarAgentCheck{}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("expected failure when vbarcontrolagent snap is installed, got nil")
	}
	if !strings.Contains(err.Error(), "vbarcontrolagent (snap)") {
		t.Errorf("expected error to mention 'vbarcontrolagent (snap)', got %v", err)
	}
}

func TestTpuAbsentVbarAgentCheck_Failure_SnapTelemetry(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if cmd == "snap list ai-telemetry-collector" {
				return nil
			}
			return errors.New("not found")
		},
	}
	check := &tpuAbsentVbarAgentCheck{}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("expected failure when ai-telemetry-collector snap is installed, got nil")
	}
	if !strings.Contains(err.Error(), "ai-telemetry-collector (snap)") {
		t.Errorf("expected error to mention 'ai-telemetry-collector (snap)', got %v", err)
	}
}

func TestTpuAbsentVbarAgentCheck_Failure_SystemdService(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "systemctl list-unit-files") {
				return nil
			}
			return errors.New("not found")
		},
	}
	check := &tpuAbsentVbarAgentCheck{}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("expected failure when systemd service is installed, got nil")
	}
	if !strings.Contains(err.Error(), "systemd service") {
		t.Errorf("expected error to mention 'systemd service', got %v", err)
	}
}

func TestTpuAbsentVbarAgentCheck_Failure_BinaryInstalled(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(cmd string) error {
			if cmd == "command -v vbar_control_agent" {
				return nil
			}
			return errors.New("not found")
		},
	}
	check := &tpuAbsentVbarAgentCheck{}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("expected failure when vbar_control_agent binary is installed, got nil")
	}
	if !strings.Contains(err.Error(), "vbar_control_agent (binary)") {
		t.Errorf("expected error to mention 'vbar_control_agent (binary)', got %v", err)
	}
}
