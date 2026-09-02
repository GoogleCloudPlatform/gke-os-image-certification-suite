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
	"os/exec"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

type localRunner struct{}

func (r *localRunner) Run(ctx context.Context, cmd string) error {
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	return c.Run()
}

func (r *localRunner) CombinedOutput(ctx context.Context, cmd string) ([]byte, error) {
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	return c.CombinedOutput()
}

func TestVerifyKernelFeature_Modinfo_Builtin(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"PATH=/sbin:/usr/sbin:$PATH modinfo -F filename af_packet": {
				Out: []byte("(builtin)\n"),
			},
		},
	}

	if err := VerifyKernelFeature(context.Background(), runner, "CONFIG_PACKET", "af_packet"); err != nil {
		t.Fatalf("Expected modinfo (builtin) to pass, got: %v", err)
	}
}

func TestVerifyKernelFeature_Kconfig_Module_Lockout(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test $(PATH=/sbin:/usr/sbin:$PATH sysctl -n kernel.modules_disabled 2>/dev/null) = 1": nil, // modules_disabled = 1
		},
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null) | grep -E '^CONFIG_DUMMY_MOD=(y|m)$'": {
				Out: []byte("CONFIG_DUMMY_MOD=m\n"),
			},
		},
	}

	if err := VerifyKernelFeature(context.Background(), runner, "CONFIG_DUMMY_MOD", ""); err == nil {
		t.Fatal("Expected Kconfig (=m) audit with modules_disabled=1 to fail, got nil")
	}
}

// TestLaptopKernel_Prong2_Live verifies PRONG 2 (Kconfig Audit fallback with moduleName="")
// directly on your laptop kernel:
// Case 1: CONFIG_BRIDGE=m (Module IS loaded in RAM)
// Case 2: CONFIG_X86_CPUID=m (Module IS NOT loaded in RAM, but dynamic loading allowed)
func TestLaptopKernel_Prong2_Live(t *testing.T) {
	runner := &localRunner{}
	ctx := context.Background()

	// Skip if host kernel config is not accessible in this environment
	out, _ := runner.CombinedOutput(ctx, "(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null) | head -n 1")
	if len(out) == 0 {
		t.Skip("Skipping live laptop kernel test: kernel config is not available on this host")
	}

	// Case 1: CONFIG_BRIDGE=m -> Active in RAM (/sys/module/bridge)
	if err := VerifyKernelFeature(ctx, runner, "CONFIG_BRIDGE", ""); err != nil {
		t.Errorf("Expected CONFIG_BRIDGE=m (active in RAM) to pass, got error: %v", err)
	}

	// Case 2: CONFIG_X86_CPUID=m -> Not loaded in RAM (/sys/module/cpuid), but modules_disabled=0
	if err := VerifyKernelFeature(ctx, runner, "CONFIG_X86_CPUID", ""); err != nil {
		t.Errorf("Expected CONFIG_X86_CPUID=m to pass via dynamic loading, got error: %v", err)
	}
}
