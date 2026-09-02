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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// KernelFeatureSpec defines the module translation name for a Kconfig symbol
// under the GKE Dataplane V2 Conformance Contract.
type KernelFeatureSpec struct {
	ModuleName  string
	Description string
}

// VerifyKernelFeature checks whether a Linux kernel configuration symbol and/or its
// module translation is active on the host OS.
//
// =========================================================================================
//
//	KERNEL FEATURE VERIFICATION DECISION TREE
//
// =========================================================================================
//
//	 [ Input: configSymbol (e.g. "CONFIG_VXLAN"), moduleName (e.g. "vxlan" or "") ]
//	                                    │
//	                                    ▼
//	                    ┌───────────────────────────────┐
//	                    │ Is moduleName != "" ?         │
//	                    └───────────────┬───────────────┘
//	                                    │
//	                  Yes ┌─────────────┴─────────────┐ No / Not Found
//	                      ▼                           ▼
//	           ┌─────────────────────┐     ┌────────────────────────────────────┐
//	           │ PRONG 1: modinfo    │     │ PRONG 2: Kconfig Audit             │
//	           │ modinfo -F filename │     │ zcat /proc/config.gz ||            │
//	           └──────────┬──────────┘     │ cat /boot/config-$(uname -r)       │
//	                      │                └─────────────────┬──────────────────┘
//	          ┌───────────┴───────────┐                      │
//	(builtin) │                       │ /path/to/foo.ko      ▼
//	          ▼                       │            ┌───────────────────┐
//	    ┌───────────┐                 │            │ grep '^CONFIG_='  │
//	    │ PASS (=y) │                 │            └─────────┬─────────┘
//	    └───────────┘                 │                 =y   │   =m
//	                                  │            ┌─────────┴─────────┐
//	                                  │            ▼                   │
//	                                  │      ┌───────────┐             │
//	                                  │      │ PASS (=y) │             │
//	                                  │      └───────────┘             │
//	                                  └──────────────┬─────────────────┘
//	                                                 ▼
//	                                       ┌────────────────────┐
//	                                       │  Is module active  │
//	                                       │   in kernel RAM    │
//	                                       │  (/sys/module/)?   │
//	                                       └─────────┬──────────┘
//	                                                 │
//	                                       Yes ┌─────┴─────┐ No
//	                                           ▼           ▼
//	                                     ┌───────────┐ ┌────────────────────────┐
//	                                     │ PASS (=m) │ │ Check Dynamic Loading  │
//	                                     └───────────┘ │ kernel.modules_disabled│
//	                                                   └───────────┬────────────┘
//	                                                    disabled=0 │ disabled=1
//	                                                ┌──────────────┴──────────────┐
//	                                                ▼                             ▼
//	                                          ┌───────────┐             ┌───────────────────┐
//	                                          │ PASS (=m) │             │ FAIL (Locked Out) │
//	                                          └───────────┘             └───────────────────┘
//
// =========================================================================================
//
// 1. If moduleName != "", queries `modinfo -F filename <moduleName>` to detect (builtin) vs .ko file on disk.
// 2. If it's a .ko file on disk (=m), verifies it is either already loaded in RAM (/sys/module/<moduleName>) OR kernel.modules_disabled == 0.
// 3. If moduleName == "" (or modinfo fails), falls back to auditing Kconfig via /proc/config.gz or /boot/config-*.
// VerificationState represents a distinct phase or transition in the kernel feature check pipeline.
type VerificationState string

const (
	StateModinfoFastPath   VerificationState = "ModinfoFastPath"
	StateKconfigAudit      VerificationState = "KconfigAudit"
	StateRAMAndDynamicLoad VerificationState = "RAMAndDynamicLoad"
	StatePass              VerificationState = "Pass"
	StateFail              VerificationState = "Fail"
)

// verificationMachine maintains the context and audit trail as a kernel feature check
// transitions through its verification state pipeline.
type verificationMachine struct {
	ctx          context.Context
	runner       validation.SSHRunner
	configSymbol string
	moduleName   string

	discoveredAs string   // "(builtin)", "=y", or "=m (or .ko on disk)"
	err          error    // Hard failure blocker if encountered
	trace        []string // Complete audit trail of transitions and decisions
}

// VerifyKernelFeature checks whether a Linux kernel configuration symbol and/or its
// module translation is active on the host OS using a structured Verification State Machine.
func VerifyKernelFeature(ctx context.Context, runner validation.SSHRunner, configSymbol string, moduleName string) error {
	m := &verificationMachine{
		ctx:          ctx,
		runner:       runner,
		configSymbol: configSymbol,
		moduleName:   moduleName,
	}

	currState := StateModinfoFastPath
	for {
		switch currState {
		case StateModinfoFastPath:
			currState = m.handleModinfo()
		case StateKconfigAudit:
			currState = m.handleKconfig()
		case StateRAMAndDynamicLoad:
			currState = m.handleRAMOrDynamic()
		case StatePass:
			return nil
		case StateFail:
			if m.err != nil {
				return fmt.Errorf("%w [Trace: %s]", m.err, strings.Join(m.trace, " -> "))
			}
			return fmt.Errorf("verification failed for %s [Trace: %s]", configSymbol, strings.Join(m.trace, " -> "))
		default:
			return fmt.Errorf("unknown verification state %q for %s [Trace: %s]", currState, configSymbol, strings.Join(m.trace, " -> "))
		}
	}
}

func (m *verificationMachine) handleModinfo() VerificationState {
	if m.moduleName == "" {
		m.trace = append(m.trace, "ModinfoFastPath: skipped (no ModuleName)")
		return StateKconfigAudit
	}

	out, err := m.runner.CombinedOutput(m.ctx, "PATH=/sbin:/usr/sbin:$PATH modinfo -F filename "+m.moduleName)
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		m.trace = append(m.trace, "ModinfoFastPath: module not found via modinfo, falling back to Kconfig")
		return StateKconfigAudit
	}

	filename := strings.TrimSpace(string(out))
	if filename == "(builtin)" {
		m.discoveredAs = "modinfo (builtin)"
		m.trace = append(m.trace, "ModinfoFastPath: found (builtin)")
		return StatePass
	}

	// The driver is compiled as a .ko loadable module on disk (=m)
	m.discoveredAs = fmt.Sprintf("modinfo (loadable module %s)", filename)
	m.trace = append(m.trace, fmt.Sprintf("ModinfoFastPath: found .ko module on disk (%s)", filename))
	return StateRAMAndDynamicLoad
}

func (m *verificationMachine) handleKconfig() VerificationState {
	configCmd := fmt.Sprintf("(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null) | grep -E '^%s=(y|m)$'", m.configSymbol)
	out, err := m.runner.CombinedOutput(m.ctx, configCmd)
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		m.err = fmt.Errorf("kernel requirement %s is not enabled (=y or =m) in running kernel configuration", m.configSymbol)
		m.trace = append(m.trace, "KconfigAudit: symbol not found (=n or missing)")
		return StateFail
	}

	val := strings.TrimSpace(string(out))
	if strings.HasSuffix(val, "=y") {
		m.discoveredAs = "Kconfig audit (=y)"
		m.trace = append(m.trace, "KconfigAudit: found built-in (=y)")
		return StatePass
	}

	// The symbol was found as =m in Kconfig fallback
	m.discoveredAs = "Kconfig audit (=m, dynamic loading permitted)"
	m.trace = append(m.trace, "KconfigAudit: found loadable module (=m)")
	return StateRAMAndDynamicLoad
}

func (m *verificationMachine) handleRAMOrDynamic() VerificationState {
	if m.moduleName != "" {
		probeCmd := fmt.Sprintf("test -d /sys/module/%s || test $(PATH=/sbin:/usr/sbin:$PATH sysctl -n kernel.modules_disabled 2>/dev/null) != 1", m.moduleName)
		if err := m.runner.Run(m.ctx, probeCmd); err == nil {
			m.trace = append(m.trace, fmt.Sprintf("RAMAndDynamicLoad: module %s is active in RAM OR kernel.modules_disabled=0", m.moduleName))
			return StatePass
		}
		m.err = fmt.Errorf("driver %s (%s) is compiled as module (=m), but sysctl kernel.modules_disabled=1 prevents runtime loading and module is not loaded in RAM", m.configSymbol, m.moduleName)
		m.trace = append(m.trace, "RAMAndDynamicLoad: FAIL (hardened kernel modules_disabled=1 locked out unloaded .ko module)")
		return StateFail
	}

	// When moduleName == "" and discovered as =m in Kconfig fallback
	if err := m.runner.Run(m.ctx, "test $(PATH=/sbin:/usr/sbin:$PATH sysctl -n kernel.modules_disabled 2>/dev/null) = 1"); err == nil {
		m.err = fmt.Errorf("requirement %s is compiled as module (=m), but sysctl kernel.modules_disabled=1 prevents runtime module loading", m.configSymbol)
		m.trace = append(m.trace, "RAMAndDynamicLoad: FAIL (kernel.modules_disabled=1 prevents runtime module loading)")
		return StateFail
	}

	m.trace = append(m.trace, "RAMAndDynamicLoad: kernel.modules_disabled=0 permits on-demand dynamic loading")
	return StatePass
}
