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

// The TPU checks in this file validate guest OS customizations based on:
// https://docs.cloud.google.com/tpu/docs/configure-networking-access-compute

package accelerator

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/acceleratorutil"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// tpuVfioPciBindingCheck verifies that all Google TPU v7x PCIe devices (vendor 0x1ae0,
// device 0x0076) present on the system are bound to the vfio-pci kernel driver.
//
// Justification:
// When a TPU v7x accelerator is enumerated by the Linux kernel, it must be bound
// to the vfio-pci driver so user-space runtime libraries (libtpu) can directly access
// the hardware via /dev/vfio/<group>.
type tpuVfioPciBindingCheck struct{}

func (c *tpuVfioPciBindingCheck) Name() string {
	return "accelerator/tpu-v7x-vfio-pci-binding"
}

func (c *tpuVfioPciBindingCheck) Description() string {
	return "Verifies that Google TPU PCIe devices (0x1ae0) are bound to the vfio-pci kernel driver"
}

func (c *tpuVfioPciBindingCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuVfioPciBindingCheck) Destructive() bool {
	return false
}

func (c *tpuVfioPciBindingCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to check for Google TPU presence: %w", err)
	}
	if !hasTPU {
		log.Printf("INFO: %s: Google TPU device not detected; skipping check", c.Name())
		return nil
	}

	cmd := fmt.Sprintf(`for vendor_file in /sys/bus/pci/devices/*/vendor; do
  if [ -f "$vendor_file" ] && \
     grep -qi "%s" "$vendor_file" 2>/dev/null && \
     grep -qi "%s" "$(dirname "$vendor_file")/device" 2>/dev/null; then
    dev_dir=$(dirname "$vendor_file")
    driver=$(readlink -f "$dev_dir/driver" 2>/dev/null)
    if [ "${driver##*/}" != "vfio-pci" ]; then
      echo "TPU device $(basename "$dev_dir") is not bound to vfio-pci (bound to '${driver##*/}')"
      exit 1
    fi
  fi
done
exit 0`, acceleratorutil.VendorGoogle, acceleratorutil.TPUDeviceV7x)
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("Google TPU PCIe device found but not bound to vfio-pci: %w", err)
	}
	return nil
}

// tpuVfioDeviceSetupCheck verifies that the VFIO subsystem is correctly configured
// for user-space TPU runtime access.
//
// Justification:
// When TPU devices are bound to vfio-pci, the vfio_pci module must be loaded,
// /dev/vfio/<group> character devices must have 0666 permissions so non-root containers
// can access them, and allow_unsafe_interrupts=1 must be enabled on x86_64 platforms.
type tpuVfioDeviceSetupCheck struct{}

func (c *tpuVfioDeviceSetupCheck) Name() string {
	return "accelerator/tpu-v7x-vfio-device-setup"
}

func (c *tpuVfioDeviceSetupCheck) Description() string {
	return "Verifies that VFIO char devices (/dev/vfio/<group>) have 0666 permissions, allow_unsafe_interrupts is enabled on x86_64, and vfio_pci is loaded"
}

func (c *tpuVfioDeviceSetupCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuVfioDeviceSetupCheck) Destructive() bool {
	return false
}

func (c *tpuVfioDeviceSetupCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to check for Google TPU presence: %w", err)
	}
	if !hasTPU {
		log.Printf("INFO: %s: Google TPU device not detected; skipping check", c.Name())
		return nil
	}

	cmd := fmt.Sprintf(`for vendor_file in /sys/bus/pci/devices/*/vendor; do
  if [ -f "$vendor_file" ] && \
     grep -qi "%s" "$vendor_file" 2>/dev/null && \
     grep -qi "%s" "$(dirname "$vendor_file")/device" 2>/dev/null; then
    if ! (test -d /sys/module/vfio_pci || lsmod | grep -q "^vfio_pci"); then
      echo "vfio_pci module is not loaded"
      exit 1
    fi
    dev_dir=$(dirname "$vendor_file")
    group=$(basename "$(readlink -f "$dev_dir/iommu_group" 2>/dev/null)")
    vfio_dev="/dev/vfio/$group"
    if [ ! -c "$vfio_dev" ]; then
      echo "VFIO character device $vfio_dev not found"
      exit 1
    fi
    mode=$(stat -c "%%a" "$vfio_dev" 2>/dev/null)
    if [ "$mode" != "666" ]; then
      echo "$vfio_dev has mode $mode (expected 0666)"
      exit 1
    fi
    if [ "$(uname -m)" = "x86_64" ]; then
      allow_int=$(cat /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts 2>/dev/null)
      if [ "$allow_int" != "1" ] && [ "$allow_int" != "Y" ] && [ "$allow_int" != "y" ]; then
        echo "allow_unsafe_interrupts is not enabled ($allow_int)"
        exit 1
      fi
    fi
  fi
done
exit 0`, acceleratorutil.VendorGoogle, acceleratorutil.TPUDeviceV7x)
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("VFIO device setup requirements not met for detected TPU device (vfio_pci module loaded, 0666 permissions on /dev/vfio/<group>, allow_unsafe_interrupts enabled): %w", err)
	}
	return nil
}

// tpuDevicePermissionsRuleCheck verifies that udev rules grant world read-write (0666)
// permissions to Compute Acceleration Subsystem character devices (/dev/accel*).
//
// Justification:
// Modern Linux kernels expose TPU accelerators via character devices under /dev/accel/
// (e.g., accel0, accel1). Setting MODE="0666" allows non-root container workloads to
// interact with TPU devices without requiring root or privileged security contexts.
type tpuDevicePermissionsRuleCheck struct{}

func (c *tpuDevicePermissionsRuleCheck) Name() string {
	return "accelerator/tpu-v7x-device-permissions-rule"
}

func (c *tpuDevicePermissionsRuleCheck) Description() string {
	return "Verifies that udev rules grant 0666 permissions to Compute Acceleration Subsystem devices (accel*)"
}

func (c *tpuDevicePermissionsRuleCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuDevicePermissionsRuleCheck) Destructive() bool {
	return false
}

// NixOS: the path for installation might be different like /run/current-system/sw/lib/udev/rules.d
func (c *tpuDevicePermissionsRuleCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to check for Google TPU presence: %w", err)
	}
	if !hasTPU {
		log.Printf("INFO: %s: Google TPU device not detected; skipping check", c.Name())
		return nil
	}

	cmd := `bash -c 'shopt -s nullglob; grep -E "KERNEL==\"accel\*\"[[:space:]]*,?[[:space:]]*MODE=\"0666\"|MODE=\"0666\"[[:space:]]*,?[[:space:]]*KERNEL==\"accel\*\"" /etc/udev/rules.d/* /lib/udev/rules.d/* /usr/lib/udev/rules.d/* /run/current-system/sw/lib/udev/rules.d/*'`
	if err := runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("required udev rule granting 0666 permissions to accel* devices not found: %w", err)
	}
	return nil
}

// tpuResourceLimitsCheck verifies that memory locking (memlock) is unlimited
// and open file limits (nofile) are at least 100,000 via PAM limits or systemd containerd service.
//
// Justification:
// TPU runtime (libtpu) pins large DMA memory buffers and opens multiple device file
// descriptors. Memory locking must be unlimited and file limits >= 100,000.
type tpuResourceLimitsCheck struct{}

func (c *tpuResourceLimitsCheck) Name() string {
	return "accelerator/tpu-v7x-resource-limits"
}

func (c *tpuResourceLimitsCheck) Description() string {
	return "Verifies that memlock is unlimited and nofile is at least 100000 in PAM security limits or systemd containerd service"
}

func (c *tpuResourceLimitsCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuResourceLimitsCheck) Destructive() bool {
	return false
}

func (c *tpuResourceLimitsCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to check for Google TPU presence: %w", err)
	}
	if !hasTPU {
		log.Printf("INFO: %s: Google TPU device not detected; skipping check", c.Name())
		return nil
	}

	// 1. Check if PAM limits are configured in /etc/security/limits.conf or limits.d/ (Ubuntu, Debian, NixOS)
	memlockPamCmd := `bash -c 'shopt -s nullglob; grep -E "^\s*(\*|root)\s+(hard|soft|-)\s+memlock\s+unlimited" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null'`
	nofilePamCmd := `bash -c 'shopt -s nullglob; awk '\''$1 ~ /^(\*|root)$/ && ($2 ~ /^(hard|soft|-)$/) && $3 == "nofile" { if ($4 == "unlimited" || ($4 ~ /^[0-9]+$/ && $4 >= 100000)) found=1 } END { exit !found }'\'' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null'`
	if err := runner.Run(ctx, memlockPamCmd); err == nil {
		if err := runner.Run(ctx, nofilePamCmd); err == nil {
			return nil
		}
	}

	// Check if running on COS (where PAM limits are not used and memlock is unconstrained inside container sandboxes via IPC_LOCK)
	osRelease, err := runner.CombinedOutput(ctx, "cat /etc/os-release")
	isCOS := err == nil && (strings.Contains(strings.ToLower(string(osRelease)), "id=cos") || strings.Contains(strings.ToLower(string(osRelease)), "id_like=cos"))

	// 2. Alternatively, check systemd container runtime service limits (standard for COS and containerized runtimes)
	systemdLimitsCmd := "systemctl show containerd -p LimitMEMLOCK -p LimitNOFILE"
	out, err := runner.CombinedOutput(ctx, systemdLimitsCmd)
	if err == nil {
		if validMemlock, validNofile := parseSystemdLimits(string(out), isCOS); validMemlock && validNofile {
			return nil
		}
	}

	return fmt.Errorf("required resource limits (unlimited memlock and >= 100000 nofile) not configured in PAM limits (/etc/security/limits.conf) or containerd systemd service")
}

// parseSystemdLimits inspects systemctl show output for LimitMEMLOCK and LimitNOFILE values.
func parseSystemdLimits(out string, isCOS bool) (bool, bool) {
	var validMemlock, validNofile bool
	if isCOS {
		// On Container-Optimized OS (COS), memlock is unconstrained inside container sandboxes via IPC_LOCK capability,
		// and containerd runtime only requires LimitNOFILE=infinity.
		validMemlock = true
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LimitMEMLOCK=") {
			val := strings.TrimPrefix(line, "LimitMEMLOCK=")
			if val == "infinity" || val == "unlimited" || val == "18446744073709551615" {
				validMemlock = true
			}
		}
		if strings.HasPrefix(line, "LimitNOFILE=") {
			val := strings.TrimPrefix(line, "LimitNOFILE=")
			if val == "infinity" || val == "unlimited" || val == "18446744073709551615" {
				validNofile = true
			} else if num, err := strconv.ParseInt(val, 10, 64); err == nil && num >= 100000 {
				validNofile = true
			}
		}
	}
	return validMemlock, validNofile
}

// tpuKernelCmdlineCheck verifies that required kernel boot parameters are active
// in the running kernel command line (/proc/cmdline) or kernel sysfs.
//
// Justification:
// TPU v7x DMA requires IOMMU scalable mode (intel_iommu=on,sm_on), Transparent Hugepages
// (transparent_hugepage=always, or madvise on COS), and low latency polling (idle=poll on Ubuntu).
type tpuKernelCmdlineCheck struct{}

func (c *tpuKernelCmdlineCheck) Name() string {
	return "accelerator/tpu-v7x-kernel-cmdline"
}

func (c *tpuKernelCmdlineCheck) Description() string {
	return "Verifies that required kernel boot parameters (intel_iommu=on,sm_on, transparent_hugepage=always, idle=poll) are active in /proc/cmdline or sysfs"
}

func (c *tpuKernelCmdlineCheck) Tier() validation.Tier {
	return validation.Tier1
}

func (c *tpuKernelCmdlineCheck) Destructive() bool {
	return false
}

func (c *tpuKernelCmdlineCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to check for Google TPU presence: %w", err)
	}
	if !hasTPU {
		log.Printf("INFO: %s: Google TPU device not detected; skipping check", c.Name())
		return nil
	}

	out, err := runner.CombinedOutput(ctx, "cat /proc/cmdline")
	if err != nil {
		return fmt.Errorf("failed to read /proc/cmdline: %w", err)
	}
	cmdline := string(out)

	// intel_iommu=on,sm_on is required on all architectures and operating systems for TPU VFIO access
	if !strings.Contains(cmdline, "intel_iommu=on,sm_on") {
		return fmt.Errorf("required kernel boot parameter \"intel_iommu=on,sm_on\" missing from /proc/cmdline: %s", strings.TrimSpace(cmdline))
	}

	// Check if running on COS
	osRelease, err := runner.CombinedOutput(ctx, "cat /etc/os-release")
	isCOS := err == nil && (strings.Contains(strings.ToLower(string(osRelease)), "id=cos") || strings.Contains(strings.ToLower(string(osRelease)), "id_like=cos"))

	// transparent_hugepage can be seen via /proc/cmdline (transparent_hugepage=always), active as [always] in sysfs,
	// or active as [madvise] on COS where libtpu explicitly issues madvise(MADV_HUGEPAGE).
	thpCmd := `grep -q "\[always\]" /sys/kernel/mm/transparent_hugepage/enabled`
	if isCOS {
		thpCmd = `grep -q -E "\[always\]|\[madvise\]" /sys/kernel/mm/transparent_hugepage/enabled`
	}
	if !strings.Contains(cmdline, "transparent_hugepage=always") && runner.Run(ctx, thpCmd) != nil {
		return fmt.Errorf("transparent hugepages not enabled (expected transparent_hugepage=always in /proc/cmdline or [always] in /sys/kernel/mm/transparent_hugepage/enabled)")
	}

	// idle=poll is required on standard Linux/Ubuntu distributions (omitted on COS)
	if !isCOS && !strings.Contains(cmdline, "idle=poll") {
		return fmt.Errorf("required kernel boot parameter \"idle=poll\" missing from /proc/cmdline: %s", strings.TrimSpace(cmdline))
	}

	return nil
}

var tpuV7xConstraint = validation.Constraint{
	Condition: func(ctx context.Context, runner validation.SSHRunner) (bool, string, error) {
		hasTPU, err := acceleratorutil.HasGoogleTPUV7x(ctx, runner)
		if err != nil {
			return false, "", fmt.Errorf("failed to check for Google TPU presence: %w", err)
		}
		if !hasTPU {
			return false, "Google TPU v7x device not detected on node", nil
		}
		return true, "", nil
	},
}

func (c *tpuVfioPciBindingCheck) Constraints() validation.Constraint        { return tpuV7xConstraint }
func (c *tpuVfioDeviceSetupCheck) Constraints() validation.Constraint       { return tpuV7xConstraint }
func (c *tpuDevicePermissionsRuleCheck) Constraints() validation.Constraint { return tpuV7xConstraint }
func (c *tpuResourceLimitsCheck) Constraints() validation.Constraint        { return tpuV7xConstraint }
func (c *tpuKernelCmdlineCheck) Constraints() validation.Constraint         { return tpuV7xConstraint }

func init() {
	validation.Register(&tpuVfioPciBindingCheck{})
	validation.Register(&tpuVfioDeviceSetupCheck{})
	validation.Register(&tpuDevicePermissionsRuleCheck{})
	validation.Register(&tpuResourceLimitsCheck{})
	validation.Register(&tpuKernelCmdlineCheck{})
}
