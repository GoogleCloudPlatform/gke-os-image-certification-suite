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

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/acceleratorutil"
)

// mockTPUPCIDeviceOutput returns simulated sysfs output indicating a TPU v7x is present.
const mockTPUPCIDeviceOutput = "0000:00:04.0 0x1ae0 0x0076 0x120000\n"

func TestTpuVfioPciBindingCheck_Success(t *testing.T) {
	expectedCmd := fmt.Sprintf(`for vendor_file in /sys/bus/pci/devices/*/vendor; do
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

	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if cmd == expectedCmd {
				return nil
			}
			return errors.New("unexpected command")
		},
	}
	check := &tpuVfioPciBindingCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuVfioPciBindingCheck_SkipWhenNoTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte("0000:00:03.0 0x1af4 0x1000 0x020000\n"), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("should not be called when no TPU is present")
		},
	}
	check := &tpuVfioPciBindingCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuVfioPciBindingCheck_SkipWhenNonV7xTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte("0000:00:04.0 0x1ae0 0x006f 0x120000\n"), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("should not be called when non-v7x TPU is present")
		},
	}
	check := &tpuVfioPciBindingCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuVfioPciBindingCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("not found")
		},
	}
	check := &tpuVfioPciBindingCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil error")
	}
}

func TestTpuVfioDeviceSetupCheck_Success(t *testing.T) {
	expectedCmd := fmt.Sprintf(`for vendor_file in /sys/bus/pci/devices/*/vendor; do
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

	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if cmd == expectedCmd {
				return nil
			}
			return errors.New("unexpected command")
		},
	}
	check := &tpuVfioDeviceSetupCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuVfioDeviceSetupCheck_SkipWhenNoTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(""), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("should not be called when no TPU is present")
		},
	}
	check := &tpuVfioDeviceSetupCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuVfioDeviceSetupCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("not found")
		},
	}
	check := &tpuVfioDeviceSetupCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil error")
	}
}

func TestTpuDevicePermissionsRuleCheck_Success(t *testing.T) {
	expectedCmd := `bash -c 'shopt -s nullglob; grep -E "KERNEL==\"accel\*\"[[:space:]]*,?[[:space:]]*MODE=\"0666\"|MODE=\"0666\"[[:space:]]*,?[[:space:]]*KERNEL==\"accel\*\"" /etc/udev/rules.d/* /lib/udev/rules.d/* /usr/lib/udev/rules.d/* /run/current-system/sw/lib/udev/rules.d/*'`
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if cmd == expectedCmd {
				return nil
			}
			return errors.New("unexpected command")
		},
	}
	check := &tpuDevicePermissionsRuleCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuDevicePermissionsRuleCheck_SkipWhenNoTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(""), nil
		},
	}
	check := &tpuDevicePermissionsRuleCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuDevicePermissionsRuleCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("not found")
		},
	}
	check := &tpuDevicePermissionsRuleCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil error")
	}
}

func TestTpuResourceLimitsCheck_PAMSuccess(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			return nil
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuResourceLimitsCheck_SystemdSuccess_Infinity(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "systemctl show containerd") {
				return []byte("LimitMEMLOCK=infinity\nLimitNOFILE=infinity\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "limits.conf") {
				return errors.New("limits.conf not present on COS")
			}
			return nil
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success on COS via systemd limits, got %v", err)
	}
}

func TestTpuResourceLimitsCheck_SystemdSuccess_HigherNumericLimit(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "systemctl show containerd") {
				return []byte("LimitMEMLOCK=infinity\nLimitNOFILE=1048576\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "limits.conf") {
				return errors.New("limits.conf not configured")
			}
			return nil
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success with NOFILE=1048576 via systemd limits, got %v", err)
	}
}

func TestTpuResourceLimitsCheck_SystemdSuccess_COSDefault(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "systemctl show containerd") {
				return []byte("LimitMEMLOCK=8388608\nLimitNOFILE=infinity\n"), nil
			}
			if strings.Contains(cmd, "os-release") {
				return []byte("NAME=\"Container-Optimized OS\"\nID=cos\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "limits.conf") {
				return errors.New("limits.conf not configured on COS")
			}
			return nil
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success on COS default containerd limits, got %v", err)
	}
}

func TestTpuResourceLimitsCheck_SkipWhenNoTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(""), nil
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuResourceLimitsCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "systemctl show containerd") {
				return []byte("LimitMEMLOCK=1024\nLimitNOFILE=1024\n"), nil
			}
			if strings.Contains(cmd, "os-release") {
				return []byte("NAME=Ubuntu\nID=ubuntu\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			return errors.New("limit missing")
		},
	}
	check := &tpuResourceLimitsCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil error")
	}
}

func TestTpuKernelCmdlineCheck_UbuntuSuccess(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "cat /proc/cmdline") {
				return []byte("BOOT_IMAGE=/vmlinuz-6.8.0 ro console=ttyS0 idle=poll transparent_hugepage=always intel_iommu=on,sm_on"), nil
			}
			if strings.Contains(cmd, "os-release") {
				return []byte("NAME=Ubuntu\nID=ubuntu\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
	}
	check := &tpuKernelCmdlineCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTpuKernelCmdlineCheck_COSSuccess(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "cat /proc/cmdline") {
				return []byte("BOOT_IMAGE=/syslinux/vmlinuz.A intel_iommu=on,sm_on modules-load=vfio-pci"), nil
			}
			if strings.Contains(cmd, "os-release") {
				return []byte("NAME=\"Container-Optimized OS\"\nID=cos\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "transparent_hugepage/enabled") {
				return nil // [always]
			}
			return nil
		},
	}
	check := &tpuKernelCmdlineCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success on COS, got %v", err)
	}
}

func TestTpuKernelCmdlineCheck_COSSuccess_Madvise(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "cat /proc/cmdline") {
				return []byte("BOOT_IMAGE=/syslinux/vmlinuz.A intel_iommu=on,sm_on modules-load=vfio-pci"), nil
			}
			if strings.Contains(cmd, "os-release") {
				return []byte("NAME=\"Container-Optimized OS\"\nID=cos\n"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
		runFunc: func(cmd string) error {
			if strings.Contains(cmd, "grep -q -E \"\\[always\\]|\\[madvise\\]\"") {
				return nil // [madvise]
			}
			return nil
		},
	}
	check := &tpuKernelCmdlineCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected success on COS with madvise THP, got %v", err)
	}
}

func TestTpuKernelCmdlineCheck_SkipWhenNoTPU(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			return []byte(""), nil
		},
	}
	check := &tpuKernelCmdlineCheck{}
	if err := check.Run(context.Background(), runner); err != nil {
		t.Fatalf("expected skip (nil), got %v", err)
	}
}

func TestTpuKernelCmdlineCheck_Failure(t *testing.T) {
	runner := &mockRunner{
		combinedOutputFunc: func(cmd string) ([]byte, error) {
			if strings.Contains(cmd, "cat /proc/cmdline") {
				return []byte("BOOT_IMAGE=/vmlinuz-6.8.0 ro console=ttyS0"), nil
			}
			return []byte(mockTPUPCIDeviceOutput), nil
		},
	}
	check := &tpuKernelCmdlineCheck{}
	if err := check.Run(context.Background(), runner); err == nil {
		t.Fatal("expected failure, got nil error")
	}
}
