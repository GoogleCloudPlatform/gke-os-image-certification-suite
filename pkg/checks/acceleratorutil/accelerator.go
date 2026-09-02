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

// Package acceleratorutil provides shared utilities and hardware inspection helpers for accelerator checks.
package acceleratorutil

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

const (
	VendorGoogle = "0x1ae0"
	VendorNvidia = "0x10de"
	VendorAMD    = "0x1002"
)

const (
	TPUDeviceV7x = "0x0076" // TPU v7x
	TPUDeviceV6e = "0x006f" // TPU v6e
	TPUDeviceV5p = "0x0062" // TPU v5p
)

// PCIDevice represents a PCIe endpoint discovered in the Linux sysfs PCI tree.
type PCIDevice struct {
	Address string // PCI bus address, e.g. "0000:00:04.0"
	Vendor  string // PCI Vendor ID, e.g. "0x1ae0"
	Device  string // PCI Device ID, e.g. "0x0076"
	Class   string // PCI Device Class, e.g. "0x120000" or "0x030200"
}

// pciScanScript is a zero-dependency bash command that reads raw sysfs PCI attributes.
const pciScanScript = `for v in /sys/bus/pci/devices/*/vendor; do
  if [ -f "$v" ]; then
    d=$(dirname "$v")
    echo "$(basename "$d") $(cat "$v" 2>/dev/null) $(cat "$d/device" 2>/dev/null) $(cat "$d/class" 2>/dev/null)"
  fi
done`

// GetPCIDevices queries all PCIe devices on the system by reading the Linux sysfs tree.
func GetPCIDevices(ctx context.Context, runner validation.SSHRunner) ([]PCIDevice, error) {
	out, err := runner.CombinedOutput(ctx, pciScanScript)
	if err != nil {
		return nil, fmt.Errorf("failed to scan PCI devices from sysfs: %w", err)
	}

	var devices []PCIDevice
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		devices = append(devices, PCIDevice{
			Address: fields[0],
			Vendor:  strings.ToLower(fields[1]),
			Device:  strings.ToLower(fields[2]),
			Class:   strings.ToLower(fields[3]),
		})
	}
	return devices, nil
}

func HasGoogleTPUV7x(ctx context.Context, runner validation.SSHRunner) (bool, error) {
	devices, err := GetPCIDevices(ctx, runner)
	if err != nil {
		return false, err
	}
	for _, dev := range devices {
		if isGoogleTPUV7x(dev) {
			return true, nil
		}
	}
	return false, nil
}

func HasGoogleTPU(ctx context.Context, runner validation.SSHRunner) (bool, error) {
	devices, err := GetPCIDevices(ctx, runner)
	if err != nil {
		return false, err
	}
	for _, dev := range devices {
		if isGoogleTPU(dev) {
			return true, nil
		}
	}
	return false, nil
}

func HasNvidiaGPU(ctx context.Context, runner validation.SSHRunner) (bool, error) {
	devices, err := GetPCIDevices(ctx, runner)
	if err != nil {
		return false, err
	}
	for _, dev := range devices {
		if isNvidiaGPU(dev) {
			return true, nil
		}
	}
	return false, nil
}

func HasAMDGPU(ctx context.Context, runner validation.SSHRunner) (bool, error) {
	devices, err := GetPCIDevices(ctx, runner)
	if err != nil {
		return false, err
	}
	for _, dev := range devices {
		if isAMDGPU(dev) {
			return true, nil
		}
	}
	return false, nil
}

func isGoogleTPUV7x(dev PCIDevice) bool {
	if dev.Vendor != VendorGoogle {
		return false
	}
	return strings.EqualFold(dev.Device, TPUDeviceV7x)
}

func isGoogleTPU(dev PCIDevice) bool {
	if dev.Vendor != VendorGoogle {
		return false
	}
	return isDisplayOrAcceleratorClass(dev.Class)
}

func isNvidiaGPU(dev PCIDevice) bool {
	if dev.Vendor != VendorNvidia {
		return false
	}
	return isDisplayOrAcceleratorClass(dev.Class)
}

func isAMDGPU(dev PCIDevice) bool {
	if dev.Vendor != VendorAMD {
		return false
	}
	return isDisplayOrAcceleratorClass(dev.Class)
}

// isDisplayOrAcceleratorClass checks for PCI class 0x0300 (VGA), 0x0302 (3D), 0x0380 (Display other), or 0x1200 (Processing Accelerator).
func isDisplayOrAcceleratorClass(class string) bool {
	class = strings.ToLower(class)
	return strings.HasPrefix(class, "0x0300") ||
		strings.HasPrefix(class, "0x0302") ||
		strings.HasPrefix(class, "0x0380") ||
		strings.HasPrefix(class, "0x1200")
}
