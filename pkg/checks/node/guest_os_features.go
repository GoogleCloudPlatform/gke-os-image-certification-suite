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
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type guestOSFeatureCheck struct {
	featureName string
	cmd         string
}

func (c *guestOSFeatureCheck) Name() string { return "node/guest-os-feature-" + c.featureName }
func (c *guestOSFeatureCheck) Description() string {
	return fmt.Sprintf("Verifies that host OS kernel and drivers support Guest OS Feature: %s", c.featureName)
}
func (c *guestOSFeatureCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *guestOSFeatureCheck) Destructive() bool     { return false }

func (c *guestOSFeatureCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	if err := runner.Run(ctx, c.cmd); err != nil {
		return fmt.Errorf("Guest OS feature %s verification failed: driver support or kernel config missing: %w", c.featureName, err)
	}
	return nil
}

func init() {
	// Commands are designed with robust fallback checking across COS (utilizing proc/config.gz) and Ubuntu
	gvnicCmd := `modinfo gve >/dev/null 2>&1 || grep -E "CONFIG_GOOGLE_GVE=[ym]" /boot/config-$(uname -r) >/dev/null 2>&1 || (zgrep "CONFIG_GOOGLE_GVE=[ym]" /proc/config.gz >/dev/null 2>&1)`
	idpfCmd := `modinfo idpf >/dev/null 2>&1 || grep -E "CONFIG_IDPF=[ym]" /boot/config-$(uname -r) >/dev/null 2>&1 || (zgrep "CONFIG_IDPF=[ym]" /proc/config.gz >/dev/null 2>&1)`
	virtioScsiMqCmd := `modinfo virtio_scsi >/dev/null 2>&1 || grep -E "CONFIG_SCSI_VIRTIO=[ym]" /boot/config-$(uname -r) >/dev/null 2>&1 || (zgrep "CONFIG_SCSI_VIRTIO=[ym]" /proc/config.gz >/dev/null 2>&1)`

	features := []struct {
		name string
		cmd  string
	}{
		{"UEFI_COMPATIBLE", "test -d /sys/firmware/efi"},
		{"GVNIC", gvnicCmd},
		{"IDPF", idpfCmd},
		{"VIRTIO_SCSI_MULTIQUEUE", virtioScsiMqCmd},
	}

	for _, f := range features {
		validation.Register(&guestOSFeatureCheck{featureName: f.name, cmd: f.cmd})
	}
}
