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

package storage

import (
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checklib"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

func init() {
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/dev", CheckName: "dev"})
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/sys", CheckName: "sys"})
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/lib/modules", CheckName: "lib-modules"})
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/etc/udev", CheckName: "etc-udev"})
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/lib/udev", CheckName: "lib-udev"})
	validation.Register(&checklib.PathExistenceCheck{Component: "storage", Pattern: "/run/udev", CheckName: "run-dev"})
}
