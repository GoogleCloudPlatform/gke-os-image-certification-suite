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

package validation

import (
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
)

// IsApplicable evaluates whether a check should run against the target environment.
func IsApplicable(c Check, env TargetEnvironment) (bool, string) {
	constrained, ok := c.(ConstrainedCheck)
	if !ok {
		return true, "" // Unconstrained checks run everywhere
	}

	rule := constrained.Constraints()
	targetOS := strings.ToLower(strings.TrimSpace(env.OSID))

	// 1. Evaluate OnlyOS
	if len(rule.OnlyOS) > 0 {
		matched := false
		for _, os := range rule.OnlyOS {
			if strings.EqualFold(os, targetOS) {
				matched = true
				break
			}
		}
		if !matched {
			return false, fmt.Sprintf("OS %q is not in OnlyOS %v", targetOS, rule.OnlyOS)
		}
	}

	// 2. Evaluate SkipOS
	for _, os := range rule.SkipOS {
		if strings.EqualFold(os, targetOS) {
			return false, fmt.Sprintf("OS %q matches SkipOS rule", targetOS)
		}
	}

	// 3. Evaluate Top-Level GKE Version Range (if version is supplied)
	if env.HasVersion {
		if rule.MinGKEVersion != "" {
			min, err := utils.ParseSemVer(rule.MinGKEVersion)
			if err == nil && env.GKEVersion.Compare(min) < 0 {
				return false, fmt.Sprintf("GKE version %s is below minimum required %s", env.GKEVersion, min)
			}
		}
		if rule.MaxGKEVersion != "" {
			max, err := utils.ParseSemVer(rule.MaxGKEVersion)
			if err == nil && env.GKEVersion.Compare(max) > 0 {
				return false, fmt.Sprintf("GKE version %s exceeds maximum allowed %s", env.GKEVersion, max)
			}
		}
	}

	// 4. Evaluate Matrix Rules (OS-specific version constraints)
	for _, mr := range rule.MatrixRules {
		if strings.EqualFold(mr.OSID, targetOS) {
			inRange := true
			if env.HasVersion {
				if mr.MinGKEVersion != "" {
					min, err := utils.ParseSemVer(mr.MinGKEVersion)
					if err == nil && env.GKEVersion.Compare(min) < 0 {
						inRange = false
					}
				}
				if mr.MaxGKEVersion != "" {
					max, err := utils.ParseSemVer(mr.MaxGKEVersion)
					if err == nil && env.GKEVersion.Compare(max) > 0 {
						inRange = false
					}
				}
			}
			if inRange && mr.Skip {
				return false, fmt.Sprintf("matches matrix skip rule for OS %s within version range [%s, %s]", mr.OSID, mr.MinGKEVersion, mr.MaxGKEVersion)
			}
		}
	}

	return true, ""
}
