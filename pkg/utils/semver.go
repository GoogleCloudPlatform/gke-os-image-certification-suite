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

package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SemVer represents a parsed semantic version.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string
	Raw        string
}

var semverRegex = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

// ParseSemVer parses a version string into a SemVer struct.
func ParseSemVer(v string) (SemVer, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return SemVer{}, fmt.Errorf("empty version string")
	}

	matches := semverRegex.FindStringSubmatch(v)
	if matches == nil {
		return SemVer{}, fmt.Errorf("invalid semantic version string: %q", v)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid major version %q: %w", matches[1], err)
	}

	minor := 0
	if matches[2] != "" {
		minor, err = strconv.Atoi(matches[2])
		if err != nil {
			return SemVer{}, fmt.Errorf("invalid minor version %q: %w", matches[2], err)
		}
	}

	patch := 0
	if matches[3] != "" {
		patch, err = strconv.Atoi(matches[3])
		if err != nil {
			return SemVer{}, fmt.Errorf("invalid patch version %q: %w", matches[3], err)
		}
	}

	return SemVer{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		PreRelease: matches[4],
		Raw:        v,
	}, nil
}

// Compare returns:
// -1 if s < other
//  0 if s == other
//  1 if s > other
func (s SemVer) Compare(other SemVer) int {
	if s.Major != other.Major {
		if s.Major < other.Major {
			return -1
		}
		return 1
	}
	if s.Minor != other.Minor {
		if s.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if s.Patch != other.Patch {
		if s.Patch < other.Patch {
			return -1
		}
		return 1
	}
	if s.PreRelease == "" && other.PreRelease != "" {
		return 1
	}
	if s.PreRelease != "" && other.PreRelease == "" {
		return -1
	}
	if s.PreRelease < other.PreRelease {
		return -1
	} else if s.PreRelease > other.PreRelease {
		return 1
	}
	return 0
}

func (s SemVer) String() string {
	if s.Raw == "latest" {
		return "latest"
	}
	base := fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
	if s.PreRelease != "" {
		base += "-" + s.PreRelease
	}
	return base
}
