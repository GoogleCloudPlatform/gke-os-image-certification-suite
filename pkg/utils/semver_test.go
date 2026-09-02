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

import "testing"

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		input      string
		wantMajor  int
		wantMinor  int
		wantPatch  int
		wantPre    string
		expectErr  bool
	}{
		{"1.33", 1, 33, 0, "", false},
		{"1.33.0", 1, 33, 0, "", false},
		{"v1.33.2", 1, 33, 2, "", false},
		{"1.33.2-gke.1100", 1, 33, 2, "gke.1100", false},
		{"  1.30  ", 1, 30, 0, "", false},
		{"latest", 0, 0, 0, "", true},
		{"", 0, 0, 0, "", true},
		{"invalid", 0, 0, 0, "", true},
		{"1.abc", 0, 0, 0, "", true},
	}

	for _, tc := range tests {
		got, err := ParseSemVer(tc.input)
		if tc.expectErr {
			if err == nil {
				t.Errorf("ParseSemVer(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseSemVer(%q) returned unexpected error: %v", tc.input, err)
			}
			if got.Major != tc.wantMajor || got.Minor != tc.wantMinor || got.Patch != tc.wantPatch || got.PreRelease != tc.wantPre {
				t.Errorf("ParseSemVer(%q) = (%d, %d, %d, %q), want (%d, %d, %d, %q)",
					tc.input, got.Major, got.Minor, got.Patch, got.PreRelease,
					tc.wantMajor, tc.wantMinor, tc.wantPatch, tc.wantPre)
			}
		}
	}
}

func TestCompareSemVer(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		{"1.30", "1.30", 0},
		{"1.30.0", "1.30", 0},
		{"1.30.1", "1.30", 1},
		{"1.30", "1.31", -1},
		{"2.0", "1.36", 1},
		{"1.33.2-gke.1100", "1.33.2", -1}, // pre-release is older than normal release
		{"1.33.2-gke.1100", "1.33.2-gke.1200", -1},
	}

	for _, tc := range tests {
		s1, err := ParseSemVer(tc.v1)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", tc.v1, err)
		}
		s2, err := ParseSemVer(tc.v2)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", tc.v2, err)
		}

		got := s1.Compare(s2)
		if got != tc.want {
			t.Errorf("CompareSemVer(%q, %q) = %d, want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
}
