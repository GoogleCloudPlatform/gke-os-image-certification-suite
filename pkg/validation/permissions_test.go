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
	"testing"
)

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name      string
		permStr   string
		expected  uint32
		expectErr bool
	}{
		{"9-char regular", "rwxr-xr-x", 0755, false},
		{"10-char directory", "drwxr-xr-x", 0755, false},
		{"10-char file", "-rwxr-xr-x", 0755, false},
		{"sticky bit T", "drwx-----T", 0701, false},
		{"invalid length", "rwxr-xr", 0, true},
		{"invalid length long", "drwxr-xr-x-", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, err := ParsePermissions(tc.permStr)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error for %q, but passed", tc.permStr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for %q: %v", tc.permStr, err)
				}
				if val != tc.expected {
					t.Errorf("expected %o, got %o", tc.expected, val)
				}
			}
		})
	}
}

func TestIsPermissiveSuperset(t *testing.T) {
	tests := []struct {
		name       string
		actual     string
		expected   string
		wantResult bool
		expectErr  bool
	}{
		{"exact match", "rwxr-xr-x", "rwxr-xr-x", true, false},
		{"more permissive group read", "crw-rw----", "crw--w----", true, false},
		{"insufficient group write", "crw-------", "crw--w----", false, false},
		{"completely mismatched type/perms", "drwx-----T", "-rwxr-xr-x", false, false},
		{"invalid actual string", "invalid", "rwxr-xr-x", false, true},
		{"invalid expected string", "rwxr-xr-x", "invalid", false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := IsPermissiveSuperset(tc.actual, tc.expected)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error for actual=%q expected=%q, but got nil", tc.actual, tc.expected)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for actual=%q expected=%q: %v", tc.actual, tc.expected, err)
				}
				if res != tc.wantResult {
					t.Errorf("IsPermissiveSuperset(%q, %q) = %v; want %v", tc.actual, tc.expected, res, tc.wantResult)
				}
			}
		})
	}
}
