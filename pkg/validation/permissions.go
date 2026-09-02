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
)

// ParsePermissions converts a 9 or 10 character Unix permissions string (e.g., "drwxr-xr-x" or "rwxr-xr-x")
// into its bitwise octal representation.
func ParsePermissions(permStr string) (uint32, error) {
	if len(permStr) == 10 {
		permStr = permStr[1:]
	}
	if len(permStr) != 9 {
		return 0, fmt.Errorf("invalid permissions string length: %s", permStr)
	}

	var perm uint32
	// User
	if permStr[0] == 'r' { perm |= 0400 }
	if permStr[1] == 'w' { perm |= 0200 }
	if permStr[2] == 'x' || permStr[2] == 's' || permStr[2] == 'S' { perm |= 0100 }
	// Group
	if permStr[3] == 'r' { perm |= 0040 }
	if permStr[4] == 'w' { perm |= 0020 }
	if permStr[5] == 'x' || permStr[5] == 's' || permStr[5] == 'S' { perm |= 0010 }
	// Others
	if permStr[6] == 'r' { perm |= 0004 }
	if permStr[7] == 'w' { perm |= 0002 }
	if permStr[8] == 'x' || permStr[8] == 't' || permStr[8] == 'T' { perm |= 0001 }

	return perm, nil
}

// IsPermissiveSuperset checks if the actual permission string is equal to or
// more permissive than the expected permission string (using bitwise superset comparison).
func IsPermissiveSuperset(actual, expected string) (bool, error) {
	if actual == expected {
		return true, nil
	}

	actualBits, err := ParsePermissions(actual)
	if err != nil {
		return false, fmt.Errorf("failed to parse actual permissions %q: %w", actual, err)
	}

	expectedBits, err := ParsePermissions(expected)
	if err != nil {
		return false, fmt.Errorf("failed to parse expected permissions %q: %w", expected, err)
	}

	return (actualBits & expectedBits) == expectedBits, nil
}
