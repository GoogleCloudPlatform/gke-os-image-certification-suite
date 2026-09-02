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
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestGlibcCheck_Success(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"COS 2.35", "GNU C Library (Gentoo 2.35-r24 p9) stable release version 2.35."},
		{"COS 2.37", "GNU C Library (Gentoo 2.37-r14 p12) stable release version 2.37."},
		{"Ubuntu 2.35", "ldd (Ubuntu GLIBC 2.35-0ubuntu3.10) 2.35"},
		{"Ubuntu 2.39", "ldd (Ubuntu GLIBC 2.39-0ubuntu8.7) 2.39"},
		{"Newer glibc 3.1", "ldd (GLIBC 3.1) 3.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := &glibcCheck{}
			runner := &testutil.MockSSHRunner{
				CombinedOutputResult: map[string]testutil.CombinedOutputVal{
					"ldd --version 2>/dev/null || /lib64/libc.so.6 2>/dev/null || /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || /lib/libc.so.6 2>/dev/null": {
						Out: []byte(tc.output),
						Err: nil,
					},
				},
			}
			err := check.Run(context.Background(), runner)
			if err != nil {
				t.Fatalf("Expected check to pass for output %q, got error: %v", tc.output, err)
			}
		})
	}
}

func TestGlibcCheck_Failure(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"Old COS 2.31", "GNU C Library stable release version 2.31."},
		{"Old Ubuntu 2.31", "ldd (Ubuntu GLIBC 2.31) 2.31"},
		{"invalid format", "no version here"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := &glibcCheck{}
			runner := &testutil.MockSSHRunner{
				CombinedOutputResult: map[string]testutil.CombinedOutputVal{
					"ldd --version 2>/dev/null || /lib64/libc.so.6 2>/dev/null || /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || /lib/libc.so.6 2>/dev/null": {
						Out: []byte(tc.output),
						Err: nil,
					},
				},
			}
			err := check.Run(context.Background(), runner)
			if err == nil {
				t.Fatalf("Expected check to fail for output %q, but got nil error", tc.output)
			}
		})
	}
}

func TestGlibcCheck_ExecutionError(t *testing.T) {
	check := &glibcCheck{}
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"ldd --version 2>/dev/null || /lib64/libc.so.6 2>/dev/null || /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || /lib/libc.so.6 2>/dev/null": {
				Out: nil,
				Err: errors.New("command failed"),
			},
		},
	}
	err := check.Run(context.Background(), runner)
	if err == nil {
		t.Fatal("Expected check to fail due to SSH execution error")
	}
}
