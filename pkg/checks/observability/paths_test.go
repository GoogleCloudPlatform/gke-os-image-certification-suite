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

package observability

import (
	"context"
	"errors"
	"testing"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation/testutil"
)

func TestVerifyPathPermissions_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /var/log/": {
				Out: []byte("drwxr-xr-x\n"),
				Err: nil,
			},
		},
	}
	if err := verifyPathPermissions(context.Background(), runner, "/var/log/", "drwxr-xr-x"); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyPathPermissions_Insufficient(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -c '%A' /var/log/": {
				Out: []byte("drw-r--r--\n"), // missing exec
				Err: nil,
			},
		},
	}
	if err := verifyPathPermissions(context.Background(), runner, "/var/log/", "drwxr-xr-x"); err == nil {
		t.Fatal("Expected check to fail because permissions are insufficient, but it passed")
	}
}

func TestVerifyDirWritable_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /var/lib/google-fluentbit/pos-files/ || test -d $(dirname /var/lib/google-fluentbit/pos-files/) || test -d $(dirname $(dirname /var/lib/google-fluentbit/pos-files/))": nil,
		},
	}
	if err := verifyDirWritable(context.Background(), runner, "/var/lib/google-fluentbit/pos-files/"); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyDirWritable_Failure(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		RunErrMap: map[string]error{
			"test -d /var/lib/google-fluentbit/pos-files/ || test -d $(dirname /var/lib/google-fluentbit/pos-files/) || test -d $(dirname $(dirname /var/lib/google-fluentbit/pos-files/))": errors.New("read-only filesystem"),
		},
	}
	if err := verifyDirWritable(context.Background(), runner, "/var/lib/google-fluentbit/pos-files/"); err == nil {
		t.Fatal("Expected check to fail on non-existent directory, but it passed")
	}
}

func TestVerifyConcreteFile_Success(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -L -c '%s' /etc/ssl/certs/ca-certificates.crt": {
				Out: []byte("215430\n"),
				Err: nil,
			},
		},
	}
	if err := verifyConcreteFile(context.Background(), runner, "/etc/ssl/certs/ca-certificates.crt"); err != nil {
		t.Fatalf("Expected check to pass, got: %v", err)
	}
}

func TestVerifyConcreteFile_BrokenSymlink(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -L -c '%s' /etc/ssl/certs/ca-certificates.crt": {
				Out: nil,
				Err: errors.New("No such file or directory"),
			},
		},
	}
	if err := verifyConcreteFile(context.Background(), runner, "/etc/ssl/certs/ca-certificates.crt"); err == nil {
		t.Fatal("Expected check to fail on broken symlink, but it passed")
	}
}

func TestVerifyConcreteFile_Empty(t *testing.T) {
	runner := &testutil.MockSSHRunner{
		CombinedOutputResult: map[string]testutil.CombinedOutputVal{
			"stat -L -c '%s' /etc/ssl/certs/ca-certificates.crt": {
				Out: []byte("0\n"),
				Err: nil,
			},
		},
	}
	if err := verifyConcreteFile(context.Background(), runner, "/etc/ssl/certs/ca-certificates.crt"); err == nil {
		t.Fatal("Expected check to fail on empty file, but it passed")
	}
}
