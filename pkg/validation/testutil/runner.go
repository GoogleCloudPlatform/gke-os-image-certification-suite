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

package testutil

import (
	"context"
)

// MockSSHRunner is a reusable mock implementation of validation.SSHRunner for testing checks.
type MockSSHRunner struct {
	RunCmds            []string
	CombinedOutputCmds []string

	RunErrMap            map[string]error
	CombinedOutputResult map[string]CombinedOutputVal
}

// CombinedOutputVal represents a mocked return value for CombinedOutput.
type CombinedOutputVal struct {
	Out []byte
	Err error
}

// Run records the command and returns a mocked error if configured.
func (m *MockSSHRunner) Run(ctx context.Context, cmd string) error {
	m.RunCmds = append(m.RunCmds, cmd)
	if m.RunErrMap != nil {
		if err, ok := m.RunErrMap[cmd]; ok {
			return err
		}
	}
	return nil
}

// CombinedOutput records the command and returns mocked output/error if configured.
func (m *MockSSHRunner) CombinedOutput(ctx context.Context, cmd string) ([]byte, error) {
	m.CombinedOutputCmds = append(m.CombinedOutputCmds, cmd)
	if m.CombinedOutputResult != nil {
		if res, ok := m.CombinedOutputResult[cmd]; ok {
			return res.Out, res.Err
		}
	}
	return nil, nil
}
