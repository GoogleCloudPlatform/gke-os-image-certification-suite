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
	"context"
	"golang.org/x/crypto/ssh"
)

type RealSSHRunner struct {
	Client *ssh.Client
}

func NewRealSSHRunner(client *ssh.Client) *RealSSHRunner {
	return &RealSSHRunner{Client: client}
}

func (r *RealSSHRunner) Run(ctx context.Context, cmd string) error {
	session, err := r.Client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	done := make(chan error, 1)
	go func() {
		fullCmd := "export PATH=$PATH:$HOME/.local/bin; " + cmd
		done <- session.Run(fullCmd)
	}()

	select {
	case <-ctx.Done():
		if session.Signal(ssh.SIGKILL) != nil {
			// ignore
		}
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (r *RealSSHRunner) CombinedOutput(ctx context.Context, cmd string) ([]byte, error) {
	session, err := r.Client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		fullCmd := "export PATH=$PATH:$HOME/.local/bin; " + cmd
		out, err := session.CombinedOutput(fullCmd)
		done <- result{out: out, err: err}
	}()

	select {
	case <-ctx.Done():
		if session.Signal(ssh.SIGKILL) != nil {
			// ignore
		}
		return nil, ctx.Err()
	case res := <-done:
		return res.out, res.err
	}
}
