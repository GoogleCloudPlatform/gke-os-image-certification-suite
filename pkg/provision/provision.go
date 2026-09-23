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

package provision

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

type SSHKeyPair struct {
	PrivateKeyPEM []byte
	PublicKeySSH  string
}

func GenerateSSHKeyPair() (*SSHKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKeySSH := string(ssh.MarshalAuthorizedKey(pub))

	return &SSHKeyPair{
		PrivateKeyPEM: privateKeyPEM,
		PublicKeySSH:  publicKeySSH,
	}, nil
}

// CreateInstance creates a GCE VM with a public IP and registers the ephemeral SSH key.
func CreateInstance(ctx context.Context, projectID, zone, instanceName, machineType, sourceImage, sshUser, publicKey, subnet string) (string, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return "", fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	// Format the SSH key for GCE metadata: "user:ssh-rsa AAAA... user"
	sshKeysValue := fmt.Sprintf("%s:%s %s", sshUser, strings.TrimSpace(publicKey), sshUser)

	req := &computepb.InsertInstanceRequest{
		Project: projectID,
		Zone:    zone,
		InstanceResource: &computepb.Instance{
			Name: proto.String(instanceName),
			Disks: []*computepb.AttachedDisk{
				{
					InitializeParams: &computepb.AttachedDiskInitializeParams{
						DiskSizeGb:  proto.Int64(10),
						SourceImage: proto.String(sourceImage),
					},
					AutoDelete: proto.Bool(true),
					Boot:       proto.Bool(true),
					Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
				},
			},
			MachineType: proto.String(fmt.Sprintf("zones/%s/machineTypes/%s", zone, machineType)),
			NetworkInterfaces: []*computepb.NetworkInterface{
				{
					// Use default network and assign ephemeral public IP for outbound internet access
					AccessConfigs: []*computepb.AccessConfig{
						{
							Name: proto.String("External NAT"),
							Type: proto.String(computepb.AccessConfig_ONE_TO_ONE_NAT.String()),
						},
					},
				},
			},
			Metadata: &computepb.Metadata{
				Items: []*computepb.Items{
					{
						Key:   proto.String("ssh-keys"),
						Value: proto.String(sshKeysValue),
					},
					{
						Key:   proto.String("enable-oslogin"),
						Value: proto.String("FALSE"),
					},
				},
			},
		},
	}
	if subnet != "" {
		idx := strings.LastIndex(zone, "-")
		// If '-' is not found (idx == -1),
		// or it's at the very beginning (idx == 0 -> empty prefix),
		// or it's at the very end (idx == len-1 -> empty suffix)
		if idx <= 0 || idx == len(zone)-1 {
			return "", fmt.Errorf("Cannot extract region from zone %s", zone)
		}
		region := zone[:idx]
		req.InstanceResource.NetworkInterfaces[0].Subnetwork = proto.String(fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/regions/%s/subnetworks/%s", projectID, region, subnet))
	}

	op, err := instancesClient.Insert(ctx, req)
	if err != nil {
		return "", fmt.Errorf("unable to create instance: %w", err)
	}

	if err = op.Wait(ctx); err != nil {
		return "", fmt.Errorf("unable to wait for the GCE operation: %w", err)
	}

	// Poll until instance status is RUNNING
	var inst *computepb.Instance
	for {
		inst, err = instancesClient.Get(ctx, &computepb.GetInstanceRequest{
			Project:  projectID,
			Zone:     zone,
			Instance: instanceName,
		})
		if err != nil {
			return "", fmt.Errorf("unable to get instance details: %w", err)
		}

		if inst.Status != nil && *inst.Status == "RUNNING" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if len(inst.NetworkInterfaces) > 0 {
		ip := inst.NetworkInterfaces[0].NetworkIP
		if ip != nil && *ip != "" {
			return *ip, nil
		}
	}

	return "", fmt.Errorf("instance created but no internal IP found")
}

func DeleteInstance(ctx context.Context, projectID, zone, instanceName string) error {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	op, err := instancesClient.Delete(ctx, &computepb.DeleteInstanceRequest{
		Project:  projectID,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("unable to delete instance: %w", err)
	}

	return op.Wait(ctx)
}

func WaitForSSH(ctx context.Context, addr string, config *ssh.ClientConfig, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				// TCP port is open, try SSH handshake
				client, err := ssh.Dial("tcp", addr, config)
				if err == nil {
					client.Close()
					return nil
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
	return fmt.Errorf("timeout waiting for SSH on %s", addr)
}
