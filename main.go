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

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/provision"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/utils"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
	"golang.org/x/crypto/ssh"

	// Blank imports to trigger check registration
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/accelerator"
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/gke-metadata-server"
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/networking"
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/node"
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/observability"
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/security"
)

var (
	vmIP       = flag.String("vm-ip", "", "IP address of the target GCE VM (ignored if -provision-vm is true)")
	sshKeyPath = flag.String("ssh-key", "", "Path to the private SSH key file (ignored if -provision-vm is true)")
	sshUser    = flag.String("ssh-user", "certuser", "SSH username for the VM (ignored if -provision-vm is true)")

	provisionVM    = flag.Bool("provision-vm", false, "Auto-provision a GCE VM for the test run")
	gcpProject     = flag.String("gcp-project", "", "GCP Project ID (required if -provision-vm is true)")
	gcpZone        = flag.String("gcp-zone", "", "GCP Zone (required if -provision-vm is true)")
	machineType    = flag.String("machine-type", "e2-medium", "GCE Machine Type")
	sourceImage    = flag.String("source-image", "", "Source image path or family (required if -provision-vm is true)")
	gkeVersionFlag = flag.String("gke-version", "1.35.0", "Target GKE Kubernetes version (e.g. 1.35.0 or 1.36.0)")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalf("Testsuite failed: %v", err)
	}
	fmt.Println("Testsuite completed successfully.")
}

func run() error {
	var gkeVer utils.SemVer
	var hasVersion bool
	var err error

	versionStr := *gkeVersionFlag
	gkeVer, err = utils.ParseSemVer(versionStr)
	if err != nil {
		return fmt.Errorf("failed to parse --gke-version flag: %w", err)
	}
	// Fail-fast validation
	if gkeVer.Major < 1 || (gkeVer.Major == 1 && gkeVer.Minor < 34) {
		return fmt.Errorf("unsupported GKE version %s: minimum supported GKE version is 1.34", versionStr)
	}
	hasVersion = true

	ctx := context.Background()
	var targetIP string
	var targetUser string
	var keyBytes []byte
	var cleanup func()

	// 1. Resolve Target Connection Info (either provision a new VM or use existing)
	if *provisionVM {
		targetIP, keyBytes, cleanup, err = provisionAndTunnel(ctx)
		if err != nil {
			return err
		}
		defer cleanup()
		targetUser = "certuser"
	} else {
		targetIP, targetUser, keyBytes, err = getTargetConnectionInfo()
		if err != nil {
			return err
		}
	}

	// 2. Connect to the Target VM
	sshClient, err := connectToVM(targetIP, targetUser, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	defer func() {
		if sshClient != nil {
			sshClient.Close()
		}
	}()

	// 3. Setup Reconnect Closure (needed if JIT installation triggers user group changes)
	reconnectClosure := func() (validation.SSHRunner, error) {
		log.Println("Reconnecting SSH to apply group changes...")
		sshClient.Close()
		client, err := connectToVM(targetIP, targetUser, keyBytes)
		if err != nil {
			return nil, err
		}
		sshClient = client
		return validation.NewRealSSHRunner(sshClient), nil
	}

	var runner validation.SSHRunner = validation.NewRealSSHRunner(sshClient)

	// 4. Detect target VM OS once at startup
	osID, err := detectOS(ctx, runner)
	if err != nil {
		return fmt.Errorf("failed to detect target OS: %w", err)
	}
	log.Printf("Detected target VM operating system: %s", osID)

	var targetEnv validation.TargetEnvironment
	targetEnv.OSID = osID
	targetEnv.GKEVersion = gkeVer
	targetEnv.HasVersion = hasVersion

	if hasVersion {
		log.Printf("Evaluating check constraints for OS: %s, GKE Version: %s", osID, gkeVer)
	} else {
		log.Printf("Evaluating check constraints for OS: %s (no GKE version specified, skipping version gates)", osID)
	}

	// 5. Retrieve and validate registered checks
	allChecks := validation.RegisteredChecks()
	if err := validateChecks(allChecks); err != nil {
		return fmt.Errorf("invalid check registry: %w", err)
	}

	var activeChecks []validation.Check
	for _, c := range allChecks {
		applicable, reason := validation.IsApplicable(c, targetEnv)
		if !applicable {
			log.Printf("Skipping check %s: %s", c.Name(), reason)
			continue
		}
		activeChecks = append(activeChecks, c)
	}

	tier0Checks := filterChecksByTier(activeChecks, validation.Tier0)
	tier1Checks := filterChecksByTier(activeChecks, validation.Tier1)

	// 6. Run Tier 0 Gatekeeper checks first (No JIT installations yet!)
	if len(tier0Checks) > 0 {
		if err := runTier0(ctx, runner, tier0Checks); err != nil {
			return fmt.Errorf("Gatekeeper checks failed: %w", err)
		}
	}

	// 7. Resolve and Install Dependencies JIT for Tier 1 checks (passing detected osID!)
	runner, err = resolveAndInstallDependencies(ctx, runner, tier1Checks, reconnectClosure, osID)
	if err != nil {
		return fmt.Errorf("failed JIT dependency installation: %w", err)
	}

	// 8. Run Tier 1 Checks
	if len(tier1Checks) > 0 {
		if err := runTier1(ctx, runner, tier1Checks); err != nil {
			return fmt.Errorf("completed with failures: %w", err)
		}
	}

	return nil
}

// provisionAndTunnel provisions a new GCE VM and establishes an IAP tunnel to it.
// It returns the local tunnel target address, ephemeral SSH key bytes, a cleanup closure, and any error.
func provisionAndTunnel(ctx context.Context) (string, []byte, func(), error) {
	if *gcpProject == "" || *gcpZone == "" || *sourceImage == "" {
		return "", nil, nil, fmt.Errorf("-gcp-project, -gcp-zone, and -source-image are required when -provision-vm is true")
	}

	// 1. Generate Ephemeral SSH Key
	log.Println("Generating ephemeral SSH key...")
	keyPair, err := provision.GenerateSSHKeyPair()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	// 2. Provision VM
	instanceName := fmt.Sprintf("gke-os-cert-suite-%d-%s", time.Now().Unix(), randomString(6))
	log.Printf("Provisioning GCE VM %s in project %s, zone %s...", instanceName, *gcpProject, *gcpZone)
	internalIP, err := provision.CreateInstance(ctx, *gcpProject, *gcpZone, instanceName, *machineType, *sourceImage, "certuser", keyPair.PublicKeySSH)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to provision VM: %w", err)
	}
	log.Printf("VM provisioned successfully. Internal IP: %s", internalIP)

	// 3. Setup Cleanup Closure
	var tunnelCmd *exec.Cmd
	cleanup := func() {
		if tunnelCmd != nil && tunnelCmd.Process != nil {
			log.Println("Stopping IAP tunnel...")
			if err := tunnelCmd.Process.Kill(); err != nil {
				log.Printf("Warning: failed to kill IAP tunnel process: %v", err)
			}
			_ = tunnelCmd.Wait()
		}
		log.Printf("Tearing down GCE VM %s...", instanceName)
		if err := provision.DeleteInstance(ctx, *gcpProject, *gcpZone, instanceName); err != nil {
			log.Printf("Warning: failed to delete instance %s: %v", instanceName, err)
		} else {
			log.Println("VM torn down successfully.")
		}
	}

	// 4. Find free local port for IAP tunnel
	localPort, err := getFreePort()
	if err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("failed to find free local port for IAP tunnel: %w", err)
	}
	targetIP := fmt.Sprintf("127.0.0.1:%d", localPort)

	// 5. Establish SSH Config
	sshConfig, err := getSSHConfig("certuser", keyPair.PrivateKeyPEM)
	if err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("failed to get SSH config: %w", err)
	}

	// 6. Start IAP Tunnel and Wait for SSH with retries
	log.Println("Establishing IAP tunnel and waiting for SSH...")
	sshReady := false
	var tunnelExitErr error
	tunnelExited := make(chan struct{})

	startTunnel := func() error {
		log.Printf("Starting IAP tunnel to %s on local port %d...", instanceName, localPort)
		tunnelCmd = exec.Command("gcloud", "compute", "start-iap-tunnel", instanceName, "22",
			fmt.Sprintf("--local-host-port=localhost:%d", localPort),
			"--zone="+*gcpZone,
			"--project="+*gcpProject)

		tunnelLog, err := os.Create("iap-tunnel.log")
		if err != nil {
			return fmt.Errorf("failed to create tunnel log: %w", err)
		}
		tunnelCmd.Stdout = tunnelLog
		tunnelCmd.Stderr = tunnelLog

		if err := tunnelCmd.Start(); err != nil {
			_ = tunnelLog.Close()
			return err
		}
		_ = tunnelLog.Close()

		tunnelExited = make(chan struct{})
		go func(cmd *exec.Cmd, exited chan struct{}) {
			tunnelExitErr = cmd.Wait()
			close(exited)
		}(tunnelCmd, tunnelExited)

		return nil
	}

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if tunnelCmd == nil {
			if err := startTunnel(); err != nil {
				log.Printf("Warning: failed to start tunnel: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			time.Sleep(3 * time.Second)
		}

		select {
		case <-tunnelExited:
			log.Printf("IAP tunnel exited with error: %v. Retrying in 10s...", tunnelExitErr)
			if logBytes, err := os.ReadFile("iap-tunnel.log"); err == nil {
				log.Printf("Tunnel log output:\n%s", string(logBytes))
			}
			tunnelCmd = nil // Trigger restart
			time.Sleep(10 * time.Second)
			continue
		default:
		}

		conn, err := net.DialTimeout("tcp", targetIP, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			client, err := ssh.Dial("tcp", targetIP, sshConfig)
			if err == nil {
				_ = client.Close()
				sshReady = true
				break
			}
			log.Printf("Tunnel port is open, but SSH handshake waiting... (%v)", err)
		} else {
			log.Printf("Waiting for tunnel port %d to open...", localPort)
		}
		time.Sleep(5 * time.Second)
	}

	if !sshReady {
		cleanup()
		return "", nil, nil, fmt.Errorf("timeout waiting for SSH via IAP tunnel")
	}

	return targetIP, keyPair.PrivateKeyPEM, cleanup, nil
}

// getTargetConnectionInfo validates connection flags and reads the private SSH key.
func getTargetConnectionInfo() (string, string, []byte, error) {
	if *vmIP == "" {
		return "", "", nil, fmt.Errorf("-vm-ip flag is required when -provision-vm is false")
	}
	if *sshKeyPath == "" {
		return "", "", nil, fmt.Errorf("-ssh-key flag is required when -provision-vm is false")
	}
	keyBytes, err := os.ReadFile(*sshKeyPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to read SSH private key file: %w", err)
	}
	return *vmIP, *sshUser, keyBytes, nil
}

// filterChecksByTier filters the registered checks and returns only checks matching the tier.
func filterChecksByTier(checks []validation.Check, tier validation.Tier) []validation.Check {
	var filtered []validation.Check
	for _, c := range checks {
		if c.Tier() == tier {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// resolveAndInstallDependencies resolves required tools from checks and installs them JIT, passing the detected osID.
func resolveAndInstallDependencies(ctx context.Context, runner validation.SSHRunner, checks []validation.Check, reconnect func() (validation.SSHRunner, error), osID string) (validation.SSHRunner, error) {
	requiredTools := make(map[tools.Type]bool)
	for _, c := range checks {
		if depCheck, ok := c.(validation.DependentCheck); ok {
			for _, tool := range depCheck.RequiredTools() {
				requiredTools[tool] = true
			}
		}
	}

	if len(requiredTools) > 0 {
		log.Printf("Installing %d required tools JIT...", len(requiredTools))
		requiresReconnect := false
		for tool := range requiredTools {
			installer, ok := tools.Get(tool)
			if !ok {
				return nil, fmt.Errorf("no installer registered for tool %s", tool)
			}
			log.Printf("  Checking if %s is already installed JIT...", installer.Name())
			exists, err := installer.Exists(ctx, runner, osID)
			if err == nil && exists {
				log.Printf("    %s is already installed and functional. Skipping JIT installation.", installer.Name())
				continue
			}
			if err != nil {
				log.Printf("    Warning: failed to check if %s exists: %v. Proceeding with installation.", installer.Name(), err)
			}

			log.Printf("    %s is missing or broken. Installing...", installer.Name())
			if err := installer.Install(ctx, runner, osID); err != nil {
				return nil, fmt.Errorf("failed to install tool %s: %w", tool, err)
			}
			if installer.RequiresReconnect() {
				requiresReconnect = true
			}
		}
		log.Println("Tool installations complete.")

		if requiresReconnect && reconnect != nil {
			var err error
			runner, err = reconnect()
			if err != nil {
				return nil, fmt.Errorf("failed to reconnect to VM after installing required tools: %w", err)
			}
		}
	}
	return runner, nil
}

// runTier0 executes the Tier 0 gatekeeper checks sequentially.
func runTier0(ctx context.Context, runner validation.SSHRunner, checks []validation.Check) error {
	fmt.Printf("Running Tier 0 Gatekeeper checks (%d)...\n", len(checks))
	for _, c := range checks {
		fmt.Printf("  Running Gatekeeper %s...\n", c.Name())
		if err := c.Run(ctx, runner); err != nil {
			return fmt.Errorf("FATAL: Gatekeeper %s failed: %w. Halting execution", c.Name(), err)
		}
	}
	fmt.Println("All Tier 0 Gatekeeper checks passed.")
	return nil
}

// runTier1 executes the Tier 1 checks sequentially, separating destructive and non-destructive.
func runTier1(ctx context.Context, runner validation.SSHRunner, checks []validation.Check) error {
	fmt.Printf("Running Tier 1 checks (%d)...\n", len(checks))
	var nonDestructive []validation.Check
	var destructive []validation.Check
	for _, c := range checks {
		if c.Destructive() {
			destructive = append(destructive, c)
		} else {
			nonDestructive = append(nonDestructive, c)
		}
	}

	hasFailures := false
	if len(nonDestructive) > 0 {
		fmt.Printf("Running non-destructive Tier 1 checks sequentially (%d)...\n", len(nonDestructive))
		for _, c := range nonDestructive {
			fmt.Printf("  Running check %s...\n", c.Name())
			if err := c.Run(ctx, runner); err != nil {
				fmt.Printf("  ERROR: check %s failed: %v\n", c.Name(), err)
				hasFailures = true
			}
		}
	}

	if len(destructive) > 0 {
		fmt.Printf("Running destructive Tier 1 checks sequentially (%d)...\n", len(destructive))
		for _, c := range destructive {
			fmt.Printf("  Running destructive check %s...\n", c.Name())
			if err := c.Run(ctx, runner); err != nil {
				fmt.Printf("  ERROR: destructive check %s failed: %v\n", c.Name(), err)
				hasFailures = true
			}
			if cleanable, ok := c.(validation.CleanableCheck); ok {
				fmt.Printf("  Cleaning up destructive check %s...\n", c.Name())
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 1*time.Minute)
				err := cleanable.Cleanup(cleanupCtx, runner)
				cancel()
				if err != nil {
					fmt.Printf("  ERROR: cleanup for check %s failed: %v\n", c.Name(), err)
					hasFailures = true
				}
			}
		}
	}

	if hasFailures {
		return fmt.Errorf("one or more Tier 1 checks failed")
	}
	return nil
}

func getSSHConfig(user string, keyBytes []byte) (*ssh.ClientConfig, error) {
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}, nil
}

func connectToVM(ip, user string, keyBytes []byte) (*ssh.Client, error) {
	config, err := getSSHConfig(user, keyBytes)
	if err != nil {
		return nil, err
	}

	addr := ip
	if _, _, err := net.SplitHostPort(ip); err != nil {
		addr = fmt.Sprintf("%s:22", ip)
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH to %s: %w", addr, err)
	}

	return client, nil
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// validateChecks ensures that all registered checks conform to the suite's architectural rules:
// 1. Tier 0 checks (Gatekeepers) are forbidden from declaring any external tool dependencies.
// 2. Destructive checks MUST implement CleanableCheck to guarantee cleanup logic.
func validateChecks(checks []validation.Check) error {
	for _, c := range checks {
		if c.Tier() == validation.Tier0 {
			if depCheck, ok := c.(validation.DependentCheck); ok {
				if len(depCheck.RequiredTools()) > 0 {
					return fmt.Errorf("architectural violation: Tier 0 check %q is forbidden from declaring tool dependencies (declared: %v)", c.Name(), depCheck.RequiredTools())
				}
			}
		}
		if c.Destructive() {
			if _, ok := c.(validation.CleanableCheck); !ok {
				return fmt.Errorf("architectural violation: destructive check %q must implement CleanableCheck to guarantee cleanup logic", c.Name())
			}
		}
	}
	return nil
}

// detectOS queries /etc/os-release on the VM to find the OS ID.
func detectOS(ctx context.Context, runner validation.SSHRunner) (string, error) {
	out, err := runner.CombinedOutput(ctx, "grep -E '^ID=' /etc/os-release | cut -d= -f2")
	if err != nil {
		return "", fmt.Errorf("failed to read /etc/os-release: %w", err)
	}
	// Strip quotes and whitespace
	osID := strings.Trim(string(bytes.TrimSpace(out)), `"'`)
	return osID, nil
}

func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}
