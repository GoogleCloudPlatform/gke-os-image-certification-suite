# GKE Image Certification Suite

The GKE Image Certification Suite is a Go-based automated validation framework designed to certify the custom Operating System (OS) images, e.g., Container-Optimized OS (COS) and Ubuntu, meet the core node-level bootstrap contracts required to run on Google Kubernetes Engine (GKE).

This suite is used by GKE partners and customers under the Image Customization model to self-certify their golden images before registering them with the GKE qualification pipelines. It orchestrates machine provisioning, bootstrapping, secure SSH connectivity via IAP, and sequential execution of validation checks.

---

## Code Repository

The codebase is hosted on GitHub:

* **Repository URL:** `https://github.com/GoogleCloudPlatform/gke-os-image-certification-suite`

---

## Execution Modes

The suite supports two modes of execution: **Automated Mode** (recommended for clean runs) and **Manual Mode** (recommended for debugging and advanced machine setup).

### Prerequisites

Open up firewall rules in your GCP project to allow SSH access via IAP:

```bash
gcloud compute firewall-rules create allow-iap-ssh \
        --project=<GCP_PROJECT> \
        --network=default \
        --direction=INGRESS \
        --action=ALLOW \
        --rules=tcp:22 \
        --source-ranges="$(curl -s ifconfig.me)/32"
```

---

### Mode 1: Automated Provisioning (Recommended)

In this mode, the runner automatically handles the entire machine lifecycle:

1. Generates an ephemeral SSH key pair in memory.
2. Provisions a GCE VM (with an ephemeral public IP for outbound internet access during bootstrapping).
3. Establishes a secure IAP (Identity-Aware Proxy) tunnel.
4. Runs Tier 0 Gatekeeper checks concurrently (up to 5 parallel SSH sessions to respect `sshd` `MaxSessions` limits) on the clean, unmodified operating system.
5. Runs non-destructive Tier 1 validation checks.
6. Resolves required test tools (**Docker**, **Kind**, **Kubectl**) and bootstraps them JIT only when dependent/destructive checks require them.
   * *COS & Directory Permissions:* For Container-Optimized OS (COS) which has a read-only root directory, binary-only tools (Kind, Kubectl) are installed in `$HOME/.local/bin`. The pre-installed Docker daemon is reused.
7. Reconnects if necessary to apply group membership changes (`docker` group).
8. Runs remaining dependent and destructive Tier 1 checks.
9. Tears down the VM and stops the IAP tunnel (guaranteed via defers, even on failure).

> [!NOTE]
> **OS Login Compatibility:** If your target GCP project has OS Login enabled by default, instance-level metadata SSH keys will be ignored. Ensure your VM environment is configured with `enable-oslogin=FALSE` in GCE metadata to allow standard key injection.

#### Command Example

```bash
go run main.go \
  -provision-vm=true \
  -gcp-project=<GCP_PROJECT> \
  -gcp-zone=<GCP_ZONE> \
  -source-image=<FULL_SOURCE_IMAGE_PATH> \
  -gke-version=<GKE_VERSION>
```

#### Supported Image References

The list of supported base OS images is maintained in:
`https://www.gstatic.com/gke-image-maps/base-images/node-config-to-base-images-<MINOR_VERSION>.json`

For example:
`https://www.gstatic.com/gke-image-maps/base-images/node-config-to-base-images-1.35.json`

As of August 2026, GKE versions >= 1.34 are supported. The table below lists sample OS images for reference (users can find more images in the JSON mapping above):

| GKE Version | COS Image | Ubuntu Image |
| :--- | :--- | :--- |
| `1.34` | `projects/cos-cloud/global/images/cos-125-19216-104-133` | `projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-34-amd64-v20260130` |
| `1.35` | `projects/cos-cloud/global/images/cos-125-19216-395-7` | `projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-35-amd64-v20260518` |
| `1.36` | `projects/cos-cloud/global/images/cos-129-19506-224-80` | `projects/ubuntu-os-gke-cloud/global/images/ubuntu-gke-2404-1-36-amd64-v20260616` |

---

### Mode 2: Manual (Targeting an Existing VM)

If you already have a VM running and want to execute checks against it:

1. **Configure IAP Firewall Rule** in your GCP project to allow ingress from Google's IAP netblock (`35.235.240.0/20`):

```bash
gcloud compute firewall-rules create allow-ssh-ingress-from-iap \
  --direction=INGRESS --action=allow --rules=tcp:22 --source-ranges=35.235.240.0/20
```

2. **Start the IAP tunnel** locally in a separate terminal:

```bash
gcloud compute start-iap-tunnel <INSTANCE_NAME> 22 \
  --local-host-port=localhost:2222 \
  --zone=<ZONE> \
  --project=<PROJECT>
```

3. **Run the certification suite** pointing to the local tunnel port:

```bash
go run main.go \
  -vm-ip 127.0.0.1:2222 \
  -ssh-key ~/.ssh/google_compute_engine \
  -ssh-user certuser \
  -gke-version=1.35
```

---

## Command Line Flags

| Flag | Type | Description |
| :--- | :--- | :--- |
| `-provision-vm` | bool | Auto-provision a GCE VM for the test run (default: `false`). |
| `-gcp-project` | string | GCP Project ID (required if `-provision-vm` is `true`). |
| `-gcp-zone` | string | GCP Zone (required if `-provision-vm` is `true`). |
| `-source-image` | string | Source image path or family (required if `-provision-vm` is `true`). |
| `-gke-version` | string | Target GKE Kubernetes version (e.g. `1.35` or `1.36`). Defaults to `1.35`. |
| `-machine-type` | string | GCE Machine Type (default: `e2-medium`). |
| `-vm-ip` | string | IP/Addr of target VM (required if `-provision-vm` is `false`, supports `host:port`). |
| `-ssh-key` | string | Path to private SSH key (required if `-provision-vm` is `false`. Note: must be passphrase-less). |
| `-ssh-user` | string | SSH username (default: `certuser`). |

---

## How to Write & Add New Checks

Component owners can easily add new validation checks by implementing the `Check` interface and registering it.

### 1. Create the Check File

Do NOT put your checks directly in `pkg/checks/node/` unless it is a generic node check. Create a dedicated subdirectory for your team under `pkg/checks/` (e.g., `pkg/checks/my-team/`) to support folder-specific ownership and metadata. Save your Go file there (e.g., `pkg/checks/my-team/my_service.go`).

### 2. Implement the Check

Your check must implement the `Check` interface defined in `pkg/validation/interface.go`. If your check requires external tools (like Docker, Kind, or Kubectl), implement the `validation.DependentCheck` interface to declare dependencies.

```go
package myteam

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/tools"
	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

type MyServiceCheck struct{}

func init() {
	// Register the check with the global registry
	validation.Register(&MyServiceCheck{})
}

func (c *MyServiceCheck) Name() string {
	return "my-team/my-service-active" // Unique identifier
}

func (c *MyServiceCheck) Description() string {
	return "Verifies that my-service is running and active"
}

func (c *MyServiceCheck) Tier() validation.Tier {
	// Tier0: Gatekeeper (halts suite on failure)
	// Tier1: Regular check (failures accumulate, run sequentially)
	return validation.Tier1
}

func (c *MyServiceCheck) Destructive() bool {
	// True: Modifies system state and requires teardown logic
	// False: Read-only / non-destructive check
	return false
}

func (c *MyServiceCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	// Run command on the VM via SSHRunner (connection multiplexing)
	output, err := runner.CombinedOutput(ctx, "systemctl is-active my-service")
	if err != nil {
		return fmt.Errorf("my-service is not active: %w (output: %s)", err, string(output))
	}
	return nil
}

// Optional: Implement if you require pre-installed tools
func (c *MyServiceCheck) RequiredTools() []tools.Type {
	return []tools.Type{
		tools.Docker,
	}
}
```

### 3. Register the Package via Blank Import

Because Go does not execute `init()` functions unless the package is imported, you must add a blank import for your team's package in `main.go` (before the validation suite runs):

```go
import (
	...
	_ "github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/checks/my-team"
)
```

### 4. Developer Verification & Code Review

* **Manual Verification:** You must manually verify that your new checks compile and run successfully on both **COS** and **Ubuntu** target VMs before submitting your changes.
* **Submit for Review:** Submit a GitHub Pull Request (PR) for review to the repository maintainers (**`meagesis@google.com`**, and **`zicong@google.com`**).

### 5. Execution Flow (Tiers)

Regardless of the tier, all checks must be executable independently under the assumption of a clean-state environment. Within a specific tier, there is no designated execution order; instead, ordering is implicitly handled by the tiered check system itself. The specific details for each tier are outlined below:

* **Tier 0 (Gatekeepers):** Run first, concurrently (up to 5 parallel SSH sessions).
  * Evaluates all Tier 0 Gatekeepers and aggregates all failures before halting without running Tier 1. This ensures all baseline OS compatibility issues are discovered in a single run. Use this for critical dependencies (e.g., checking if `containerd` exists).
  * Tier 0 checks are baseline compatibility tests, or "Gatekeepers," that verify the target operating system meets the absolute minimum architectural requirements to run GKE.
  * They are simple, non-destructive checks that validate critical host prerequisites like unified cgroup v2 hierarchy support and the existence of the containerd runtime.
  * Because they must run on a clean, unmodified system, they are defined by a strict architectural constraint that forbids them from declaring or installing any external software dependencies.
* **Tier 1 (Validation Checks):** Run after all Tier 0 checks pass.
  * **All Tier 1 checks (both non-destructive and destructive) currently execute sequentially.** *(Note: Concurrent execution for non-destructive checks with worker-pool limits is in active development).*
  * **Destructive checks:** Modify some system state and/or have potential for conflicts with other checks. These checks must revert the system logic to its original state prior to completing. *(Note: Formal enforcement via the `CleanableCheck` interface is currently in code review under CL 2187941).*
  * Unlike Tier 0 checks, Tier 1 checks are permitted to declare external tool dependencies (like Docker, Kind, or Kubectl) which the runner will automatically install JIT before executing the check.

---

## How to Add a New Tool Dependency

If your check requires an external tool that is not currently supported (current examples are `docker`, `kind`, and `kubectl`), you can add support for it in the tools package:

### 1. Define Tool Type

Add your tool name to the list of constants in `pkg/tools/interface.go`:

```go
const (
    MyTool Type = "mytool"
)
```

### 2. Create Installer

Create a new installer file under `pkg/tools/mytool.go`. Implement the `tools.Installer` interface:

* `Name() string`: The user-friendly name of the tool.
* `Exists(ctx, runner, osID) (bool, error)`: Logic to verify if the tool is already installed and functional on the target VM.
* `Install(ctx, runner, osID) error`: OS-aware installation logic. Use `osID` (e.g., `"cos"`, `"ubuntu"`) to run the correct shell command sequence (e.g., `apt-get` on Ubuntu, downloading to `$HOME/.local/bin` on COS, etc.).
* `RequiresReconnect() bool`: Return `true` if the installer triggers a group change (like Docker adding the user to the `docker` group) that requires the runner to close and reopen the SSH connection to apply permissions.

### 3. Register the Installer

Register the installer with the global tools registry in the file's `init()` function:

```go
func init() {
    Register(MyTool, &MyToolInstaller{})
}
```

Tool installers are self-registering. The main runner (`main.go`) dynamically resolves installers from the registry at runtime, so no changes to `main.go` are required.
