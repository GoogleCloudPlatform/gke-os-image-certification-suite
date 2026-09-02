# GKE Guest OS Image Certification E2E Test Runner

A parallel, fully concurrent end-to-end verification script for certifying GKE COS and Ubuntu images.

## Parameters

The script is explicitly configured using standard command-line flags:

| Flag | Description | Default Fallback |
| :--- | :--- | :--- |
| `--gcp-project` | The target GCP project ID to provision VMs in. | Active configuration from `gcloud config get-value project` |
| `--gcp-zone` | The target GCE Zone to provision VMs in. | `us-central1-b` |

## Command Examples

### 1. Run with Command-Line Flags (Preferred)
```bash
./e2e/run_e2e.py --gcp-project=my-custom-project-id --gcp-zone=us-west1-a
```

### 2. Run with Defaults
Resolves the project from your active `gcloud` configuration and runs in `us-central1-b`:
```bash
./e2e/run_e2e.py
```
