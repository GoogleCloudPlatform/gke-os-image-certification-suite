#!/bin/bash
#
# Env Vars:
#
# PROJECT (required): GCP project
#
# IAM_NAME (required): Service account to use for GCE resource creation. See the readme
#   for more information.
#
# IMAGE_URL: The GCP VM image to test. Defaults to an ubuntu version.
#
# ZONE: The zone to test. Defaults to us-central1-c.
#
# MACHINE_TYPE: The machine type to test. A single instance will be
#   created. Defaults to n2d.  See
#   `gcp-compute-persistent-disk-csi-driver/test/e2e/tests/setup_e2e_test.go`
#   for related flags, eg `--disk-type-default` may need to be changed to
#   `hyperdisk-balanced` if a gen4 machine type is used. `--min-cpu-platform`
#   may also need to be set.
#
# Args:
#   Any extra args will be passd through to the ginkgo command.

set -xeuo -o pipefail

script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

: "${PROJECT:?PROJECT is required}"
: "${IAM_NAME:?IAM_NAME is required}"

cd "$script_dir"

# Only clone if we don't already have a repo. This gives you the opportunity,
# for example, to manually check out a version and go to a particular commit.
if [ ! -d ./gcp-compute-persistent-disk-csi-driver/ ]; then
  git clone https://github.com/kubernetes-sigs/gcp-compute-persistent-disk-csi-driver.git
fi

# Ensure GOPATH is unset as we aren't in the legacy go directory (`${GOPATH}/src` etc)
export GOPATH=
cd ./gcp-compute-persistent-disk-csi-driver

ginkgo_version=$(grep github.com/onsi/ginkgo/v2 go.mod | while read -r _ version; do echo $version; break; done)

go install github.com/onsi/ginkgo/v2/ginkgo@"${ginkgo_version}"

./test/run-e2e-local.sh --ginkgo.focus '\[OS-Qualification\]' \
  --instances-per-zone 1 --machine-type-mw none  --delete-instances \
  --zones "${ZONE:-us-central1-c}" --machine-type "${MACHINE_TYPE:-n2d-standard-4}" \
  --min-cpu-platform "${MIN_CPU_PLATFORM:-none}" \
  --image-url "${IMAGE_URL:-projects/ubuntu-os-cloud/global/images/family/ubuntu-minimal-2404-lts-amd64}" \
  --subnetwork "${SUBNETWORK:-}" "$@"
