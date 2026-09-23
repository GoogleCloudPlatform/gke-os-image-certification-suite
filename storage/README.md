# GKE Storage Qualification

This directory contains storage e2e tests to validate OS images for GKE.

These are more heavyweight than the main test of
`gke-image-certification-suite`. They create GCE resources (instances and
disks) to verify that subsystems like udev hotplug and local SSD work as
expected.

## Running the Qualification

The script `./run-gke-pd-qualification.sh` will clone the PD CSI repository
(kubernetes.io/gcp-compute-persistent-disk-csi-driver) to this directory and run
a CSI E2E qualification suite. The script assumes a GNU coreutils environment
where git and golang have been installed. It will ensure other tools, like
ginkgo (a golang testing framework). See comments in the script for details and
customization.

It requires a GCE project and service account to be set in the `PROJECT` and
`IAM_NAME` env vars, respectively. An example of how to setup the service
account can be found in the PD CSI repo at `deploy/setup-project.sh`; only the
SA is needed, an SA key does not need to be exported.

If a custom OS is tested, add an `--image-url` flag with the full path to the
image you wish to qualify, for example
`projects/ubuntu-os-cloud/global/images/family/ubuntu-minimal-2404-lts-amd64`.

