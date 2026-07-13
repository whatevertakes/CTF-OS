#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

KUBECTL_VERSION=1.33.3
HELM_VERSION=3.18.4
TERRAFORM_VERSION=1.12.2
TOFU_VERSION=1.10.3
ORAS_VERSION=1.2.3
COSIGN_VERSION=2.5.0
TRIVY_VERSION=0.72.0
SYFT_VERSION=1.29.0
GRYPE_VERSION=0.96.0
OPA_VERSION=1.6.0
CONFTEST_VERSION=0.61.2
KUSTOMIZE_VERSION=5.7.1
YQ_VERSION=4.45.4
GCLOUD_VERSION=532.0.0-0

apt_install awscli azure-cli podman skopeo uidmap slirp4netns fuse-overlayfs
pip_install -r /opt/ctf-os/requirements/cloud.txt
# Keep Debian's AWS CLI isolated from the newer analysis boto3 stack. Without
# -S, /usr/local packages shadow its distro-pinned botocore and urllib3.
cat >/usr/local/bin/aws <<'EOF'
#!/bin/sh
export PYTHONPATH=/usr/lib/python3/dist-packages
exec /usr/bin/python3 -S /usr/bin/aws "$@"
EOF
chmod 0755 /usr/local/bin/aws
python3 -m venv /opt/checkov-venv
/opt/checkov-venv/bin/pip install --no-cache-dir checkov==3.2.446
ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov
python3 -m venv /opt/semgrep-venv
/opt/semgrep-venv/bin/pip install --no-cache-dir semgrep==1.127.1
ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
sed -i '/^ctf:/d' /etc/subuid
sed -i '/^ctf:/d' /etc/subgid

install_bin() { local url="$1" name="$2"; download "$url" "/tmp/$name"; install -m 0755 "/tmp/$name" "/usr/local/bin/$name"; }
install_bin "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" kubectl
download "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" /tmp/helm.tgz
tar -xzf /tmp/helm.tgz -C /tmp && install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm
download "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" /tmp/terraform.zip
unzip -q /tmp/terraform.zip -d /usr/local/bin
download "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip" /tmp/tofu.zip
unzip -q /tmp/tofu.zip -d /tmp/tofu && install -m 0755 /tmp/tofu/tofu /usr/local/bin/tofu
download "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" /tmp/oras.tgz
tar -xzf /tmp/oras.tgz -C /tmp oras && install -m 0755 /tmp/oras /usr/local/bin/oras
install_bin "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" cosign
download "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" /tmp/trivy.tgz
tar -xzf /tmp/trivy.tgz -C /tmp trivy && install -m 0755 /tmp/trivy /usr/local/bin/trivy
download "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" /tmp/syft.tgz
tar -xzf /tmp/syft.tgz -C /tmp syft && install -m 0755 /tmp/syft /usr/local/bin/syft
download "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" /tmp/grype.tgz
tar -xzf /tmp/grype.tgz -C /tmp grype && install -m 0755 /tmp/grype /usr/local/bin/grype
install_bin "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" opa
install_bin "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" yq
download "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" /tmp/conftest.tgz
tar -xzf /tmp/conftest.tgz -C /tmp conftest && install -m 0755 /tmp/conftest /usr/local/bin/conftest
download "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz" /tmp/kustomize.tgz
tar -xzf /tmp/kustomize.tgz -C /tmp kustomize && install -m 0755 /tmp/kustomize /usr/local/bin/kustomize

# Google Cloud CLI uses a fixed package version from the official repository.
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main' >/etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y --no-install-recommends "google-cloud-cli=$GCLOUD_VERSION"
rm -rf /var/lib/apt/lists/* /tmp/helm.tgz /tmp/linux-amd64 /tmp/*.zip /tmp/tofu /tmp/*.tgz /tmp/kubectl /tmp/cosign

for command in aws az gcloud kubectl helm terraform tofu podman skopeo oras cosign trivy syft grype kustomize opa conftest checkov semgrep yq; do require_command "$command"; done
for module in boto3 botocore google.cloud.storage google.auth azure.identity azure.storage.blob kubernetes yaml requests httpx jinja2; do require_import "$module"; done
