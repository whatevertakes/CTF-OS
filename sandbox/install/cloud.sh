#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

KUBECTL_VERSION=1.36.3
HELM_VERSION=4.2.3
TERRAFORM_VERSION=1.15.8
TOFU_VERSION=1.12.5
ORAS_VERSION=1.3.3
COSIGN_VERSION=3.1.2
TRIVY_VERSION=0.72.0
SYFT_VERSION=1.49.0
GRYPE_VERSION=0.116.0
OPA_VERSION=1.18.2
CONFTEST_VERSION=0.68.2
KUSTOMIZE_VERSION=5.8.1
YQ_VERSION=4.53.3
GCLOUD_VERSION=532.0.0-0
KUBECTL_SHA256=ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336
HELM_SHA256=e9b88b4ee95b18c706839c28d3a0220e5bc470e9cd9262410c90793c45ff8b7c
TERRAFORM_SHA256=d25ce7b6902013ad905db3d2eab0be4cd905887fe88b81a6171b8d5503c31f3d
TOFU_SHA256=dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536
ORAS_SHA256=9ce999f8d2de03fc03968b29d743077a58783e545e5eaa53917ca177352d0e59
COSIGN_SHA256=f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf
TRIVY_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
SYFT_SHA256=7aa2f03ee92739cf643279ba3990548b9925d4e22cae13f46831ee62821147fe
GRYPE_SHA256=40aff724297312f91ea390d003bed8d8651c74cc7f5b26732db80b3a408d2fc5
OPA_SHA256=9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8
YQ_SHA256=fa52a4e758c63d38299163fbdd1edfb4c4963247918bf9c1c5d31d84789eded4
CONFTEST_SHA256=e8144c6d6d2ae0260b869caa60c7c262a1f95ac63ec1e5d2fb19be452d606347
KUSTOMIZE_SHA256=029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d
GCLOUD_KEY_SHA256=3ecc63922b7795eb23fdc449ff9396f9114cb3cf186d6f5b53ad4cc3ebfbb11f

apt_install awscli azure-cli podman skopeo uidmap slirp4netns fuse-overlayfs
pip_install_locked /opt/ctf-os/requirements-lock/cloud.txt
# Keep Debian's AWS CLI isolated from the newer analysis boto3 stack. Without
# -S, /usr/local packages shadow its distro-pinned botocore and urllib3.
cat >/usr/local/bin/aws <<'EOF'
#!/bin/sh
export PYTHONPATH=/usr/lib/python3/dist-packages
exec /usr/bin/python3 -S /usr/bin/aws "$@"
EOF
chmod 0755 /usr/local/bin/aws
# Azure CLI is a Debian Python application too. Keep it on the same isolated
# distro path so newer analysis libraries under /usr/local cannot shadow its
# pinned dependencies.
cat >/usr/local/bin/az <<'EOF'
#!/bin/sh
export PYTHONPATH=/usr/lib/python3/dist-packages
exec /usr/bin/python3 -S /usr/bin/az "$@"
EOF
chmod 0755 /usr/local/bin/az
python3 -m venv /opt/checkov-venv
venv_install_locked \
  /opt/checkov-venv /opt/ctf-os/requirements-lock/isolated/checkov.txt
ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov
python3 -m venv /opt/semgrep-venv
venv_install_locked \
  /opt/semgrep-venv /opt/ctf-os/requirements-lock/isolated/semgrep.txt
ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
sed -i '/^ctf:/d' /etc/subuid
sed -i '/^ctf:/d' /etc/subgid

install_bin() { local url="$1" name="$2" sha256="$3"; download_sha256 "$url" "/tmp/$name" "$sha256"; install -m 0755 "/tmp/$name" "/usr/local/bin/$name"; }
install_bin "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" kubectl "$KUBECTL_SHA256"
download_sha256 "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" /tmp/helm.tgz "$HELM_SHA256"
tar -xzf /tmp/helm.tgz -C /tmp && install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm
download_sha256 "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" /tmp/terraform.zip "$TERRAFORM_SHA256"
unzip -q /tmp/terraform.zip -d /usr/local/bin
download_sha256 "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip" /tmp/tofu.zip "$TOFU_SHA256"
unzip -q /tmp/tofu.zip -d /tmp/tofu && install -m 0755 /tmp/tofu/tofu /usr/local/bin/tofu
download_sha256 "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" /tmp/oras.tgz "$ORAS_SHA256"
tar -xzf /tmp/oras.tgz -C /tmp oras && install -m 0755 /tmp/oras /usr/local/bin/oras
install_bin "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" cosign "$COSIGN_SHA256"
download_sha256 "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" /tmp/trivy.tgz "$TRIVY_SHA256"
tar -xzf /tmp/trivy.tgz -C /tmp trivy && install -m 0755 /tmp/trivy /usr/local/bin/trivy
download_sha256 "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" /tmp/syft.tgz "$SYFT_SHA256"
tar -xzf /tmp/syft.tgz -C /tmp syft && install -m 0755 /tmp/syft /usr/local/bin/syft
download_sha256 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" /tmp/grype.tgz "$GRYPE_SHA256"
tar -xzf /tmp/grype.tgz -C /tmp grype && install -m 0755 /tmp/grype /usr/local/bin/grype
install_bin "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" opa "$OPA_SHA256"
install_bin "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" yq "$YQ_SHA256"
download_sha256 "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" /tmp/conftest.tgz "$CONFTEST_SHA256"
tar -xzf /tmp/conftest.tgz -C /tmp conftest && install -m 0755 /tmp/conftest /usr/local/bin/conftest
download_sha256 "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz" /tmp/kustomize.tgz "$KUSTOMIZE_SHA256"
tar -xzf /tmp/kustomize.tgz -C /tmp kustomize && install -m 0755 /tmp/kustomize /usr/local/bin/kustomize

# Google Cloud CLI uses a fixed package version from the official repository.
download_sha256 https://packages.cloud.google.com/apt/doc/apt-key.gpg /tmp/cloud.google.gpg "$GCLOUD_KEY_SHA256"
gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg /tmp/cloud.google.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main' >/etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y --no-install-recommends "google-cloud-cli=$GCLOUD_VERSION"
rm -rf /var/lib/apt/lists/* /tmp/helm.tgz /tmp/linux-amd64 /tmp/*.zip /tmp/tofu /tmp/*.tgz /tmp/kubectl /tmp/cosign

for command in aws az gcloud kubectl helm terraform tofu podman skopeo oras cosign trivy syft grype kustomize opa conftest checkov semgrep yq; do require_command "$command"; done
for module in boto3 botocore google.cloud.storage google.auth azure.identity azure.storage.blob kubernetes yaml requests httpx jinja2; do require_import "$module"; done
aws --version 2>&1 | grep -Fq 'aws-cli/2.9.19'
az version | grep -Fq '"azure-cli": "2.45.0"'
gcloud --version | grep -Fq 'Google Cloud SDK 532.0.0'
semgrep --version | grep -Fxq '1.171.0'
checkov --version | grep -Fxq '3.2.446'
