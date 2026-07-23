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
KUBECTL_SHA256=2fcf65c64f352742dc253a25a7c95617c2aba79843d1b74e585c69fe4884afb0
HELM_SHA256=f8180838c23d7c7d797b208861fecb591d9ce1690d8704ed1e4cb8e2add966c1
TERRAFORM_SHA256=1eaed12ca41fcfe094da3d76a7e9aa0639ad3409c43be0103ee9f5a1ff4b7437
TOFU_SHA256=acf330602ec6ae29ba68dd5d8eb1f645811ae9809231ecdccd4774b21d5c79bc
ORAS_SHA256=b4efc97a91f471f323f193ea4b4d63d8ff443ca3aab514151a30751330852827
COSIGN_SHA256=1f6c194dd0891eb345b436bb71ff9f996768355f5e0ce02dde88567029ac2188
TRIVY_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
SYFT_SHA256=5b01c831cb5d712899d9179cabd80f55b6708dbd36af981ce27e59b6569e6690
GRYPE_SHA256=11196534554bedcaeb4050450ea884c810c26e893ef2073ba72f84e2e5cf3b38
OPA_SHA256=0deb8a2d40fc5d75316530f50f63456a3000b20b50ef4158a81003b4aebf4892
YQ_SHA256=b96de04645707e14a12f52c37e6266832e03c29e95b9b139cddcae7314466e69
CONFTEST_SHA256=5b3dcacb37c970645a9ddc7ebf776f11f727d1abe4e3e60c2381c2398c864d8f
KUSTOMIZE_SHA256=ea375e7372f9aa029129d4b2d16c66b7750b7f1213c4f66f910d981c895818d8
GCLOUD_KEY_SHA256=3ecc63922b7795eb23fdc449ff9396f9114cb3cf186d6f5b53ad4cc3ebfbb11f

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
