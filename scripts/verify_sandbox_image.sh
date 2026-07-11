#!/usr/bin/env bash
set -euo pipefail

image="${1:-ctf-os-sandbox:latest}"
label="ctf-os.sandbox-smoke=$$"
containers=()
cleanup() {
  if ((${#containers[@]})); then docker rm -f "${containers[@]}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT INT TERM

docker image inspect "$image" >/dev/null
docker run --rm --entrypoint /bin/bash "$image" -lc '
set -euo pipefail
test -s /tools.txt
python3 --version
gcc --version | head -n1
gdb --version | head -n1
r2 -v
python3 -c "import pwn"
python3 -c "import angr"
python3 -c "import z3"
python3 -c "import Crypto"
python3 -c "import volatility3"
python3 -c "import torch; print(torch.__version__); assert torch.version.cuda is None"
python3 -c "import keras; print(keras.__version__)"
sage --version
RsaCtfTool --help >/dev/null
test -x "$(command -v flatter)"
cado-nfs.py --help >/dev/null 2>&1 || cado-nfs --help >/dev/null
binwalk --help >/dev/null
exiftool -ver
tshark --version | head -n1
ffmpeg -version | head -n1
zsteg --help >/dev/null
podman --version
buildah --version
'

image_id="$(docker image inspect "$image" --format '{{.Id}}')"
for suffix in one two; do
  containers+=("$(docker run -d --label ctf-os=true --label "$label" \
    --memory 16g --cpus 2.0 --entrypoint /bin/bash "$image" -lc 'sleep 60')")
done
for container in "${containers[@]}"; do
  test "$(docker inspect "$container" --format '{{.HostConfig.Memory}}')" = "17179869184"
  test "$(docker inspect "$container" --format '{{.HostConfig.NanoCpus}}')" = "2000000000"
  test "$(docker inspect "$container" --format '{{.HostConfig.MemoryReservation}}')" = "0"
  test -z "$(docker inspect "$container" --format '{{.HostConfig.CpusetCpus}}')"
  test "$(docker inspect "$container" --format '{{.Image}}')" = "$image_id"
done
printf 'Nested Podman support: '
docker run --rm --entrypoint /bin/bash "$image" -lc 'podman info >/dev/null 2>&1' \
  && echo enabled || echo installed-but-disabled-by-runtime

docker image inspect "$image" --format 'Image ID: {{.Id}}'
docker image inspect "$image" --format 'Image size: {{.Size}} bytes'
docker image inspect "$image" --format 'Architecture: {{.Architecture}}'
