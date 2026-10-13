#!/usr/bin/env bash
# Run this inside the air-gapped Linux environment from the application repository.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /media/transfer/airgap-transfer-kit" >&2
  exit 64
fi

bundle_root=$(realpath -e "$1")
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python_bin=${PYTHON_BIN:-python3.11}
docker_bin=${DOCKER_BIN:-docker}

for command in "$python_bin" "$docker_bin" sha256sum; do
  command -v "$command" >/dev/null || [[ -x "$command" ]] || {
    echo "Missing required command: $command" >&2
    exit 69
  }
done

(cd "$bundle_root" && sha256sum --check SHA256SUMS)
image_archive="$bundle_root/images/runtime-images.tar"
if [[ "$docker_bin" == *.exe && -x "$(command -v wslpath || true)" ]]; then
  image_archive=$(wslpath -w "$image_archive")
fi
"$docker_bin" load --input "$image_archive"

if [[ -f "$bundle_root/models/models.tar" ]]; then
  mkdir -p "$repo_root/models"
  tar -C "$repo_root/models" -xf "$bundle_root/models/models.tar"
fi

"$python_bin" -m venv "$repo_root/.venv"
"$repo_root/.venv/bin/python" -m pip install --no-index --find-links "$bundle_root/wheels" \
  --no-build-isolation -e "$repo_root[dev,nist-mapper]"
echo "Offline installation complete. Copy .env.example to .env, set passwords/model paths, then start docker-compose.airgap.yml."
