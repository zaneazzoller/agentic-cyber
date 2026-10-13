#!/usr/bin/env bash
# Run this on a connected Linux/WSL host with Docker access. Do not run it in the air-gapped zone.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: [VLLM_IMAGE=<exact-current-vllm-image>] $0 /path/to/airgap-transfer-kit" >&2
  exit 64
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bundle_root=$(realpath -m "$1")
python_bin=${PYTHON_BIN:-python3.11}
docker_bin=${DOCKER_BIN:-docker}
vllm_image=${VLLM_IMAGE:-}
model_store=${MODEL_STORE:-}

for command in "$python_bin" "$docker_bin" sha256sum tar; do
  command -v "$command" >/dev/null || [[ -x "$command" ]] || {
    echo "Missing required command: $command" >&2
    exit 69
  }
done

if [[ -e "$bundle_root" ]]; then
  echo "Transfer-kit destination already exists; choose a new empty path: $bundle_root" >&2
  exit 73
fi
mkdir -p "$bundle_root/wheels" "$bundle_root/images" "$bundle_root/models"

echo "Downloading Linux Python wheels (including all transitive dependencies)..."
"$python_bin" -m pip download \
  --dest "$bundle_root/wheels" \
  --only-binary=:all: \
  --requirement "$repo_root/requirements-airgap.txt"

echo "Pulling and exporting application runtime images..."
runtime_images=("postgres:16-alpine" "apache/kafka:3.8.0")
if [[ -n "$vllm_image" ]]; then
  runtime_images+=("$vllm_image")
else
  echo "No VLLM_IMAGE supplied; exporting PostgreSQL and Kafka only."
fi
for image in "${runtime_images[@]}"; do
  "$docker_bin" pull "$image"
done
image_archive="$bundle_root/images/runtime-images.tar"
if [[ "$docker_bin" == *.exe && -x "$(command -v wslpath || true)" ]]; then
  image_archive=$(wslpath -w "$image_archive")
fi
"$docker_bin" image save --output "$image_archive" "${runtime_images[@]}"
printf '%s\n' "${runtime_images[@]}" > "$bundle_root/images/images.txt"

if [[ -n "$model_store" ]]; then
  if [[ ! -d "$model_store" ]]; then
    echo "MODEL_STORE is not a directory: $model_store" >&2
    exit 66
  fi
  echo "Copying staged model directories..."
  tar -C "$model_store" -cf "$bundle_root/models/models.tar" .
else
  echo "WARNING: no MODEL_STORE; transfer local model directories separately." >&2
fi

cp "$repo_root/requirements-airgap.txt" "$bundle_root/"
cp "$repo_root/docker-compose.yml" "$repo_root/docker-compose.airgap.yml" "$repo_root/.env.example" "$bundle_root/"
sha256sum "$bundle_root"/wheels/* "$bundle_root"/images/runtime-images.tar > "$bundle_root/SHA256SUMS"
if [[ -f "$bundle_root/models/models.tar" ]]; then
  sha256sum "$bundle_root/models/models.tar" >> "$bundle_root/SHA256SUMS"
fi

{
  echo "Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Python: $($python_bin --version)"
  echo "vLLM image: ${vllm_image:-not included}"
  echo "Images: ${runtime_images[*]}"
  echo "Model store included: $([[ -n "$model_store" ]] && echo yes || echo no)"
} > "$bundle_root/BUNDLE-CONTENTS.txt"
echo "Air-gap transfer kit created at: $bundle_root"
