#!/usr/bin/env bash
set -euo pipefail

expected_revision="0fb5b4aa1398281c2fd3dbe14db147e05b61f201"
mode="${1:-all}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
source_dir="$script_dir/webauthn-circom"
submodule_path="examples/webauthn/webauthn-circom"
output_dir="${2:-$repo_root/target/webauthn}"

case "$mode" in
  all|graph|reference) ;;
  *)
    echo "usage: $0 [all|graph|reference] [OUTPUT_DIR]" >&2
    exit 2
    ;;
esac

git -C "$repo_root" submodule update --init --recursive -- "$submodule_path"
actual_revision="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  echo "unexpected WebAuthn source revision: $actual_revision" >&2
  exit 1
fi

mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
circuit="$source_dir/scripts/webauthn_default.circom"
input="$source_dir/scripts/input_webauthn_default.json"

if [[ ! -e "$source_dir/node_modules/circomlib/circuits/sha256/sha256.circom" ]]; then
  echo "install the pinned source dependencies first:" >&2
  echo "  corepack yarn --cwd $source_dir install --frozen-lockfile" >&2
  exit 1
fi

if [[ "$mode" == "all" || "$mode" == "graph" ]]; then
  cargo run --release --manifest-path "$repo_root/Cargo.toml" \
    -p circom-witness-graph-builder -- --O1 \
    "$circuit" "$output_dir/webauthn.graph"
fi

if [[ "$mode" == "all" || "$mode" == "reference" ]]; then
  command -v circom >/dev/null || {
    echo "reference generation requires Circom 2.2.2 on PATH" >&2
    exit 1
  }
  command -v node >/dev/null || {
    echo "reference generation requires Node.js on PATH" >&2
    exit 1
  }
  circom_version="$(circom --version)"
  if [[ "$circom_version" != *"2.2.2"* ]]; then
    echo "expected Circom 2.2.2, got: $circom_version" >&2
    exit 1
  fi
  wasm_dir="$output_dir/reference-wasm"
  mkdir -p "$wasm_dir"
  (
    cd -- "$source_dir/scripts"
    circom --O1 webauthn_default.circom --wasm --output "$wasm_dir"
  )
  node "$wasm_dir/webauthn_default_js/generate_witness.js" \
    "$wasm_dir/webauthn_default_js/webauthn_default.wasm" \
    "$input" "$output_dir/reference.wtns"
fi

echo "source_revision=$actual_revision"
echo "output_dir=$output_dir"
