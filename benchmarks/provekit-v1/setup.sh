#!/usr/bin/env bash

set -euo pipefail

benchmark_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${benchmark_root}/../.." && pwd)"

git -C "${repository_root}" submodule update --init --recursive \
  benchmarks/provekit-v1/upstream \
  benchmarks/provekit-v1/sources/self \
  benchmarks/provekit-v1/sources/world-id-protocol \
  benchmarks/provekit-v1/sources/webauth-circom

corepack pnpm --dir "${benchmark_root}/sources/self" install --frozen-lockfile
corepack yarn --cwd "${benchmark_root}/sources/webauth-circom" install --frozen-lockfile

passport_source_root="${benchmark_root}/upstream/target/v1-benchmarks/sources"
mkdir -p "${passport_source_root}"
if [[ ! -e "${passport_source_root}/self" ]]; then
  ln -s "${benchmark_root}/sources/self" "${passport_source_root}/self"
fi

echo "ProveKit V1 Circom benchmark sources are ready."
