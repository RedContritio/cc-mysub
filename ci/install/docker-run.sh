#!/usr/bin/env bash
# 本机（含 macOS）在 privileged Linux 容器内跑 install.sh 自助入网 e2e。CI 可直接跑 run.sh。
# 仿 ci/egress/docker-run.sh：privileged golang 容器 + apt 装依赖 → bash /repo/ci/install/run.sh。
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="golang:1.23-bookworm"

docker run --rm --privileged -v "$REPO:/repo" -w /repo "$IMG" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  # curl/openssl/ca-certificates: PKI + 拉取; jq: install.sh 的 jget 解析配置;
  # python3: 本地 release/deploy.json http 服务 (python3 -m http.server)。
  apt-get install -y -qq curl ca-certificates openssl jq python3 >/dev/null
  bash /repo/ci/install/run.sh
'
