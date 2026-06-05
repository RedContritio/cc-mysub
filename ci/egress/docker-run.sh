#!/usr/bin/env bash
# 本机（含 macOS）在 privileged Linux 容器内跑 egress 审计。CI(ubuntu-latest) 直接跑 run.sh。
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="golang:1.23-bookworm"
STAGE="${1:---all}"

docker run --rm --privileged -v "$REPO:/repo" -w /repo "$IMG" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq iproute2 iptables dnsmasq dnsutils curl ca-certificates openssl >/dev/null
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs >/dev/null
  npm i -g @anthropic-ai/claude-code >/dev/null 2>&1
  node --version; claude --version || true
  bash /repo/ci/egress/run.sh '"$STAGE"'
'
