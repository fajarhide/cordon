#!/usr/bin/env bash
# Starts a daemon for a recording. Container backend on podman, token set, so
# the auth checks and the data plane checks both run rather than skip.
set -euo pipefail
ROOT="$HOME/.cordon-rec"
rm -rf "$ROOT"; mkdir -p "$ROOT"
pkill -f 'cordon serve' 2>/dev/null || true
CORDON_ROOT="$ROOT" \
CORDON_LISTEN=tcp:127.0.0.1:7900 \
CORDON_TOKEN=rec-token \
CORDON_BACKEND=container \
CORDON_CONTAINER_CLI=podman \
  /tmp/cbin/cordon serve >/tmp/cordon-rec.log 2>&1 &
for _ in $(seq 60); do
  curl -sf http://127.0.0.1:7900/v1/health >/dev/null && exit 0
  sleep 0.25
done
echo "daemon tidak naik"; cat /tmp/cordon-rec.log; exit 1
