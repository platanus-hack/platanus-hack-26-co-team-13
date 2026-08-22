#!/usr/bin/env bash
set -euo pipefail

readonly APP_DIR="/opt/provenance-firewall"
readonly REQUEST="${SSH_ORIGINAL_COMMAND:-${1:-}}"

if [[ ! "$REQUEST" =~ ^deploy\ ([0-9a-f]{40})$ ]]; then
  printf 'Rejected deployment command.\n' >&2
  exit 2
fi

readonly REVISION="${BASH_REMATCH[1]}"
cd "$APP_DIR"
git fetch --quiet origin main
git cat-file -e "${REVISION}^{commit}"
git checkout --quiet --detach "$REVISION"
docker compose build --pull
docker compose up -d --remove-orphans
docker image prune -f >/dev/null

for attempt in {1..20}; do
  if curl --fail --silent --show-error http://127.0.0.1/api/v1/health >/dev/null; then
    printf 'Deployed %s successfully.\n' "$REVISION"
    exit 0
  fi
  sleep 3
done

docker compose ps
printf 'Deployment health check failed.\n' >&2
exit 1
