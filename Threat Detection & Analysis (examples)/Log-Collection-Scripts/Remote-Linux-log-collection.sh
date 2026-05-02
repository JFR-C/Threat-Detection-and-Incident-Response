#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="$1"          # e.g. server01
SSH_USER="${2:-root}"     # or a sudo-capable user
OUTPUT_ROOT="${3:-/ir/collections}"

if [[ -z "$TARGET_HOST" ]]; then
  echo "Usage: $0 <host> [ssh_user] [output_root]" >&2
  exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
HOST_DIR="${OUTPUT_ROOT}/${TARGET_HOST}"
mkdir -p "$HOST_DIR"

REMOTE_STAGING="/tmp/ir_staging_${TIMESTAMP}"

ssh "${SSH_USER}@${TARGET_HOST}" "set -euo pipefail
  sudo mkdir -p '${REMOTE_STAGING}'
  sudo chmod 700 '${REMOTE_STAGING}'

  # Copy traditional logs
  if [ -d /var/log ]; then
    sudo tar --preserve-permissions --preserve-order -czf '${REMOTE_STAGING}/var_log.tar.gz' /var/log
  fi

  # Export systemd journal (if present)
  if command -v journalctl >/dev/null 2>&1; then
    sudo journalctl --no-pager --since='1970-01-01' > '${REMOTE_STAGING}/journal_full.log'
  fi

  # Optional: wtmp/btmp/utmp
  for f in /var/log/wtmp /var/log/btmp /var/run/utmp; do
    if [ -f \"\$f\" ]; then
      sudo cp \"\$f\" '${REMOTE_STAGING}/'
    fi
  done

  # Compress staging
  sudo tar --preserve-permissions --preserve-order -czf '${REMOTE_STAGING}.tar.gz' -C '$(dirname "${REMOTE_STAGING}")' '$(basename "${REMOTE_STAGING}")'

  # Hash for integrity
  sudo sha256sum '${REMOTE_STAGING}.tar.gz' | sudo tee '${REMOTE_STAGING}.tar.gz.sha256'
"

# Pull archive + hash
scp "${SSH_USER}@${TARGET_HOST}:${REMOTE_STAGING}.tar.gz" "${HOST_DIR}/"
scp "${SSH_USER}@${TARGET_HOST}:${REMOTE_STAGING}.tar.gz.sha256" "${HOST_DIR}/"

echo "Collected: ${HOST_DIR}/$(basename "${REMOTE_STAGING}.tar.gz")"
echo "Hash:      ${HOST_DIR}/$(basename "${REMOTE_STAGING}.tar.gz").sha256"
