#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${E2E_COMPOSE_FILE:-e2e-compose.yml}"
BUILD_FLAG="${E2E_BUILD_FLAG:---build}"
WAIT_TIMEOUT_SECONDS="${E2E_WAIT_TIMEOUT_SECONDS:-600}"

containers=(
  "resilmesh-sop-wo-temporal"
  "resilmesh-sap-neo4j"
  "resilmesh-sap-isim"
  "resilmesh-sap-casm-shared-worker"
  "resilmesh-sap-casm-easm-worker"
  "resilmesh-sap-casm-cve-connector"
  "resilmesh-sap-casm-redis"
)

cleanup() {
  echo
  echo "[cleanup] docker compose -f ${COMPOSE_FILE} down -v"
  docker compose -f "${COMPOSE_FILE}" down -v || true
}
trap cleanup EXIT

wait_for_container() {
  local name="$1"
  local deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))

  while (( SECONDS < deadline )); do
    if ! docker inspect "${name}" >/dev/null 2>&1; then
      sleep 3
      continue
    fi

    local health
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealth{{end}}' "${name}" 2>/dev/null || echo "unknown")"
    local state
    state="$(docker inspect -f '{{.State.Status}}' "${name}" 2>/dev/null || echo "unknown")"

    if [[ "${health}" == "healthy" ]]; then
      echo "[ready] ${name} (healthy)"
      return 0
    fi

    if [[ "${health}" == "nohealth" && "${state}" == "running" ]]; then
      echo "[ready] ${name} (running)"
      return 0
    fi

    sleep 5
  done

  echo "[error] Timed out waiting for container: ${name}"
  docker ps --format 'table {{.Names}}\t{{.Status}}'
  return 1
}

echo "[up] docker compose -f ${COMPOSE_FILE} up -d ${BUILD_FLAG}"
docker compose -f "${COMPOSE_FILE}" up -d ${BUILD_FLAG}

for name in "${containers[@]}"; do
  wait_for_container "${name}"
done

echo
echo "[deps] poetry install"
poetry install --no-interaction

echo
echo "[run] poetry run python -m test.e2e.run"
poetry run python -m test.e2e.run

