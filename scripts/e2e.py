#!/usr/bin/env python3
"""E2E test orchestration script."""

import os
import subprocess
import sys
import time
from typing import NoReturn


COMPOSE_FILE: str = os.getenv("E2E_COMPOSE_FILE", "e2e-compose.yml")
BUILD_FLAG: str = os.getenv("E2E_BUILD_FLAG", "--build")
WAIT_TIMEOUT_SECONDS: int = int(os.getenv("E2E_WAIT_TIMEOUT_SECONDS", "600"))
SKIP_CLEANUP: bool = os.getenv("E2E_SKIP_CLEANUP", "0") == "1"

CONTAINERS: list[str] = [
    "resilmesh-sop-wo-temporal",
    "resilmesh-sap-neo4j",
    "resilmesh-sap-isim",
    "resilmesh-sap-casm-shared-worker",
    "resilmesh-sap-casm-easm-worker",
    "resilmesh-sap-casm-cve-connector",
    "resilmesh-sap-casm-redis",
]


def cleanup() -> None:
    """Tear down Docker Compose stack."""
    print()
    print(f"[cleanup] docker compose -f {COMPOSE_FILE} down -v")
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "down", "-v"],
        check=False,
    )


def wait_for_container(name: str) -> None:
    """Wait for container to be healthy or running."""
    deadline: float = time.time() + WAIT_TIMEOUT_SECONDS

    while time.time() < deadline:
        if subprocess.run(
            ["docker", "inspect", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode != 0:
            time.sleep(3)
            continue

        health: str = subprocess.run(
            ["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealth{{end}}", name],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

        state: str = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", name],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

        if health == "healthy":
            print(f"[ready] {name} (healthy)")
            return

        if health == "nohealth" and state == "running":
            print(f"[ready] {name} (running)")
            return

        time.sleep(5)

    print(f"[error] Timed out waiting for container: {name}")
    subprocess.run(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"], check=False)
    sys.exit(1)


def main() -> NoReturn:
    """Run E2E tests."""
    try:
        print(f"[up] docker compose -f {COMPOSE_FILE} up -d {BUILD_FLAG}")
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", BUILD_FLAG],
            check=True,
        )

        for name in CONTAINERS:
            wait_for_container(name)

        print()
        print("[deps] poetry install")
        subprocess.run(["poetry", "install", "--no-interaction"], check=True)

        print()
        print("[run] poetry run python -m test.e2e.run")
        subprocess.run(["poetry", "run", "python", "-m", "test.e2e.run"], check=True)

    finally:
        if not SKIP_CLEANUP:
            cleanup()

    sys.exit(0)


if __name__ == "__main__":
    main()
