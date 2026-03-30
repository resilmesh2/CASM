# Local E2E Guide

This guide describes how to run the end-to-end test flow on a local machine before merging to `main`.

The local E2E flow does two things:

1. Starts the full Docker-backed test stack from `e2e-compose.yml`.
2. Runs `python -m test.e2e.run`, which first resets the test Neo4j graph and Redis DB, then triggers the workflows in sequence and checks the stored GraphQL results against snapshots.

## Prerequisites

- Docker with Compose support
- Python 3.12
- Poetry
- An NVD API key exported as `NVD_KEY` for reliable CVE connector execution

Install Python dependencies once:

```bash
poetry install
```

## Config Files

Two config files matter during a local E2E run:

- `docker/test.config.yaml`
  Used inside the worker and ISIM containers started by `e2e-compose.yml`.
- `test/e2e/config.yaml`
  Used by the local `poetry run python -m test.e2e.run` process when it queries the REST and GraphQL endpoints on `localhost`.

The checked-in defaults already match the isolated local E2E stack:

- Temporal: `localhost:17233`
- ISIM REST: `http://localhost:18000`
- ISIM GraphQL: `http://localhost:14001/graphql`
- Neo4j: `bolt://localhost:17687`
- Redis: `localhost:16379`

## Run The Stack

Export the NVD key in the same shell where you will start Docker and run the test runner:

```bash
export NVD_KEY=your_nvd_api_key
```

Build and start the local E2E environment:

```bash
docker compose -f e2e-compose.yml up -d --build
```

Optional health checks:

```bash
docker compose -f e2e-compose.yml ps
docker compose -f e2e-compose.yml logs --tail=50 resilmesh-sop-wo-temporal
```

Wait until Temporal is healthy and the main services are up before starting the Python runner.

## Run The E2E Orchestration

Start the orchestrated E2E flow from the repository root:

```bash
poetry run python -m test.e2e.run
```

This runner:

- Resets the local E2E Neo4j graph and configured Redis DB before any workflow runs
- Connects to Temporal on `localhost:17233`
- Triggers Nmap, EASM, CVE connector, Nuclei, and component workflows
- Verifies the resulting GraphQL payloads against the snapshots in `test/e2e/__snapshots__/`

If the command exits with status `0`, the local E2E flow passed.

The reset step is destructive for the local E2E stack data. Do not point `test/e2e/config.yaml` at a shared or non-test Neo4j/Redis instance when running this command.

To intentionally rewrite snapshots during the same flow, pass `--snapshot-update`:

```bash
poetry run python -m test.e2e.run --snapshot-update
```

## Useful Endpoints While Debugging

- Temporal UI: `http://localhost:18080`
- Neo4j Browser: `http://localhost:17474`
- ISIM REST: `http://localhost:18000`
- ISIM GraphQL: `http://localhost:14001/graphql`

## Cleanup

Stop the stack and remove volumes after the run:

```bash
docker compose -f e2e-compose.yml down -v
```

## Troubleshooting

If the run times out or fails, start with:

```bash
docker compose -f e2e-compose.yml ps
docker compose -f e2e-compose.yml logs --tail=100 resilmesh-sap-casm-shared-worker
docker compose -f e2e-compose.yml logs --tail=100 resilmesh-sap-casm-cve-connector-worker
docker compose -f e2e-compose.yml logs --tail=100 resilmesh-sop-wo-temporal
```

Common causes:

- `NVD_KEY` was not exported before `docker compose up`
- One of the local ports is already occupied
- The stack was started, but Temporal or Neo4j was not healthy yet when the runner began

## Snapshot Updates

Normal E2E runs should not update snapshots.

If the behavior changed intentionally, rerun the orchestrator with `--snapshot-update` and review the snapshot diff carefully before committing it.
