# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FastAPI-based REST API for scanning files using ClamAV antivirus. Supports file upload scanning, S3 object scanning with async result delivery via Kafka or RabbitMQ, and Redis-based result caching.

## Common Commands

### Task Runner (preferred)

```bash
task install          # Install Python dependencies
task dev              # Run locally with hot reload (port 8080)
task build            # Build Docker image
task test             # Run all tests in Docker
task test:unit        # Unit tests only
task test:integration # Integration tests
task test:cov         # Tests with coverage report
task test:local       # Run tests locally (no Docker)
task lint             # Run ruff linter
task format           # Format code with ruff
```

### Docker Compose Profiles

```bash
task run:simple       # ClamAV + Redis + MinIO + API
task run:kafka        # + Redpanda/Kafka
task run:rabbitmq     # + RabbitMQ
task run:all          # All services
task down             # Stop services
```

### Direct Commands

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
pytest -v                                    # All tests
pytest tests/unit -v                         # Unit tests only
pytest tests/integration -v -s               # Integration tests
pytest tests/unit/test_models.py::TestFileScanResult::test_clean_file -v  # Single test
```

## Architecture

**Layered structure:**
- `app/routers/scan.py` — All HTTP endpoints under `/api/v1/` (scan, health, version)
- `app/services/` — Service clients (ClamAV, Redis cache, S3, Kafka, RabbitMQ)
- `app/models.py` — Pydantic v2 request/response schemas
- `app/config.py` — Pydantic Settings, all config via environment variables
- `app/main.py` — FastAPI app with async lifespan for startup/shutdown

**Key patterns:**
- Services are global singletons initialized at startup via `@asynccontextmanager` lifespan
- Each service can be independently enabled/disabled via `ENABLE_*` env vars
- S3 scan endpoints (`/scan/kafka`, `/scan/rabbitmq`) run as FastAPI background tasks returning 202 Accepted
- Scan results are cached by SHA256 hash in Redis with configurable TTL (default 24h)
- ClamAV connects via Unix socket (default) or TCP, configurable via `CLAMAV_TYPE`

**API endpoints:**
- `POST /api/v1/scan` — Upload and scan files (multipart)
- `POST /api/v1/scan/kafka` — Async S3 scan, results to Kafka topic
- `POST /api/v1/scan/rabbitmq` — Async S3 scan, results to RabbitMQ queue
- `GET /api/v1/health` — Health check with per-service status
- `GET /api/v1/version` — API and ClamAV version info

## Testing

Tests use `pytest` with `unittest.mock` for external dependencies. Fixtures in `tests/conftest.py` provide a `TestClient`, mocked ClamAV client, and sample files (clean, EICAR virus pattern, oversized). Integration tests mock the service layer; unit tests mock socket/network connections.