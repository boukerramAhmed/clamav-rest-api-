# ClamAV API

A FastAPI-based REST API for scanning files using ClamAV antivirus engine.

## Features

- **Multiple File Scanning**: Upload and scan up to 10 files in a single request
- **ClamAV Integration**: Supports both Unix socket and TCP connections to ClamAV daemon
- **S3/MinIO Support**: Scan files directly from S3-compatible storage
- **Message Broker Flexibility**:
  - **Kafka/Redpanda**: Asynchronous scanning with Redpanda message broker
  - **RabbitMQ**: Asynchronous scanning with RabbitMQ message broker
- **Result Caching**: Redis-based caching for faster repeated scans
- **Detailed Results**: Returns comprehensive scan results including:
  - File metadata (filename, size, SHA256 hash)
  - Scan status (clean, infected, error)
  - Virus signatures (if infected)
  - Scan duration and timestamp
  - Cache status
- **Health Checks**: Comprehensive health check endpoints with service status reporting
- **Service Flexibility**: Enable/disable services via environment variables
- **Docker Compose Profiles**: Run only the services you need (simple, Kafka, RabbitMQ, or all)
- **Simple Mode**: Lightweight deployment with core services only (ClamAV, Redis, MinIO, API)
- **Production Ready**: Includes Kubernetes deployment manifests and Docker container

## Requirements

### Python Dependencies
- Python 3.11+
- FastAPI
- Uvicorn
- Python clamd library
- boto3 (for S3/MinIO support)
- redis (for caching)
- aiokafka (for Kafka/Redpanda support)
- pika (for RabbitMQ support)
- pydantic-settings

### External Services
- ClamAV daemon (either locally or accessible via TCP)
- Redis (optional, for result caching)
- MinIO/S3 (optional, for S3 scanning)
- Redpanda/Kafka (optional, for async Kafka-based scanning)
- RabbitMQ (optional, for async RabbitMQ-based scanning)

### Tools
- Docker & Docker Compose (for containerized deployment)
- Task (https://taskfile.dev/) (for task management - optional but recommended)

## Installation

### Local Development

1. Clone the repository and navigate to the project:
```bash
cd /Users/ahmedboukerram/workdir/ops/clamav-api
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### Docker Compose

Docker Compose supports profiles for running different service combinations:

**Simple Mode** (default - recommended for basic scanning):
```bash
docker compose up -d
```
Runs: ClamAV, Redis, MinIO, API (core services only, no message brokers)

**With Kafka Profile** (for async scanning with Kafka/Redpanda):
```bash
docker compose --profile kafka up -d
```
Runs: Core services + Redpanda, Kafka-init, Console (UI at http://localhost:8081)

**With RabbitMQ Profile** (for async scanning with RabbitMQ):
```bash
docker compose --profile rabbitmq up -d
```
Runs: Core services + RabbitMQ (Management UI at http://localhost:15672)

**With All Services** (includes both Kafka and RabbitMQ):
```bash
docker compose --profile all up -d
```
Runs: All services (ClamAV, Redis, MinIO, API, Kafka, Console, RabbitMQ)

**Stopping Services**:
```bash
# Stop simple mode (default)
docker compose down

# Stop specific profile
docker compose --profile kafka down
docker compose --profile rabbitmq down

# Stop all services
docker compose --profile all down
```

### Docker (Manual)

1. Build the Docker image:
```bash
docker build -t clamav-api:latest .
```

2. Run the container:
```bash
# Using Unix socket (if ClamAV is running on the host)
docker run -p 8080:8080 \
  -v /var/run/clamav:/var/run/clamav:ro \
  -e CLAMAV_TYPE=unix \
  clamav-api:latest

# Using TCP connection
docker run -p 8080:8080 \
  -e CLAMAV_TYPE=tcp \
  -e CLAMAV_HOST=clamav-host \
  -e CLAMAV_PORT=3310 \
  clamav-api:latest
```

### Kubernetes

1. Update the image in `k8s/deployment.yaml` with your registry:
```yaml
image: your-registry/clamav-api:latest
```

2. Apply the manifests:
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

3. Verify the deployment:
```bash
kubectl get pods -n portal -l app=clamav-api
kubectl logs -n portal -l app=clamav-api
```

## Configuration

### ClamAV Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `CLAMAV_TYPE` | unix | Connection type: "unix" or "tcp" |
| `CLAMAV_UNIX_SOCKET` | /var/run/clamav/clamd.ctl | Unix socket path for ClamAV |
| `CLAMAV_HOST` | localhost | ClamAV hostname (for TCP) |
| `CLAMAV_PORT` | 3310 | ClamAV port (for TCP) |
| `CLAMAV_TIMEOUT` | 30 | ClamAV scan timeout (seconds) |

### File Upload Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_FILE_SIZE` | 104857600 | Maximum file size (100MB) |
| `MAX_FILES` | 10 | Maximum files per request |
| `UPLOAD_TIMEOUT` | 300 | Upload timeout (seconds) |

### Redis Cache Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | localhost | Redis hostname |
| `REDIS_PORT` | 6379 | Redis port |
| `CACHE_TTL` | 86400 | Cache time-to-live (seconds, 24 hours) |
| `CACHE_ENABLED` | true | Enable/disable caching |

### S3/MinIO Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `S3_ENDPOINT` | http://localhost:9000 | S3/MinIO endpoint URL |
| `S3_ACCESS_KEY` | minioadmin | S3 access key |
| `S3_SECRET_KEY` | minioadmin | S3 secret key |
| `S3_BUCKET` | scans | Default S3 bucket name |
| `ENABLE_S3` | true | Enable/disable S3 scanning |

### Kafka/Redpanda Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | localhost:9092 | Kafka broker addresses |
| `KAFKA_TOPIC` | scan-results | Default Kafka topic for results |
| `ENABLE_KAFKA` | true | Enable/disable Kafka integration |

### RabbitMQ Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `RABBITMQ_HOST` | localhost | RabbitMQ hostname |
| `RABBITMQ_PORT` | 5672 | RabbitMQ port |
| `RABBITMQ_USER` | guest | RabbitMQ username |
| `RABBITMQ_PASSWORD` | guest | RabbitMQ password |
| `RABBITMQ_QUEUE` | scan-results | Default RabbitMQ queue |
| `ENABLE_RABBITMQ` | true | Enable/disable RabbitMQ integration |

### Application Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | ClamAV API | Application name |
| `APP_VERSION` | 1.0.0 | Application version |
| `DEBUG` | false | Debug mode |

## Task Management (Taskfile)

The project includes a `Taskfile.yml` for convenient command execution using the [Task](https://taskfile.dev/) runner.

### Installation
```bash
# macOS
brew install go-task

# Linux
sudo sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Or download from https://taskfile.dev/installation/
```

### Available Tasks

**Setup & Development**
- `task install` - Install Python dependencies
- `task dev` - Run locally with uvicorn (hot reload)
- `task build` - Build Docker image
- `task clean` - Clean cache and build artifacts

**Docker Compose Operations**
- `task run:simple` - Run in simple mode (ClamAV, Redis, MinIO, API only)
- `task run:kafka` - Run with Kafka profile (includes Redpanda and Console)
- `task run:rabbitmq` - Run with RabbitMQ profile
- `task run:all` - Run all services
- `task up:simple` - Start services in simple mode
- `task up` / `task up:kafka` / `task up:rabbitmq` / `task up:all` - Start services
- `task down:simple` - Stop services in simple mode
- `task down` - Stop services (respects current profile)
- `task logs` - View logs
- `task restart` - Restart services

**Testing**
- `task test` - Run all tests in Docker
- `task test:unit` - Run unit tests
- `task test:integration` - Run integration tests
- `task test:cov` - Run tests with coverage
- `task test:local` - Run tests locally (no Docker)

**Code Quality**
- `task lint` - Run linting with ruff
- `task format` - Format code with ruff

**Kafka Operations** (require kafka profile)
- `task kafka:topics` - List all Kafka topics
- `task kafka:create TOPIC=my-topic` - Create a topic
- `task kafka:consume` - Consume messages (default: scan-results, 10 messages)
- `task kafka:consume TOPIC=my-topic NUM=20` - Consume from specific topic

**RabbitMQ Operations** (require rabbitmq profile)
- `task rabbitmq:queues` - List queues
- `task rabbitmq:consumers` - List consumers
- `task rabbitmq:messages QUEUE=scan-results COUNT=10` - List messages in a queue (uses default queue and 10 messages if not specified)
- `task rabbitmq:purge QUEUE=scan-results` - Purge a queue

**Standalone RabbitMQ** (docker run without compose)
- `task rabbitmq:run` - Run RabbitMQ standalone (management UI at http://localhost:15672)
- `task rabbitmq:stop` - Stop the standalone RabbitMQ container

### Usage Examples

```bash
# Simple mode (recommended for basic file scanning)
task run:simple
task logs
task down:simple

# Start with Kafka (for async scanning)
task run:kafka
task logs

# Run tests
task test

# Manage Kafka topics
task kafka:topics
task kafka:create TOPIC=notifications

# Using PROFILE variable
task up PROFILE=rabbitmq
task down PROFILE=rabbitmq

# All services
task run:all
task kafka:topics
task rabbitmq:queues
task logs
```

## API Endpoints

### GET /
Root endpoint with API information.

### POST /api/v1/scan
Scan files for viruses.

**Request:**
```bash
curl -X POST "http://localhost:8080/api/v1/scan" \
  -F "files=@file1.pdf" \
  -F "files=@file2.zip"
```

**Response:**
```json
{
  "total_files": 2,
  "clean_files": 1,
  "infected_files": 1,
  "error_files": 0,
  "results": [
    {
      "filename": "file1.pdf",
      "size_bytes": 102400,
      "sha256_hash": "abc123def456...",
      "status": "clean",
      "virus_signature": null,
      "scan_time_seconds": 0.15,
      "timestamp": "2026-01-31T10:30:00Z"
    },
    {
      "filename": "file2.zip",
      "size_bytes": 204800,
      "sha256_hash": "def456ghi789...",
      "status": "infected",
      "virus_signature": "Win.Test.EICAR_HDB-1",
      "scan_time_seconds": 0.23,
      "timestamp": "2026-01-31T10:30:00Z"
    }
  ]
}
```

### POST /api/v1/scan-s3
Scan a file from S3 asynchronously using Kafka.

**Request:**
```json
{
  "s3_key": "uploads/document.pdf",
  "kafka_topic": "scan-results",
  "s3_bucket": "scans"
}
```

**Response:**
```json
{
  "request_id": "abc123-def456-789",
  "status": "accepted",
  "message": "Scan request accepted. Result will be sent to Kafka topic 'scan-results'"
}
```

### POST /api/v1/scan-s3-rabbitmq
Scan a file from S3 asynchronously using RabbitMQ.

**Request:**
```json
{
  "s3_key": "uploads/document.pdf",
  "rabbitmq_queue": "scan-results",
  "s3_bucket": "scans"
}
```

**Response:**
```json
{
  "request_id": "abc123-def456-789",
  "status": "accepted",
  "message": "Scan request accepted. Result will be sent to RabbitMQ queue 'scan-results'"
}
```

### GET /api/v1/health
Check API and all service health status.

**Response:**
```json
{
  "status": "healthy",
  "message": "API and ClamAV are operational",
  "services": {
    "clamav": {"enabled": true, "connected": true},
    "redis": {"enabled": true, "connected": true},
    "s3": {"enabled": true, "connected": true},
    "kafka": {"enabled": true, "connected": true},
    "rabbitmq": {"enabled": true, "connected": true}
  }
}
```

### GET /api/v1/version
Get API and ClamAV version information.

**Response:**
```json
{
  "api_version": "1.0.0",
  "clamav_version": "ClamAV 0.103.5 ... 0.103-beta"
}
```

## Testing

### Health Check
```bash
curl http://localhost:8080/api/v1/health
```

### Test with EICAR (Harmless Test Virus)
```bash
# Download EICAR test file
curl -o eicar.txt https://secure.eicar.org/eicar.com.txt

# Scan the file
curl -X POST http://localhost:8080/api/v1/scan -F "files=@eicar.txt"
```

### Multiple Files
```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -F "files=@file1.pdf" \
  -F "files=@file2.zip" \
  -F "files=@document.docx"
```

## Development

### Project Structure
```
clamav-api/
├── app/
│   ├── __init__.py
│   ├── main.py                      # FastAPI entry point
│   ├── config.py                    # Configuration management (env variables)
│   ├── models.py                    # Pydantic request/response models
│   ├── routers/
│   │   └── scan.py                 # Scan endpoints
│   └── services/
│       ├── clamav_client.py        # ClamAV wrapper
│       ├── cache.py                 # Redis cache client
│       ├── s3_client.py             # S3/MinIO client
│       ├── kafka_producer.py        # Kafka/Redpanda producer
│       └── rabbitmq_producer.py     # RabbitMQ producer
├── k8s/
│   ├── deployment.yaml
│   └── service.yaml
├── Dockerfile
├── docker-compose.yml               # Multi-service orchestration with profiles
├── Taskfile.yml                     # Task automation
├── requirements.txt
├── .dockerignore
└── README.md
```

### Adding New Features

1. Create new endpoints in `app/routers/`
2. Add new models to `app/models.py`
3. Update dependencies in `requirements.txt`
4. Update Docker image and redeploy

## Performance Considerations

- **File Size Limits**: Default 100MB per file to prevent DoS
- **File Count Limits**: Default 10 files per request
- **Timeouts**: 30-second timeout per file scan, 300-second overall timeout
- **Resource Allocation**: K8s deployment requests 500m CPU and 512Mi memory per pod

## Security

- Non-root user (UID 1000) in Docker container
- Read-only mounts for timezone and ClamAV socket
- CORS enabled for all origins (customize as needed)
- Input validation on file size and count
- Error messages don't expose internal details

## Troubleshooting

### ClamAV Connection Failed
- Ensure ClamAV daemon is running
- Check socket/host/port configuration
- Verify socket permissions if using Unix socket
- Check network connectivity if using TCP

### File Too Large
- Adjust `MAX_FILE_SIZE` environment variable
- Check available disk space for temporary files

### Slow Scans
- Check ClamAV virus definition updates
- Monitor CPU and memory usage
- Adjust `CLAMAV_TIMEOUT` if needed
- Scale horizontally by increasing pod replicas

## License

This project is provided as-is. Refer to your organization's policies.
