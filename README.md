# ClamAV API

A FastAPI-based REST API for scanning files using ClamAV antivirus engine.

## Features

- **Multiple File Scanning**: Upload and scan up to 10 files in a single request
- **ClamAV Integration**: Supports both Unix socket and TCP connections to ClamAV daemon
- **Detailed Results**: Returns comprehensive scan results including:
  - File metadata (filename, size, SHA256 hash)
  - Scan status (clean, infected, error)
  - Virus signatures (if infected)
  - Scan duration and timestamp
- **Health Checks**: Built-in health check endpoints for monitoring
- **Production Ready**: Includes Kubernetes deployment manifests and Docker container

## Requirements

- Python 3.11+
- ClamAV daemon running (either locally or accessible via TCP)
- FastAPI
- Python clamd library

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

### Docker

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

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAMAV_TYPE` | unix | Connection type: "unix" or "tcp" |
| `CLAMAV_UNIX_SOCKET` | /var/run/clamav/clamd.ctl | Unix socket path for ClamAV |
| `CLAMAV_HOST` | localhost | ClamAV hostname (for TCP) |
| `CLAMAV_PORT` | 3310 | ClamAV port (for TCP) |
| `CLAMAV_TIMEOUT` | 30 | ClamAV scan timeout (seconds) |
| `MAX_FILE_SIZE` | 104857600 | Maximum file size (100MB) |
| `MAX_FILES` | 10 | Maximum files per request |
| `UPLOAD_TIMEOUT` | 300 | Upload timeout (seconds) |
| `DEBUG` | false | Debug mode |

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

### GET /api/v1/health
Check API and ClamAV health status.

**Response:**
```json
{
  "status": "healthy",
  "message": "API and ClamAV are operational"
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
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Configuration management
│   ├── models.py               # Pydantic models
│   ├── routers/
│   │   └── scan.py            # Scan endpoints
│   └── services/
│       └── clamav_client.py   # ClamAV wrapper
├── k8s/
│   ├── deployment.yaml
│   └── service.yaml
├── Dockerfile
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
