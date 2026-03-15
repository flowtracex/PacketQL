# Docker Deployment

This is the recommended way to run PCAPQL.

## Recommended User Path

For GitHub users and SOC teams, the preferred workflow is:

1. pull the published Docker image from Docker Hub
2. mount one host directory to `/data`
3. open the UI
4. upload a PCAP

Users should not need to manually install:

- Zeek
- Kafka
- Zeek Kafka plugin
- Django
- frontend runtime

## What The Image Contains

The single-container image bundles:

- Zeek runtime
- Kafka in KRaft mode
- Go normalization and enrichment pipeline
- Django API served by Gunicorn
- static frontend served by nginx

## Run From Docker Hub

Replace the image name below with your published Docker Hub tag.

```bash
docker pull YOUR_DOCKERHUB_ORG/packetql:latest

mkdir -p /opt/packetql-data

docker run -d \
  --name packetql \
  -p 3000:3000 \
  -v /opt/packetql-data:/data \
  YOUR_DOCKERHUB_ORG/packetql:latest
```

Open:

```text
http://localhost:3000
```

## Port Conflict Example

If `3000` is already used:

```bash
docker run -d \
  --name packetql \
  -p 8088:3000 \
  -v /opt/packetql-data:/data \
  YOUR_DOCKERHUB_ORG/packetql:latest
```

Open:

```text
http://localhost:8088
```

## Runtime Volume

Mount a host path to `/data`.

That external directory stores:

- uploaded PCAP files
- generated parquet files
- source metadata
- Kafka runtime data used inside the container

## Recommended PCAP Size

For the smoothest analyst experience:

- use files below `50 MB`

Larger PCAPs can work, but beta-stage throughput tuning is still improving.

## Build Locally

This section is mainly for maintainers and contributors.

```bash
cd /opt/tools/pcapql
./docker/build-image.sh
```

Then run:

```bash
docker run -d \
  --name packetql \
  -p 3000:3000 \
  -v /opt/packetql-data:/data \
  packetql:single-optimized
```

Important:

- local image builds currently expect a usable Zeek runtime on the build host
- end users pulling the published image do not need that local Zeek setup

## Validate A Running Container

```bash
docker logs -f packetql
curl -sS http://127.0.0.1:3000 >/dev/null && echo "UI OK"
curl -sS http://127.0.0.1:3000/api/v1/system/health
```

## Production-Style Validation

For maintainers testing a validation container on alternate ports:

```bash
BASE_URL=http://127.0.0.1:8094 \
API_URL=http://127.0.0.1:18014 \
CONTAINER_NAME=packetql-validation-prod \
bash ./docker/validate-production.sh
```

## Manual Deployment Guidance

Manual deployment should be considered an advanced path.

If a user deploys outside the bundled container, they must configure and operate:

- Zeek
- Kafka
- streaming pipeline wiring
- API runtime
- frontend runtime
- persistence paths

That is why the public documentation should always lead with the Docker-based deployment model first.
