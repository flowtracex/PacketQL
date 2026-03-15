# Publishing Guide

Use this page when publishing PacketQL to GitHub and Docker Hub.

## Recommended Positioning

Keep the public message simple:

- open-source
- SOC-focused
- single-container
- easy to try
- public beta

Do not lead with the manual multi-service setup.

## GitHub Repository Description

Short version:

```text
Open-source SOC packet investigation platform that turns PCAP files into SQL-queryable security data.
```

Alternative shorter version:

```text
Turn PCAP files into SQL-ready security investigations with a single Docker container.
```

## GitHub Repository Website

Use one of:

- your product website
- your live demo URL
- your Docker Hub package page

## Suggested Topics

```text
pcap zeek soc security network-forensics duckdb parquet kafka threat-hunting incident-response ndr opensource
```

## Docker Hub Short Description

```text
Single-container SOC PCAP investigation platform powered by Zeek, Kafka, Parquet, and DuckDB.
```

## Docker Hub Full Description

```text
PacketQL is an open-source packet investigation platform that turns uploaded PCAP files into SQL-queryable security data.

The bundled container includes Zeek, Kafka in KRaft mode, a Go normalization and enrichment pipeline, Parquet output, DuckDB-backed querying, a Django API, and a React UI.

Recommended workflow:
- pull the image
- mount one host directory to /data
- open the UI
- upload a PCAP

Recommended PCAP size for the best experience: below 50 MB.

Status: Public Beta
```

## Suggested GitHub Release Title

```text
PacketQL v0.1.0-beta - Single-container packet investigation
```

## Suggested GitHub Release Notes

```text
PacketQL is now available as an open-source public beta.

PacketQL turns packet captures into structured, SQL-queryable investigation data.

Highlights:
- Browser-based PCAP upload
- Zeek-powered protocol parsing
- Structured log tables for investigation
- Parquet + DuckDB analytics workflow
- Log dashboard, log search, and SQL query workflow
- Simple single-container Docker deployment

Recommended deployment:
- pull the Docker image
- mount a host path to /data
- open the UI and upload a PCAP

Recommended PCAP size:
- below 50 MB for the smoothest beta experience

Current status:
- Public Beta
- recommended for labs, demos, and internal evaluation
- not yet positioned as hardened production infrastructure
```

## Suggested First Lines For The GitHub README Banner

Option 1:

```text
PacketQL is an open-source packet investigation platform that turns PCAP files into SQL-queryable security data.
```

Option 2:

```text
Turn PCAP files into structured, SQL-ready security investigations in minutes.
```

Option 3:

```text
Single-container PCAP investigation for SOC analysts, powered by Zeek, Kafka, Parquet, and DuckDB.
```

## Known Limitations Wording

Use this wording publicly if you want to stay honest and safe:

```text
PacketQL is currently in public beta. The recommended deployment path is the bundled Docker container. The best experience today is with PCAP files below 50 MB. Larger files and production hardening are still being improved.
```

## Recommended Docs Order On GitHub

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docker/README.md`
4. screenshots
5. release notes

## Before Publishing

Replace placeholders in the docs:

- `YOUR_DOCKERHUB_ORG/packetql:latest`
- `<your-repo-url>`

Also confirm:

- Docker image name is final
- live demo URL is final
- screenshots are ready if you want a stronger front page
