# Hosted Demo Package

This folder prepares a **read-only hosted demo** of PacketQL without changing application code.

## What This Demo Does

- serves preloaded demo datasets
- allows source switching
- allows Log Dashboard
- allows Log Search
- allows SQL query execution
- blocks most write-oriented API actions through an nginx proxy

## What This Demo Blocks

- PCAP upload API
- reset-data API
- most non-read API methods
- creating, updating, or deleting saved hunts

## Important Limitation

Because we are not changing application code, some UI buttons may still be visible.

The proxy blocks the protected endpoints, so the public demo is safer, but this is still a
**best-effort read-only demo**, not a perfect product-level demo mode.

For a fully polished demo mode, the app would eventually need a dedicated read-only setting in code.

## Folder Layout

- `docker-compose.yml` - demo app + demo proxy
- `nginx.demo.conf` - reverse proxy that blocks most write endpoints
- `prepare-demo-data.sh` - create a clean demo seed from an existing PacketQL data directory
- `reset-demo-data.sh` - restore runtime data from the demo seed
- `run-demo.sh` - reset and start the hosted demo
- `demo-data-seed/` - clean source snapshot used to reset the demo
- `runtime-data/` - working demo data used by the running container

## Recommended Demo Workflow

1. Prepare demo data once
2. Reset runtime data from the clean seed before each public demo
3. Start the demo stack

## Prepare Demo Data

By default this script copies from the validated local dataset:

```bash
cd demo-hosting
./prepare-demo-data.sh
```

You can also point it at another PacketQL data directory:

```bash
./prepare-demo-data.sh /path/to/packetql-data
```

## Start The Demo

```bash
cd demo-hosting
./run-demo.sh
```

Open:

```text
http://localhost:8088
```

## Stop The Demo

```bash
cd demo-hosting
docker compose down
```

## Reset The Demo Back To Clean State

```bash
cd demo-hosting
./reset-demo-data.sh
docker compose restart packetql
```

## Change The Docker Image

By default the compose file uses:

```text
packetql:single-optimized
```

Override it like this:

```bash
PACKETQL_IMAGE=your-dockerhub-org/packetql:latest ./run-demo.sh
```

## Current Demo Datasets

The current seed is prepared from preloaded sources under the local validated dataset.

At the moment this is suited for:

- `4SICS-GeekLounge-151020.pcap`
- `dhcp.pcap`

If you want a stronger hosted demo, add one more curated PCAP and re-run `prepare-demo-data.sh`.
