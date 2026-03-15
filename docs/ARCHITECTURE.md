# PCAPQL Architecture

PCAPQL is designed to make packet investigation simple for SOC analysts while keeping the runtime flow transparent.

## Primary Goal

Turn uploaded PCAP files into structured, SQL-queryable security data with minimal setup.

## High-Level Flow

```text
1. Analyst uploads a PCAP
2. Zeek parses network traffic
3. Zeek logs are streamed into Kafka
4. Go pipeline normalizes and enriches events
5. Events are written into Parquet
6. DuckDB queries the Parquet dataset
7. API and UI present dashboard, search, and SQL workflows
```

## End-to-End Diagram

```text
+-------------+      +---------------------------+      +---------------+
| PCAP Upload | ---> | Zeek Network Security     | ---> | Kafka (KRaft) |
| from UI     |      | Monitor                   |      | zeek-raw      |
+-------------+      +---------------------------+      +---------------+
                                                               |
                                                               v
                                                +------------------------------+
                                                | Go normalization + enrich    |
                                                | pipeline                     |
                                                +------------------------------+
                                                     |                    |
                                                     |                    |
                                                     v                    v
                                         +------------------+   +------------------+
                                         | Kafka normalized |   | Parquet files    |
                                         | stream           |   | by protocol/time |
                                         +------------------+   +------------------+
                                                                          |
                                                                          v
                                                                   +-------------+
                                                                   | DuckDB      |
                                                                   +-------------+
                                                                          |
                                                                          v
                                                           +---------------------------+
                                                           | Django API + React UI     |
                                                           | Dashboard, search, SQL    |
                                                           +---------------------------+
```

## Analyst View

SOC analysts do not need to think in terms of raw Zeek logs or internal services.

What they experience is:

- upload a PCAP
- wait for processing
- investigate protocol tables
- search normalized events
- run SQL on structured data

That is why the product messaging should focus on:

- structured log tables
- SQL-ready investigations
- simple PCAP-to-hunt workflow

instead of low-level deployment details.

## Runtime Components

### Zeek

Zeek is the packet analysis engine used to extract protocol logs from PCAP traffic.

Official project:

- https://zeek.org/

### Kafka

Kafka provides the streaming bus between packet parsing and downstream processing.

PCAPQL currently uses Kafka in KRaft mode inside the bundled container.

### Go Enrichment Pipeline

The Go service:

- reads Zeek events from Kafka
- normalizes fields
- enriches selected event data
- writes protocol-specific Parquet outputs
- optionally publishes normalized events to a Kafka topic

### Parquet + DuckDB

Parquet stores the structured event output efficiently.

DuckDB provides local analytical querying over those Parquet files.

### API + UI

The Django API exposes ingestion, metadata, search, and SQL endpoints.

The React UI gives analysts:

- PCAP upload
- log dashboard
- log search
- SQL querying
- pipeline health visibility

## Deployment Model

Recommended deployment model:

- one Docker container
- one mounted host data directory at `/data`

This keeps first-time setup simple and avoids requiring users to manually install:

- Zeek
- Kafka
- plugin wiring
- API runtime
- frontend runtime

## Persistence

Persistent runtime data lives outside the container in the mounted `/data` volume.

This is where PCAPQL stores:

- uploaded files
- parquet output
- source metadata
- bundled Kafka runtime data for the single-container deployment

## GitHub Positioning

For public GitHub documentation, describe the architecture in a way that supports the product story:

- PCAP in
- structured tables out
- SQL and investigation workflow for SOC analysts

Use manual deployment details only as secondary, advanced documentation.
