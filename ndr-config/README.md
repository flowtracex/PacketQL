# ndr-config — Centralized Configuration

Single source of truth for all NDR platform configuration. Every project reads from here via `NDR_CONFIG_DIR` env var.

## Directory Structure

```
ndr-config/
├── infra/                         Shared connections
│   ├── kafka.json                 Kafka brokers, topics
│   ├── redis.json                 Redis host, port, pool
│   └── paths.json                 File system paths
│
├── platform/                      Platform behavior
│   ├── enums.json                 Severities, statuses, verdicts, log types
│   ├── signals.json               Signal categories, peer groups, shadow mode
│   └── metrics.json               Prometheus metric definitions
│
├── schemas/                       Data contracts (per log source family)
│   ├── zeek/                      Zeek log family (18 log types)
│   │   ├── fields.json            Raw Zeek field definitions
│   │   ├── normalization.json     Field promotion + enrichment rules
│   │   └── field-metadata.json    UI labels, descriptions, groups, contexts
│   ├── ad/                        Active Directory (placeholder)
│   └── azure/                     Azure/M365 (placeholder)
│
├── services/                      Project-specific settings (no infra duplication)
│   ├── enrich.json                ndr-enrich: flush, asset profiler, Kafka topics
│   ├── flink.json                 ndr-flink: consumer group
│   └── baseline.json              ndr-baseline: schedules, model paths
│
└── README.md
```

## Related Directories

| Directory | Purpose | Env Var |
|-----------|---------|---------|
| `ndr-config/` | HOW the system behaves | `NDR_CONFIG_DIR` |
| `ndr-data/` | WHAT to preload (reference CSVs, seed data) | `NDR_SEED_DIR` |
| `docs/` | WHY — platform documentation | — |
| `data/` | Runtime output (Parquet, logs, models) | `NDR_DATA_DIR` |

## Usage

```bash
# Set in /opt/ndr/.env
NDR_CONFIG_DIR=/opt/ndr/ndr-config
```

```go
// Go
configDir := os.Getenv("NDR_CONFIG_DIR")
```

```python
# Python
config_dir = os.environ.get("NDR_CONFIG_DIR", "/opt/ndr/ndr-config")
```

## Consumer Map

| File | Consumers |
|------|-----------|
| `infra/redis.json` | ndr-enrich, ndr-baseline, ndr-flink, ndr-api |
| `infra/kafka.json` | ndr-enrich, ndr-flink |
| `schemas/zeek/fields.json` | generate_schema.go, generate_field_catalog.go |
| `schemas/zeek/normalization.json` | generate_schema.go, generate_field_catalog.go |
| `platform/enums.json` | ndr-api, ndr-frontend |
| `platform/signals.json` | ndr-flink (flink-job-deployer.sh) |
| `services/enrich.json` | ndr-enrich |
| `services/flink.json` | ndr-flink |
| `services/baseline.json` | ndr-baseline |
