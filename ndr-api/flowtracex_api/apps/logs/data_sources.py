from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class DataSource:
    source_id: str
    name: str
    created_at: str
    raw_file: str
    raw_size: int
    root_dir: str
    parquet_dir: str
    ingest_status: str = "pending"
    ingest_message: str = ""
    ingest_tables: Dict[str, int] | None = None
    updated_at: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "source_id": self.source_id,
            "name": self.name,
            "created_at": self.created_at,
            "raw_file": self.raw_file,
            "raw_size": self.raw_size,
            "root_dir": self.root_dir,
            "parquet_dir": self.parquet_dir,
            "ingest_status": self.ingest_status,
            "ingest_message": self.ingest_message,
            "ingest_tables": self.ingest_tables or {},
            "updated_at": self.updated_at or self.created_at,
        }


def _sources_root(data_dir: Path) -> Path:
    root = data_dir / "sources"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _current_source_file(data_dir: Path) -> Path:
    return _sources_root(data_dir) / ".current_source"


def _safe_slug(name: str) -> str:
    stem = Path(name).stem.lower()
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem).strip("-")
    return stem or "pcap"


def _source_meta_path(data_dir: Path, source_id: str) -> Path:
    return _sources_root(data_dir) / source_id / "meta.json"


def create_data_source(data_dir: Path, upload_name: str, upload_size: int) -> DataSource:
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    source_id = f"{_safe_slug(upload_name)}_{ts}"
    root = _sources_root(data_dir) / source_id
    raw_dir = root / "raw"
    parquet_dir = root / "parquet"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parquet_dir.mkdir(parents=True, exist_ok=True)

    ds = DataSource(
        source_id=source_id,
        name=upload_name,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
        raw_file=upload_name,
        raw_size=int(upload_size),
        root_dir=str(root),
        parquet_dir=str(parquet_dir),
        ingest_status="processing",
        ingest_message="Upload completed. Parsing started in background.",
        ingest_tables={},
        updated_at=datetime.now(tz=timezone.utc).isoformat(),
    )
    _source_meta_path(data_dir, source_id).write_text(json.dumps(ds.to_dict(), indent=2), encoding="utf-8")
    set_current_source(data_dir, source_id)
    return ds


def get_data_source(data_dir: Path, source_id: str) -> Optional[DataSource]:
    meta = _source_meta_path(data_dir, source_id)
    if not meta.exists():
        return None
    try:
        payload = json.loads(meta.read_text(encoding="utf-8"))
        return DataSource(
            source_id=str(payload["source_id"]),
            name=str(payload.get("name", "")),
            created_at=str(payload.get("created_at", "")),
            raw_file=str(payload.get("raw_file", "")),
            raw_size=int(payload.get("raw_size", 0)),
            root_dir=str(payload.get("root_dir", "")),
            parquet_dir=str(payload.get("parquet_dir", "")),
            ingest_status=str(payload.get("ingest_status", "pending")),
            ingest_message=str(payload.get("ingest_message", "")),
            ingest_tables=dict(payload.get("ingest_tables", {}) or {}),
            updated_at=str(payload.get("updated_at", payload.get("created_at", ""))),
        )
    except Exception:
        return None


def list_data_sources(data_dir: Path) -> List[DataSource]:
    result: List[DataSource] = []
    for meta in sorted(_sources_root(data_dir).glob("*/meta.json"), reverse=True):
        ds = get_data_source(data_dir, meta.parent.name)
        if ds:
            result.append(ds)
    result.sort(key=lambda d: d.created_at, reverse=True)
    return result


def set_current_source(data_dir: Path, source_id: str) -> bool:
    ds = get_data_source(data_dir, source_id)
    if not ds:
        return False
    _current_source_file(data_dir).write_text(source_id, encoding="utf-8")
    return True


def get_current_source(data_dir: Path) -> Optional[DataSource]:
    marker = _current_source_file(data_dir)
    if marker.exists():
        source_id = marker.read_text(encoding="utf-8").strip()
        if source_id:
            ds = get_data_source(data_dir, source_id)
            if ds:
                return ds
    sources = list_data_sources(data_dir)
    if not sources:
        return None
    set_current_source(data_dir, sources[0].source_id)
    return sources[0]


def resolve_source(data_dir: Path, source_id: Optional[str]) -> Optional[DataSource]:
    if source_id:
        return get_data_source(data_dir, source_id)
    return get_current_source(data_dir)


def update_data_source_ingest(
    data_dir: Path,
    source_id: str,
    ingest_status: str,
    ingest_message: str = "",
    ingest_tables: Optional[Dict[str, int]] = None,
) -> bool:
    ds = get_data_source(data_dir, source_id)
    if not ds:
        return False
    current = str(ds.ingest_status).lower()
    incoming = str(ingest_status).lower()
    # Never let heartbeat/"processing" overwrite terminal states.
    if current in {"ready", "failed"} and incoming == "processing":
        return True
    ds.ingest_status = ingest_status
    ds.ingest_message = ingest_message or ""
    ds.ingest_tables = ingest_tables or {}
    ds.updated_at = datetime.now(tz=timezone.utc).isoformat()
    _source_meta_path(data_dir, source_id).write_text(json.dumps(ds.to_dict(), indent=2), encoding="utf-8")
    return True


def reset_all_data_sources(data_dir: Path) -> Dict[str, object]:
    deleted_sources = 0
    sources_root = _sources_root(data_dir)
    for p in sources_root.iterdir():
        if p.name == ".current_source":
            continue
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            deleted_sources += 1
        elif p.is_file():
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    # Remove marker file
    try:
        _current_source_file(data_dir).unlink(missing_ok=True)
    except Exception:
        pass

    # Clean shared parquet/work leftovers inside project data dir.
    for rel in ("parquet", "work/pcap_ingest"):
        target = data_dir / rel
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True, exist_ok=True)

    return {"deleted_sources": deleted_sources}


def reset_shared_ingest_runtime(data_dir: Path) -> None:
    for rel in ("parquet", "work/pcap_ingest"):
        target = data_dir / rel
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True, exist_ok=True)
