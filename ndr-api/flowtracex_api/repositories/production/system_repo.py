from ..demo.system_repo import DemoSystemRepository
import shutil
import psutil
import socket
from pathlib import Path
from datetime import datetime, timezone

class ProductionSystemRepository(DemoSystemRepository):
    @staticmethod
    def _tail_lines(fp: Path, max_lines: int = 300):
        """Read last N lines efficiently without loading full file."""
        if not fp.exists() or not fp.is_file():
            return []
        try:
            with fp.open("rb") as f:
                f.seek(0, 2)
                end = f.tell()
                block = 8192
                data = b""
                lines = 0
                pos = end
                while pos > 0 and lines <= max_lines:
                    read_size = block if pos >= block else pos
                    pos -= read_size
                    f.seek(pos)
                    chunk = f.read(read_size)
                    data = chunk + data
                    lines = data.count(b"\n")
                text = data.decode("utf-8", errors="ignore")
                out = text.splitlines()
                return out[-max_lines:]
        except Exception:
            return []

    def get_health(self):
        # Real system metrics
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent

        return {
            "status": "healthy",
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "services": {"duckdb": "up"}
        }

    def get_identity(self):
        identity = super().get_identity()
        if isinstance(identity, dict):
            hostname = identity.get("hostname")
            version = identity.get("version")
            if not hostname or hostname == "flowtracex-demo":
                identity["hostname"] = socket.gethostname()
            if not version:
                identity["version"] = "1.0.0"
            return identity
        return {"hostname": socket.gethostname(), "version": "1.0.0"}

    def get_logs(self, filters, page=1, limit=10):
        # Lightweight host-mode log reader for the Internal Logs page.
        # It scans known local log files and returns newest lines first.
        candidates = [
            Path("/opt/ndr/ndr-api/flowtracex_api/aggregator.log"),
            Path("/opt/ndr/ndr-api/flowtracex_api/logs/django.log"),
            Path("/opt/ndr/ndr-api/flowtracex_api/logs/api.log"),
            Path("/opt/ndr/ndr-correlation/correlation.log"),
            Path("/var/log/syslog"),
            Path("/var/log/kern.log"),
        ]
        search = (filters.get("search", "") if filters else "").strip().lower()

        rows = []
        max_lines_per_file = 300
        for fp in candidates:
            if not fp.exists() or not fp.is_file():
                continue
            lines = self._tail_lines(fp, max_lines=max_lines_per_file)
            if not lines:
                continue

            for line in lines:
                raw = line.strip()
                if not raw:
                    continue
                if search and search not in raw.lower():
                    continue

                level = "INFO"
                for l in ("ERROR", "WARN", "WARNING", "CRITICAL", "DEBUG", "INFO"):
                    if l in raw:
                        level = "WARN" if l == "WARNING" else l
                        break

                timestamp = ""
                # Expected format starts with: YYYY-MM-DD HH:MM:SS,...
                if len(raw) >= 19 and raw[4] == "-" and raw[7] == "-" and raw[10] == " ":
                    timestamp = raw[:19]
                else:
                    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

                rows.append({
                    "timestamp": timestamp,
                    "level": level,
                    "source": fp.name,
                    "message": raw,
                })

        rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return {"logs": rows[:500], "total": len(rows)}
