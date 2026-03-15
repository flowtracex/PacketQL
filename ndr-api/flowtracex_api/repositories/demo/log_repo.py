from ..base.log_repo import LogRepository
from repositories.production.log_repo import ProductionLogRepository

class DemoLogRepository(LogRepository):
    """
    Demo log repository — delegates all data methods to ProductionLogRepository
    so that real Parquet data is queried via DuckDB.
    """

    def __init__(self):
        self._prod = ProductionLogRepository()

    def search_logs(self, filters, page=1, limit=10):
        return self._prod.search_logs(filters, page, limit)

    def get_analytics(self, window="24h", source_id=None):
        return self._prod.get_analytics(window=window, source_id=source_id)

    def stream_logs(self):
        """
        Stream logs by replaying Parquet data as simulated live events.
        """
        import time
        import math
        import datetime
        from clients.duckdb_client import DuckDBClient
        import json

        try:
            logs = DuckDBClient.execute_dict_rows(
                "SELECT * FROM conn ORDER BY ingest_time DESC LIMIT 200"
            )
            if logs:
                # Clean NaN and datetime values
                for row in logs:
                    for k, v in list(row.items()):
                        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                            row[k] = None
                        elif isinstance(v, (datetime.date, datetime.datetime)):
                            row[k] = v.isoformat()
                    row['_source'] = 'conn'

                idx = 0
                while True:
                    batch = logs[idx:idx + 3]
                    if not batch:
                        idx = 0
                        continue
                    idx += len(batch)
                    if idx >= len(logs):
                        idx = 0
                    yield f"data: {json.dumps(batch)}\n\n"
                    time.sleep(0.8)
            else:
                while True:
                    time.sleep(1)
                    yield f"data: []\n\n"
        except Exception as e:
            while True:
                time.sleep(1)
                yield f"data: []\n\n"
