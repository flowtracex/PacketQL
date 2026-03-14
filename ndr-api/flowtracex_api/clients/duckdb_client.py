import duckdb
from django.conf import settings
import logging
import os

logger = logging.getLogger(__name__)

class DuckDBClient:
    _instance = None
    
    @staticmethod
    def _quote_ident(name: str) -> str:
        """Safely quote a DuckDB identifier."""
        return '"' + str(name).replace('"', '""') + '"'

    @classmethod
    def get_connection(cls):
        """
        Returns a new connection to DuckDB with Parquet views registered.
        DuckDB connections are not thread-safe, so we return a new one each time.
        Uses in-memory mode for Parquet-only queries; falls back to persistent DB if it exists.
        """
        try:
            db_path = str(settings.DUCKDB_PATH)
            if os.path.exists(db_path):
                con = duckdb.connect(db_path, read_only=False)
            else:
                # Use in-memory — we only need Parquet views, no persistent storage needed
                con = duckdb.connect()
            cls._register_parquet_views(con)
            return con
        except Exception as e:
            logger.error(f"DuckDB connection error: {e}")
            return None

    @classmethod
    def _register_parquet_views(cls, con):
        """Register Parquet directories as DuckDB views for SQL queries."""
        parquet_base = getattr(settings, 'PARQUET_DATA_DIR', None)
        if not parquet_base:
            parquet_base = os.path.join(settings.DATA_DIR, 'parquet')
        
        parquet_base = str(parquet_base)
        if not os.path.isdir(parquet_base):
            return
        
        for entry in os.listdir(parquet_base):
            source_path = os.path.join(parquet_base, entry)
            if os.path.isdir(source_path) or os.path.islink(source_path):
                # Check if there are actually parquet files
                glob_path = f"{source_path}/**/*.parquet"
                view_name = cls._quote_ident(entry)
                try:
                    con.execute(f"""
                        CREATE OR REPLACE VIEW {view_name} AS
                        SELECT * FROM read_parquet('{glob_path}', hive_partitioning=true)
                    """)
                except Exception as e:
                    # Some dirs may be empty (no parquet files)
                    logger.debug(f"Skipping view for {entry}: {e}")

    @staticmethod
    def execute_query(query, params=None):
        con = None
        try:
            con = DuckDBClient.get_connection()
            if params:
                return con.execute(query, params).fetchall()
            return con.execute(query).fetchall()
        except Exception as e:
            logger.error(f"DuckDB query error: {e}")
            return []
        finally:
            if con:
                con.close()
    
    @staticmethod
    def execute_df(query, params=None):
        """Returns result as Pandas DataFrame"""
        con = None
        try:
            con = DuckDBClient.get_connection()
            if con is None:
                return None
            if params:
                return con.execute(query, params).df()
            return con.execute(query).df()
        except Exception as e:
            logger.error(f"DuckDB DataFrame error: {e}")
            return None
        finally:
            if con:
                con.close()

    @staticmethod
    def execute_dict_rows(query, params=None):
        """Returns result as list of dicts (no numpy/pandas dependency)."""
        con = None
        try:
            con = DuckDBClient.get_connection()
            if con is None:
                return []
            if params:
                result = con.execute(query, params)
            else:
                result = con.execute(query)
            columns = [desc[0] for desc in result.description]
            rows = result.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"DuckDB dict_rows error: {e}")
            return []
        finally:
            if con:
                con.close()

    @staticmethod
    def get_available_tables():
        """List all Parquet-backed tables/views available."""
        parquet_base = getattr(settings, 'PARQUET_DATA_DIR', None)
        if not parquet_base:
            parquet_base = os.path.join(settings.DATA_DIR, 'parquet')
        
        tables = []
        parquet_base = str(parquet_base)
        if os.path.isdir(parquet_base):
            for entry in os.listdir(parquet_base):
                source_path = os.path.join(parquet_base, entry)
                if os.path.isdir(source_path) or os.path.islink(source_path):
                    tables.append(entry)
        return sorted(tables)
