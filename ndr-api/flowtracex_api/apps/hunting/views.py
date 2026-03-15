from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.hunting_service import HuntingService
from .serializers import HuntSerializer

class HuntListView(APIView):

    def get(self, request):
        service = HuntingService()
        filters = request.query_params.dict()
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        
        data = service.list_hunts(filters, page, limit)
        return Response(data)

    def post(self, request):
        service = HuntingService()
        data = service.save_hunt(request.data, request.user)
        if data:
            return Response(data, status=status.HTTP_201_CREATED)
        return Response({'error': 'Failed to save hunt'}, status=status.HTTP_400_BAD_REQUEST)

class HuntDetailView(APIView):

    def get(self, request, pk):
        service = HuntingService()
        data = service.get_hunt(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        """Update an existing hunt."""
        service = HuntingService()
        data = dict(request.data)
        data['id'] = pk
        result = service.save_hunt(data, request.user)
        if result:
            return Response(result)
        return Response({'error': 'Failed to update hunt'}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """Delete a hunt."""
        service = HuntingService()
        success = service.delete_hunt(pk)
        if success:
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_404_NOT_FOUND)

class HuntRunsView(APIView):
    def get(self, request, pk):
        service = HuntingService()
        data = service.get_hunt_runs(pk)
        return Response(data)

class HuntRunDetailView(APIView):
    def get(self, request, pk):
        service = HuntingService()
        data = service.get_hunt_run_result(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

class HuntRunView(APIView):

    def post(self, request):
        service = HuntingService()
        query_type = request.data.get('query_type', 'visual')
        params = request.data
        
        data = service.run_hunt(query_type, params)
        return Response(data)

class HuntCategoriesView(APIView):

    def get(self, request):
        service = HuntingService()
        data = service.get_categories()
        return Response(data)

class HuntTemplatesView(APIView):

    def get(self, request):
        search = request.query_params.get('search')
        category = request.query_params.get('category')
        service = HuntingService()
        data = service.get_templates(search, category)
        return Response(data)


class LogEntryLookupView(APIView):
    """Look up a single Zeek log entry by UID across all Parquet-backed tables."""

    def get(self, request, uid):
        from clients.duckdb_client import DuckDBClient
        from apps.logs.data_sources import resolve_source
        from django.conf import settings
        from pathlib import Path
        import math, datetime

        ds = resolve_source(Path(getattr(settings, "DATA_DIR", Path("."))), request.query_params.get("source_id"))
        parquet_base = Path(ds.parquet_dir) if ds else None
        tables = DuckDBClient.get_available_tables(parquet_base=parquet_base)
        for table in tables:
            try:
                table_ref = '"' + str(table).replace('"', '""') + '"'
                rows = DuckDBClient.execute_query(
                    f"SELECT * FROM {table_ref} WHERE uid = ? LIMIT 1", [uid], parquet_base=parquet_base
                )
                if rows and len(rows) > 0:
                    # Get column names
                    cols = DuckDBClient.execute_query(f"DESCRIBE {table_ref}", parquet_base=parquet_base)
                    col_names = [c[0] for c in cols]
                    row = rows[0]
                    entry = {}
                    for i, name in enumerate(col_names):
                        val = row[i]
                        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                            val = None
                        elif isinstance(val, (datetime.date, datetime.datetime)):
                            val = val.isoformat()
                        entry[name] = val

                    return Response({
                        "table": table,
                        "uid": uid,
                        "fields": entry
                    })
            except Exception:
                continue

        return Response({"error": "UID not found"}, status=status.HTTP_404_NOT_FOUND)
