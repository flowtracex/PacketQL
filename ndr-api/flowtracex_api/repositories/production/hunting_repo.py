from ..base.hunting_repo import HuntingRepository
from clients.duckdb_client import DuckDBClient
from clients.redis_client import RedisClient
import json
import time
import uuid
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)


class ProductionHuntingRepository(HuntingRepository):
    """
    Production hunting repository.
    Hunts and Results stored in SQLite (Django Models).
    Hunt runs executed via DuckDB against Parquet views.
    """

    def list_hunts(self, filters, page=1, limit=10):
        try:
            from apps.hunting.models import Hunt
            from apps.hunting.serializers import HuntSerializer
            from django.core.paginator import Paginator

            queryset = Hunt.objects.all().order_by('-created_at')

            # Apply filters
            if filters.get('search'):
                queryset = queryset.filter(name__icontains=filters['search'])
            if filters.get('type'):
                queryset = queryset.filter(type=filters['type'])

            paginator = Paginator(queryset, limit)
            page_obj = paginator.get_page(page)

            return {
                "hunts": HuntSerializer(page_obj.object_list, many=True).data,
                "total": paginator.count,
                "page": page,
                "page_count": paginator.num_pages
            }
        except Exception as e:
            logger.error(f"Error listing hunts: {e}")
            return {"hunts": [], "total": 0, "page": 1, "page_count": 0}

    def save_hunt(self, data, user):
        try:
            from apps.hunting.models import Hunt
            from apps.hunting.serializers import HuntSerializer

            # Check if updating existing
            hunt_id = data.get('id')
            if hunt_id:
                hunt = Hunt.objects.get(pk=hunt_id)
                serializer = HuntSerializer(hunt, data=data, partial=True)
            else:
                serializer = HuntSerializer(data=data)

            if serializer.is_valid():
                # Manually set author if creating
                if not hunt_id and user and not user.is_anonymous:
                     serializer.save(author=user)
                else:
                     serializer.save()
                return serializer.data
            else:
                logger.error(f"Validation error saving hunt: {serializer.errors}")
                return None
        except Exception as e:
            logger.error(f"Error saving hunt: {e}")
            return None

    def get_hunt(self, hunt_id):
        try:
            from apps.hunting.models import Hunt
            from apps.hunting.serializers import HuntSerializer
            hunt = Hunt.objects.get(pk=hunt_id)
            return HuntSerializer(hunt).data
        except Exception as e:
            logger.error(f"Error getting hunt {hunt_id}: {e}")
            return None

    def delete_hunt(self, hunt_id):
        try:
            from apps.hunting.models import Hunt
            Hunt.objects.filter(pk=hunt_id).delete()
            return True
        except Exception as e:
            logger.error(f"Error deleting hunt {hunt_id}: {e}")
            return False

    def run_hunt(self, query_type, params):
        start_time = time.time()
        hunt_id = params.get('hunt_id')
        available_tables = set(DuckDBClient.get_available_tables())
        
        # Build query
        query = ""
        log_source = "conn"
        
        if query_type == 'sql':
            query = params.get('query', '')
            # Try to infer log source from query for reasoning (naive check)
            if 'dns' in query.lower(): log_source = 'dns'
            elif 'http' in query.lower(): log_source = 'http'
        else:
            # Build SQL from visual conditions
            log_source = params.get('log_source', 'conn')
            if log_source not in available_tables:
                return {
                    "results": [],
                    "total": 0,
                    "executionTime": "0.00s",
                    "query": "",
                    "error": f"Unknown log source '{log_source}'. Available: {', '.join(sorted(available_tables))}"
                }
            conditions = params.get('conditions', [])
            table_ref = '"' + str(log_source).replace('"', '""') + '"'
            
            where_clauses = []
            for cond in conditions:
                field = cond.get('field', '')
                operator = cond.get('operator', '=')
                value = cond.get('value', '')
                
                # Map operator names to SQL
                op_map = {
                    'EQUAL': '=', 'NOT_EQUAL': '!=', 'GREATER': '>',
                    'LESS': '<', 'CONTAINS': 'LIKE', 'STARTS_WITH': 'LIKE',
                    '==': '=', '!=': '!=', '>': '>', '<': '<',
                    '>=': '>=', '<=': '<=',
                }
                sql_op = op_map.get(operator, '=')
                
                if sql_op == 'LIKE' and operator == 'CONTAINS':
                    where_clauses.append(f"{field} LIKE '%{value}%'")
                elif sql_op == 'LIKE' and operator == 'STARTS_WITH':
                    where_clauses.append(f"{field} LIKE '{value}%'")
                else:
                    # Try numeric
                    try:
                        float(value)
                        where_clauses.append(f"{field} {sql_op} {value}")
                    except (ValueError, TypeError):
                        where_clauses.append(f"{field} {sql_op} '{value}'")

            where = " AND ".join(where_clauses) if where_clauses else "1=1"

            # Check for group-by aggregation
            group_by = params.get('group_by', '')
            having_threshold = params.get('having_threshold', 0)

            if group_by:
                # Aggregation mode: GROUP BY + COUNT
                try:
                    having_threshold = int(having_threshold)
                except (ValueError, TypeError):
                    having_threshold = 0

                having_clause = f" HAVING COUNT(*) >= {having_threshold}" if having_threshold > 0 else ""
                query = (
                    f"SELECT {group_by}, COUNT(*) AS occurrence_count "
                    f"FROM {table_ref} WHERE {where} "
                    f"GROUP BY {group_by}{having_clause} "
                    f"ORDER BY occurrence_count DESC LIMIT 200"
                )
            else:
                query = f"SELECT * FROM {table_ref} WHERE {where} LIMIT 200"

        # Execute
        try:
            results_df = DuckDBClient.execute_df(query)
            execution_time = time.time() - start_time
            
            results = []
            if results_df is not None and len(results_df) > 0:
                results = results_df.head(200).to_dict(orient='records')
                # Clean NaN
                import math
                import datetime
                for row in results:
                    for k, v in row.items():
                        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                            row[k] = None
                        elif isinstance(v, (datetime.date, datetime.datetime)):
                            row[k] = v.isoformat()

            # Create HuntResult if hunt_id exists
            if hunt_id:
                from apps.hunting.models import Hunt, HuntResult
                try:
                    hunt = Hunt.objects.get(pk=hunt_id)
                    
                    # Format as Detection -> Reasoning -> Evidence
                    structured_result = {
                        "detection": hunt.name,
                        "reasoning": f"Hunt '{hunt.name}' executed on {log_source}. Found {len(results)} matches matching criteria.",
                        "evidence": results
                    }
                    
                    HuntResult.objects.create(
                        hunt=hunt,
                        duration=round(execution_time, 2),
                        matches_found=len(results),
                        status="completed",
                        result_data=structured_result
                    )
                    
                    # Update hunt metadata
                    hunt.last_run_at = timezone.now()
                    hunt.matches_found = len(results)
                    hunt.status = 'completed'
                    hunt.save()
                    
                except Exception as db_e:
                    logger.error(f"Error saving hunt result: {db_e}")

            return {
                "results": results,
                "total": len(results),
                "executionTime": f"{execution_time:.2f}s",
                "query": query
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Hunt run error: {e}")
            return {
                "results": [],
                "total": 0,
                "executionTime": f"{execution_time:.2f}s",
                "query": query,
                "error": str(e)
            }

    def get_hunt_runs(self, hunt_id):
        try:
            from apps.hunting.models import HuntResult
            runs = HuntResult.objects.filter(hunt_id=hunt_id).order_by('-created_at')
            return [{
                "id": run.id,
                "created_at": run.created_at,
                "matches_found": run.matches_found,
                "status": run.status,
                "duration": run.duration
            } for run in runs]
        except Exception as e:
            logger.error(f"Error getting hunt runs: {e}")
            return []
            
    def get_categories(self):
         # Static categories for now
        return [
            {"name": "Network", "count": 5, "severity": "high"},
            {"name": "DNS", "count": 3, "severity": "medium"},
            {"name": "Authentication", "count": 2, "severity": "high"}
        ]

    def get_templates(self, search, category):
        # Static templates
        templates = [
            {"id": 1, "name": "DNS Tunneling", "description": "Detect DNS tunneling via long queries", "category": "DNS", "type": "sql",
             "query": "SELECT src_ip, query, LENGTH(query) as query_len FROM dns WHERE LENGTH(query) > 50 ORDER BY query_len DESC LIMIT 50"},
            {"id": 2, "name": "C2 Beaconing", "description": "Detect periodic C2 callback patterns", "category": "Network", "type": "visual",
             "conditions": [{"field": "dst_port", "operator": "==", "value": "443"}]},
            {"id": 3, "name": "Data Exfiltration", "description": "High-volume outbound transfers", "category": "Network", "type": "sql",
             "query": "SELECT src_ip, SUM(orig_bytes) as total FROM conn GROUP BY src_ip HAVING total > 10000000 ORDER BY total DESC"}
        ]
        if search:
            templates = [t for t in templates if search.lower() in t['name'].lower()]
        if category:
            templates = [t for t in templates if t['category'] == category]
        return templates

    def get_hunt_run_result(self, run_id):
        try:
            from apps.hunting.models import HuntResult
            run = HuntResult.objects.get(pk=run_id)
            # Ensure proper JSON response
            evidence = run.result_data.get('evidence', [])
            return {
                "id": run.id,
                "created_at": run.created_at,
                "matches_found": run.matches_found,
                "status": run.status,
                "duration": run.duration,
                "results": evidence, 
                "result_data": run.result_data
            }
        except Exception as e:
            logger.error(f"Error getting hunt run result {run_id}: {e}")
            return None
