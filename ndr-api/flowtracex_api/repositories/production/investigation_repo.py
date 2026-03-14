from ..demo.investigation_repo import DemoInvestigationRepository
from clients.duckdb_client import DuckDBClient
from apps.investigations.models import InvestigationAlert

class ProductionInvestigationRepository(DemoInvestigationRepository):
    """
    Inherits from Demo because Investigation data is SQLite in both modes.
    Only difference is how we fetch linked data like Alerts.
    """
    def get_investigation_alerts(self, inv_id):
        # Fetch alert IDs from SQLite
        links = InvestigationAlert.objects.filter(investigation_id=inv_id)
        alert_ids = [link.alert_id for link in links]
        
        if not alert_ids:
            return []

        # Fetch Alert details from DuckDB
        # In a real impl: query = f"SELECT * FROM alerts WHERE id IN ({','.join(alert_ids)})"
        # For now, return empty as we don't have the Parquet file
        return []

    def add_alert(self, inv_id, alert_id):
        # Same as demo, just link the ID
        return super().add_alert(inv_id, alert_id)
