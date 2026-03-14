from django.conf import settings
from repositories.demo.dashboard_repo import DemoDashboardRepository
from repositories.production.dashboard_repo import ProductionDashboardRepository

class DashboardService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoDashboardRepository()
        else:
            self.repo = ProductionDashboardRepository()

    def get_overview(self):
        return self.repo.get_overview_metrics()

    def get_traffic(self, range_str):
        return self.repo.get_traffic_metrics(range_str)

    def get_protocols(self):
        return self.repo.get_protocol_distribution()

    def get_coverage(self):
        return self.repo.get_deep_inspection_coverage()
