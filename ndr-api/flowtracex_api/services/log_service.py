from django.conf import settings
from repositories.demo.log_repo import DemoLogRepository
from repositories.production.log_repo import ProductionLogRepository

class LogService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoLogRepository()
        else:
            self.repo = ProductionLogRepository()

    def search_logs(self, filters, page=1, limit=10):
        return self.repo.search_logs(filters, page, limit)

    def get_analytics(self, window="24h", source_id=None):
        return self.repo.get_analytics(window=window, source_id=source_id)

    def stream_logs(self):
        return self.repo.stream_logs()
