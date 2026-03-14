from django.conf import settings
from repositories.demo.system_repo import DemoSystemRepository
from repositories.production.system_repo import ProductionSystemRepository

class SystemService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoSystemRepository()
        else:
            self.repo = ProductionSystemRepository()

    def get_health(self):
        return self.repo.get_health()

    def get_logs(self, filters, page=1, limit=10):
        return self.repo.get_logs(filters, page, limit)

    def get_audit_logs(self, filters, page=1, limit=10):
        return self.repo.get_audit_logs(filters, page, limit)

    def get_identity(self):
        return self.repo.get_identity()

    def get_preferences(self, user):
        return self.repo.get_preferences(user)

    def update_preferences(self, user, data):
        return self.repo.update_preferences(user, data)
