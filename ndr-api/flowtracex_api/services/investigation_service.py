from django.conf import settings
from repositories.demo.investigation_repo import DemoInvestigationRepository
from repositories.production.investigation_repo import ProductionInvestigationRepository

class InvestigationService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoInvestigationRepository()
        else:
            self.repo = ProductionInvestigationRepository()

    def list_investigations(self, filters, page=1, limit=10):
        return self.repo.list_investigations(filters, page, limit)

    def create_investigation(self, data):
        return self.repo.create_investigation(data)

    def get_investigation_detail(self, inv_id):
        return self.repo.get_investigation_detail(inv_id)

    def update_investigation(self, inv_id, data):
        return self.repo.update_investigation(inv_id, data)

    def add_alert(self, inv_id, alert_id):
        return self.repo.add_alert(inv_id, alert_id)

    def get_investigation_alerts(self, inv_id):
        return self.repo.get_investigation_alerts(inv_id)

    def get_timeline(self, inv_id):
        return self.repo.get_timeline(inv_id)

    def add_note(self, inv_id, text, user):
        return self.repo.add_note(inv_id, text, user)

    def get_notes(self, inv_id):
        return self.repo.get_notes(inv_id)
