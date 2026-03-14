from django.conf import settings
from repositories.demo.hunting_repo import DemoHuntingRepository
from repositories.production.hunting_repo import ProductionHuntingRepository

class HuntingService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoHuntingRepository()
        else:
            self.repo = ProductionHuntingRepository()

    def list_hunts(self, filters, page=1, limit=10):
        return self.repo.list_hunts(filters, page, limit)

    def save_hunt(self, data, user):
        return self.repo.save_hunt(data, user)

    def get_hunt(self, hunt_id):
        return self.repo.get_hunt(hunt_id)

    def get_hunt_runs(self, hunt_id):
        if hasattr(self.repo, 'get_hunt_runs'):
            return self.repo.get_hunt_runs(hunt_id)
        return []

    def get_hunt_run_result(self, run_id):
         if hasattr(self.repo, 'get_hunt_run_result'):
            return self.repo.get_hunt_run_result(run_id)
         return None

    def delete_hunt(self, hunt_id):
        return self.repo.delete_hunt(hunt_id)

    def run_hunt(self, query_type, params):
        return self.repo.run_hunt(query_type, params)

    def get_categories(self):
        return self.repo.get_categories()

    def get_templates(self, search, category):
        return self.repo.get_templates(search, category)
