from django.conf import settings
from repositories.demo.asset_repo import DemoAssetRepository
from repositories.production.asset_repo import ProductionAssetRepository

class AssetService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoAssetRepository()
        else:
            self.repo = ProductionAssetRepository()

    def list_assets(self, filters, page=1, limit=10):
        return self.repo.list_assets(filters, page, limit)

    def get_asset_detail(self, ip, time_window='24h'):
        return self.repo.get_asset_detail(ip, time_window)

    def get_asset_analytics(self):
        return self.repo.get_asset_analytics()
    
    def get_config_log(self, ip):
        return self.repo.get_config_log(ip)
