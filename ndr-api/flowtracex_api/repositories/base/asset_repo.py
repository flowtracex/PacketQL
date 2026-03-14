from abc import ABC, abstractmethod

class AssetRepository(ABC):
    @abstractmethod
    def list_assets(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_asset_detail(self, ip, time_window='24h'):
        pass

    @abstractmethod
    def get_asset_analytics(self):
        pass

    @abstractmethod
    def get_config_log(self, ip):
        pass
