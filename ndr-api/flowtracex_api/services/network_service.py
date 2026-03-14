from django.conf import settings
from repositories.demo.network_repo import DemoNetworkRepository
from repositories.production.network_repo import ProductionNetworkRepository

class NetworkService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoNetworkRepository()
        else:
            self.repo = ProductionNetworkRepository()

    def get_topology(self):
        return self.repo.get_topology()

    def get_services(self):
        return self.repo.get_services()

    def search_flows(self, filters, page=1, limit=10):
        return self.repo.search_flows(filters, page, limit)

    def get_analytics(self, window='24h'):
        return self.repo.get_analytics(window=window)

    def get_pcap(self, pcap_id):
        return self.repo.get_pcap(pcap_id)
