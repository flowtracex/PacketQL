from abc import ABC, abstractmethod

class NetworkRepository(ABC):
    @abstractmethod
    def get_topology(self):
        pass

    @abstractmethod
    def get_services(self):
        pass

    @abstractmethod
    def search_flows(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_analytics(self):
        pass

    @abstractmethod
    def get_pcap(self, pcap_id):
        pass
