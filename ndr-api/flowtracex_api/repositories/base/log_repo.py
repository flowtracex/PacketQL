from abc import ABC, abstractmethod

class LogRepository(ABC):
    @abstractmethod
    def search_logs(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_analytics(self, window="24h", source_id=None):
        pass

    @abstractmethod
    def stream_logs(self):
        pass
