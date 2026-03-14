from abc import ABC, abstractmethod

class SystemRepository(ABC):
    @abstractmethod
    def get_health(self):
        pass

    @abstractmethod
    def get_logs(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_audit_logs(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_identity(self):
        pass

    @abstractmethod
    def get_preferences(self, user):
        pass

    @abstractmethod
    def update_preferences(self, user, data):
        pass
