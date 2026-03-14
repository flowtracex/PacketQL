from abc import ABC, abstractmethod

class InvestigationRepository(ABC):
    @abstractmethod
    def list_investigations(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def create_investigation(self, data):
        pass

    @abstractmethod
    def get_investigation_detail(self, inv_id):
        pass

    @abstractmethod
    def update_investigation(self, inv_id, data):
        pass
    
    @abstractmethod
    def add_alert(self, inv_id, alert_id):
        pass

    @abstractmethod
    def get_investigation_alerts(self, inv_id):
        pass

    @abstractmethod
    def get_timeline(self, inv_id):
        pass

    @abstractmethod
    def add_note(self, inv_id, text, user):
        pass

    @abstractmethod
    def get_notes(self, inv_id):
        pass
