from abc import ABC, abstractmethod

class HuntingRepository(ABC):
    @abstractmethod
    def list_hunts(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def save_hunt(self, data, user):
        pass

    @abstractmethod
    def get_hunt(self, hunt_id):
        pass

    @abstractmethod
    def run_hunt(self, query_type, params):
        pass

    @abstractmethod
    def get_categories(self):
        pass

    @abstractmethod
    def get_templates(self, search, category):
        pass
