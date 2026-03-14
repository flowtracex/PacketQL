from abc import ABC, abstractmethod

class RuleRepository(ABC):
    @abstractmethod
    def list_rules(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def create_rule(self, data, user):
        pass

    @abstractmethod
    def get_rule(self, rule_id):
        pass

    @abstractmethod
    def update_rule(self, rule_id, data):
        pass

    @abstractmethod
    def delete_rule(self, rule_id):
        pass

    @abstractmethod
    def get_analytics(self):
        pass

    @abstractmethod
    def get_schema_fields(self):
        pass

    @abstractmethod
    def get_schema_values(self, field):
        pass

    @abstractmethod
    def get_templates(self, search, category):
        pass
