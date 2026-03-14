from django.conf import settings
from repositories.demo.rule_repo import DemoRuleRepository
from repositories.production.rule_repo import ProductionRuleRepository

class RuleService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoRuleRepository()
        else:
            self.repo = ProductionRuleRepository()

    def list_rules(self, filters, page=1, limit=10):
        return self.repo.list_rules(filters, page, limit)

    def create_rule(self, data, user):
        return self.repo.create_rule(data, user)

    def get_rule(self, rule_id):
        return self.repo.get_rule(rule_id)

    def update_rule(self, rule_id, data):
        return self.repo.update_rule(rule_id, data)

    def delete_rule(self, rule_id):
        return self.repo.delete_rule(rule_id)

    def get_analytics(self):
        return self.repo.get_analytics()

    def get_schema_fields(self):
        return self.repo.get_schema_fields()

    def get_schema_values(self, field):
        return self.repo.get_schema_values(field)

    def get_templates(self, search, category):
        return self.repo.get_templates(search, category)
