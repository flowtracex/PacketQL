from ..base.rule_repo import RuleRepository
from apps.rules.models import Rule, RuleStats
from apps.rules.serializers import RuleSerializer
from django.core.paginator import Paginator

class DemoRuleRepository(RuleRepository):
    def list_rules(self, filters, page=1, limit=10):
        queryset = Rule.objects.all().order_by('-created_at')
        
        if filters.get('search'):
            queryset = queryset.filter(name__icontains=filters['search'])
        if filters.get('severity'):
            queryset = queryset.filter(severity=filters['severity'])
        if filters.get('type'):
            queryset = queryset.filter(type=filters['type'])
        if filters.get('enabled') is not None:
            queryset = queryset.filter(enabled=filters['enabled'] in ['true', 'True', True])

        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)
        
        return {
            "rules": RuleSerializer(page_obj.object_list, many=True).data,
            "total": paginator.count,
            "page": page_obj.number,
            "page_count": paginator.num_pages
        }

    def create_rule(self, data, user):
        rule = Rule.objects.create(author=user, **data)
        # Create initial stats
        RuleStats.objects.create(rule=rule)
        return RuleSerializer(rule).data

    def get_rule(self, rule_id):
        try:
            rule = Rule.objects.get(pk=rule_id)
            return RuleSerializer(rule).data
        except Rule.DoesNotExist:
            return None

    def update_rule(self, rule_id, data):
        try:
            rule = Rule.objects.get(pk=rule_id)
            for key, value in data.items():
                setattr(rule, key, value)
            rule.save()
            return RuleSerializer(rule).data
        except Rule.DoesNotExist:
            return None

    def delete_rule(self, rule_id):
        try:
            rule = Rule.objects.get(pk=rule_id)
            rule.delete()
            return True
        except Rule.DoesNotExist:
            return False

    def get_analytics(self):
        return {
            "topRules": [],
            "falsePositiveRates": [],
            "executionTimes": [],
            "detectionTrends": []
        }

    def get_schema_fields(self):
        return {
            "default": [{"id": "src_ip", "desc": "Source IP"}, {"id": "dst_ip", "desc": "Destination IP"}],
            "enriched": [{"id": "geoip", "desc": "GeoIP Info"}]
        }

    def get_schema_values(self, field):
        return {
            "datasets": [],
            "static": [{"id": "http", "desc": "HTTP"}, {"id": "dns", "desc": "DNS"}]
        }

    def get_templates(self, search, category):
        return [
            {"id": 1, "name": "Brute Force", "description": "Detect brute force attempts", "category": "Auth", "severity": "high", "mitre": "T1110"}
        ]
