from django.urls import path
from .views import (
    RuleListView,
    RuleDetailView,
    RuleAnalyticsView,
    RuleSchemaFieldsView,
    RuleSchemaValuesView,
    RuleTemplatesView
)

urlpatterns = [
    path('rules', RuleListView.as_view(), name='rule_list'), # POST to create
    path('rules/library', RuleListView.as_view(), name='rule_library'), # GET list
    path('rules/<int:pk>', RuleDetailView.as_view(), name='rule_detail'),
    path('rules/analytics', RuleAnalyticsView.as_view(), name='rule_analytics'),
    path('rules/schema/fields', RuleSchemaFieldsView.as_view(), name='rule_schema_fields'),
    path('rules/schema/values', RuleSchemaValuesView.as_view(), name='rule_schema_values'),
    path('rules/templates', RuleTemplatesView.as_view(), name='rule_templates'),
]
