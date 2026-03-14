from django.urls import path
from .views import (
    SystemHealthView,
    SystemLogsView,
    SystemAuditLogsView,
    SystemIdentityView,
    SystemPreferencesView,
    SystemConfigView,
)

urlpatterns = [
    path('system/health', SystemHealthView.as_view(), name='system_health'),
    path('system/logs', SystemLogsView.as_view(), name='system_logs'),
    path('system/audit-logs', SystemAuditLogsView.as_view(), name='system_audit_logs'),
    path('system/identity', SystemIdentityView.as_view(), name='system_identity'),
    path('system/preferences', SystemPreferencesView.as_view(), name='system_preferences'),
    path('system/config', SystemConfigView.as_view(), name='system_config'),
]
