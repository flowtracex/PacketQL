from ..base.system_repo import SystemRepository
from apps.system.models import SystemIdentity, Preferences, AuditLog
from apps.system.serializers import SystemIdentitySerializer, PreferencesSerializer, AuditLogSerializer
from django.core.paginator import Paginator

class DemoSystemRepository(SystemRepository):
    _ANON_PREFS = {
        "theme": "dark",
        "timezone": "UTC",
        "alerts_per_page": 10,
        "notifications_enabled": True,
    }

    def get_health(self):
        return {
            "status": "healthy",
            "cpu": 15,
            "memory": 40,
            "disk": 20,
            "services": {"duckdb": "up", "celery": "up"}
        }

    def get_logs(self, filters, page=1, limit=10):
        return {"logs": [], "total": 0} # System logs from file/journal

    def get_audit_logs(self, filters, page=1, limit=10):
        queryset = AuditLog.objects.all().order_by('-timestamp')
        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)
        return {
            "logs": AuditLogSerializer(page_obj.object_list, many=True).data,
            "total": paginator.count
        }

    def get_identity(self):
        # Return first or default
        identity = SystemIdentity.objects.first()
        if not identity:
            return {"hostname": "flowtracex-demo", "version": "1.0.0"}
        return SystemIdentitySerializer(identity).data

    def get_preferences(self, user):
        if not user or getattr(user, "is_anonymous", True):
            return dict(self._ANON_PREFS)
        pref, _ = Preferences.objects.get_or_create(user=user)
        return PreferencesSerializer(pref).data

    def update_preferences(self, user, data):
        if not user or getattr(user, "is_anonymous", True):
            merged = dict(self._ANON_PREFS)
            for key, value in (data or {}).items():
                if key in merged:
                    merged[key] = value
            return merged
        pref, _ = Preferences.objects.get_or_create(user=user)
        for key, value in data.items():
            setattr(pref, key, value)
        pref.save()
        return PreferencesSerializer(pref).data
