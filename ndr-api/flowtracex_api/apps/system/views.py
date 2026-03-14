from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.system_service import SystemService
from django.conf import settings

class SystemHealthView(APIView):

    def get(self, request):
        service = SystemService()
        data = service.get_health()
        return Response(data)

class SystemLogsView(APIView):

    def get(self, request):
        service = SystemService()
        data = service.get_logs(request.query_params.dict())
        return Response(data)

class SystemAuditLogsView(APIView):

    def get(self, request):
        service = SystemService()
        data = service.get_audit_logs(request.query_params.dict())
        return Response(data)

class SystemIdentityView(APIView):

    def get(self, request):
        service = SystemService()
        data = service.get_identity()
        return Response(data)

class SystemPreferencesView(APIView):

    def get(self, request):
        service = SystemService()
        data = service.get_preferences(request.user)
        return Response(data)

    def patch(self, request):
        service = SystemService()
        data = service.update_preferences(request.user, request.data)
        return Response(data)


class SystemConfigView(APIView):
    """
    Runtime platform configuration exposed to the frontend.
    Returns APP_MODE so the React client doesn't need to bake it in at build time.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({
            "app_mode": getattr(settings, 'APP_MODE', 'production'),
            "version": getattr(settings, 'NDR_VERSION', '1.0.0'),
        })
