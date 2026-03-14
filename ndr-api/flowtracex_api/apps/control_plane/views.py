"""
Control Plane API Views — REST endpoints for detection tuning.

All modifications are validated server-side:
  - Thresholds can only be increased, never below engineering minimum
  - Sensitivity only accepts valid modes
  - Suppressions are TTL-based (auto-expire)
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from services.control_plane_service import ControlPlaneService


class GlobalSettingsView(APIView):
    """GET/PUT global detection settings."""

    def get(self, request):
        service = ControlPlaneService()
        return Response(service.get_global_config())

    def put(self, request):
        service = ControlPlaneService()
        try:
            data = service.update_global_config(request.data)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SignalControlListView(APIView):
    """GET all signals with control state."""

    def get(self, request):
        service = ControlPlaneService()
        return Response(service.list_signals())


class SignalControlDetailView(APIView):
    """GET/PUT single signal control."""

    def get(self, request, signal_id):
        service = ControlPlaneService()
        data = service.get_signal(signal_id)
        if not data:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(data)

    def put(self, request, signal_id):
        service = ControlPlaneService()
        try:
            data = service.update_signal(signal_id, request.data)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SignalSuppressView(APIView):
    """POST to suppress, DELETE to remove suppression."""

    def post(self, request, signal_id):
        service = ControlPlaneService()
        ttl = int(request.data.get("ttl_seconds", 3600))
        reason = request.data.get("reason", "")
        try:
            data = service.suppress_signal(signal_id, ttl, reason)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, signal_id):
        service = ControlPlaneService()
        removed = service.remove_signal_suppression(signal_id)
        return Response({"removed": removed})


class UseCaseControlListView(APIView):
    """GET all use cases with control state."""

    def get(self, request):
        service = ControlPlaneService()
        return Response(service.list_usecases())


class UseCaseControlDetailView(APIView):
    """GET/PUT single use case control."""

    def get(self, request, uc_id):
        service = ControlPlaneService()
        data = service.get_usecase(uc_id)
        if not data:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(data)

    def put(self, request, uc_id):
        service = ControlPlaneService()
        try:
            data = service.update_usecase(uc_id, request.data)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UseCaseSuppressView(APIView):
    """POST to suppress UC, DELETE to remove."""

    def post(self, request, uc_id):
        service = ControlPlaneService()
        ttl = int(request.data.get("ttl_seconds", 3600))
        reason = request.data.get("reason", "")
        try:
            data = service.suppress_usecase(uc_id, ttl, reason)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, uc_id):
        service = ControlPlaneService()
        removed = service.remove_usecase_suppression(uc_id)
        return Response({"removed": removed})


class SuppressionCenterView(APIView):
    """GET all active suppressions."""

    def get(self, request):
        service = ControlPlaneService()
        return Response(service.get_all_suppressions())


class PresetApplyView(APIView):
    """POST to apply a named preset."""

    def post(self, request, preset_name):
        service = ControlPlaneService()
        try:
            data = service.apply_preset(preset_name)
            return Response(data)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, preset_name=None):
        """GET lists available presets."""
        service = ControlPlaneService()
        return Response(service.list_presets())
