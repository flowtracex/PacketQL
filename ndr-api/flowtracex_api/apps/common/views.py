from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.db.models import Q
from .models import Notification, MitreTactic, MitreTechnique
from .serializers import (
    NotificationSerializer, 
    MitreTacticSerializer, 
    MitreTechniqueSerializer,
    AnalystSerializer
)
from django.contrib.auth import get_user_model
import json

User = get_user_model()

# Import Clients
if settings.APP_MODE == 'production':
    from clients.state_store_client import StateStoreClient
    from clients.duckdb_client import DuckDBClient

class GlobalSearchView(APIView):

    def get(self, request):
        query = request.query_params.get('q', '')
        search_type = request.query_params.get('type', None)
        
        results = {
            'alerts': [],
            'assets': [],
            'logs': []
        }
        
        if not query:
            return Response(results)

        if settings.APP_MODE == 'demo':
            # Demo Mode: Search SQLite (simulated/seeded)
            # For now, return empty or mock
            pass
        else:
            # Production Mode: DuckDB
            # Placeholder for DuckDB queries
            # client = DuckDBClient.get_connection()
            # results['alerts'] = ...
            pass
            
        return Response(results)

class AnalystListView(generics.ListAPIView):
    serializer_class = AnalystSerializer
    
    def get_queryset(self):
        return User.objects.filter(role__in=['analyst', 'admin'])

class NotificationListView(APIView):

    def get(self, request):
        limit = int(request.query_params.get('limit', 10))
        offset = int(request.query_params.get('offset', 0))

        if settings.APP_MODE == 'demo':
            notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[offset:offset+limit]
            serializer = NotificationSerializer(notifications, many=True)
            return Response(serializer.data)
        else:
            # Production mode: local state store
            key = f"notify:user:{request.user.id}:items"
            state_store = StateStoreClient.get_instance()
            # Assuming list of JSON strings
            # items = state_store.lrange(key, offset, offset+limit-1)
            # notifications = [json.loads(item) for item in items]
            # return Response(notifications)
            
            # Fallback to SQLite if the local state store has no items yet
            notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[offset:offset+limit]
            serializer = NotificationSerializer(notifications, many=True)
            return Response(serializer.data)

class NotificationReadView(APIView):

    def patch(self, request, pk):
        if settings.APP_MODE == 'demo':
            try:
                notification = Notification.objects.get(pk=pk, user=request.user)
                notification.read = True
                notification.save()
                return Response(NotificationSerializer(notification).data)
            except Notification.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            # Production: update local state and decrement count later if needed
            # For now fallback to SQLite
            try:
                notification = Notification.objects.get(pk=pk, user=request.user)
                notification.read = True
                notification.save()
                return Response(NotificationSerializer(notification).data)
            except Notification.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)

class MitreTacticListView(generics.ListAPIView):
    queryset = MitreTactic.objects.all()
    serializer_class = MitreTacticSerializer

class MitreTechniqueListView(generics.ListAPIView):
    serializer_class = MitreTechniqueSerializer

    def get_queryset(self):
        queryset = MitreTechnique.objects.all()
        tactic_id = self.request.query_params.get('tactic_id')
        if tactic_id:
            queryset = queryset.filter(tactic_id=tactic_id)
        return queryset
