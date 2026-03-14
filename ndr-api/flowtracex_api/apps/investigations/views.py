from rest_framework import generics, permissions, status, parsers
from rest_framework.views import APIView
from rest_framework.response import Response
from services.investigation_service import InvestigationService
from .serializers import InvestigationSerializer
import logging

logger = logging.getLogger(__name__)

class InvestigationListView(APIView):

    def get(self, request):
        service = InvestigationService()
        filters = {
            'status': request.query_params.get('status'),
            'severity': request.query_params.getlist('severity[]'),
            'search': request.query_params.get('search'),
            'mitre_tactic': request.query_params.get('mitre_tactic'),
        }
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        
        data = service.list_investigations(filters, page, limit)
        return Response(data)

    def post(self, request):
        service = InvestigationService()
        # Ensure owner is set to current user if not provided
        data = request.data.copy()
        if 'owner' not in data:
            # We need to handle this in serializer or service since owner is a FK
            # For now passing it in context or relying on default view logic
            pass 
        
        # Manually create for now to keep it simple with service
        # Service expects dictionary for create
        create_data = request.data
        # Assign owner
        # In a real app we'd use serializer.save(owner=request.user)
        # Here we mock or adjust
        
        # Using a specialized create method in service/repo that takes user
        # For now, let's assume request.data has what we need or we patch it
        # This is a simplification
        # We need to set owner_id
        create_data['owner'] = request.user
        
        result = service.create_investigation(create_data)
        return Response(result, status=status.HTTP_201_CREATED)

class InvestigationDetailView(APIView):

    def get(self, request, pk):
        service = InvestigationService()
        data = service.get_investigation_detail(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, pk):
        service = InvestigationService()
        data = service.update_investigation(pk, request.data)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

class InvestigationActionView(APIView):
    action = None # 'resolve', 'escalate', 'isolate', 'verdict'

    def post(self, request, pk):
        service = InvestigationService()
        
        if self.action == 'resolve':
            data = service.update_investigation(pk, {'status': 'closed'})
            return Response(data)
        elif self.action == 'escalate':
            # Assign to current user
            data = service.update_investigation(pk, {'assigned_to': request.user})
            return Response(data)
        elif self.action == 'isolate':
             # Mock isolation
             return Response({"status": "isolation_requested"})
        elif self.action == 'verdict':
             data = service.update_investigation(pk, {
                 'verdict': request.data.get('verdict'),
                 'justification': request.data.get('justification'),
                 'status': 'closed' # Usually implies closing
             })
             return Response(data)
             
        return Response(status=status.HTTP_400_BAD_REQUEST)

class InvestigationAlertsView(APIView):

    def get(self, request, pk):
        service = InvestigationService()
        data = service.get_investigation_alerts(pk)
        return Response(data)

class InvestigationTimelineView(APIView):

    def get(self, request, pk):
        service = InvestigationService()
        data = service.get_timeline(pk)
        return Response(data)

class InvestigationNotesView(APIView):

    def get(self, request, pk):
        service = InvestigationService()
        data = service.get_notes(pk)
        return Response(data)

    def post(self, request, pk):
        service = InvestigationService()
        text = request.data.get('text')
        data = service.add_note(pk, text, request.user)
        if data:
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class InvestigationEvidenceView(APIView):
    parser_classes = (parsers.MultiPartParser, parsers.FormParser)

    def get(self, request, pk):
        # List evidence metadata
        # Need to add this method to service/repo
        # For now return empty list
        return Response([])

    def post(self, request, pk):
        # Handle file upload
        file_obj = request.FILES.get('file')
        # Logic to save file and create EvidenceMeta
        # Mocking for now
        return Response({"status": "uploaded", "filename": file_obj.name}, status=status.HTTP_201_CREATED)
