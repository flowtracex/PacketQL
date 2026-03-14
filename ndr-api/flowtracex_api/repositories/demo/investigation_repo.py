from ..base.investigation_repo import InvestigationRepository
from apps.investigations.models import Investigation, InvestigationAlert, InvestigationTimeline, Note
from apps.investigations.serializers import InvestigationSerializer, InvestigationTimelineSerializer, NoteSerializer
from apps.detections.models import Alert
from apps.detections.serializers import AlertSerializer
from django.core.paginator import Paginator
from django.utils import timezone

class DemoInvestigationRepository(InvestigationRepository):
    def list_investigations(self, filters, page=1, limit=10):
        queryset = Investigation.objects.all().order_by('-created_at')
        
        if filters.get('status'):
            queryset = queryset.filter(status=filters['status'])
        if filters.get('severity'):
            queryset = queryset.filter(severity__in=filters['severity'])
        if filters.get('search'):
            from django.db.models import Q
            s = filters['search']
            queryset = queryset.filter(Q(name__icontains=s) | Q(description__icontains=s))
        if filters.get('mitre_tactic'):
            queryset = queryset.filter(mitre_stage__icontains=filters['mitre_tactic'])
            
        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)
        
        return {
            "investigations": InvestigationSerializer(page_obj.object_list, many=True).data,
            "total": paginator.count,
            "page": page_obj.number,
            "page_count": paginator.num_pages
        }

    def create_investigation(self, data):
        inv = Investigation.objects.create(**data)
        InvestigationTimeline.objects.create(
            investigation=inv, type="created", description="Investigation created", user=inv.owner
        )
        return InvestigationSerializer(inv).data

    def get_investigation_detail(self, inv_id):
        try:
            inv = Investigation.objects.get(pk=inv_id)
            return InvestigationSerializer(inv).data
        except Investigation.DoesNotExist:
            return None

    def update_investigation(self, inv_id, data):
        try:
            inv = Investigation.objects.get(pk=inv_id)
            for key, value in data.items():
                setattr(inv, key, value)
            inv.save()
            return InvestigationSerializer(inv).data
        except Investigation.DoesNotExist:
            return None

    def add_alert(self, inv_id, alert_id):
        try:
            inv = Investigation.objects.get(pk=inv_id)
            InvestigationAlert.objects.create(investigation=inv, alert_id=alert_id)
            InvestigationTimeline.objects.create(
                investigation=inv, type="alert_added", description=f"Alert {alert_id} added", user=inv.owner
            )
            return True
        except:
            return False

    def get_investigation_alerts(self, inv_id):
        # In Demo mode, we fetch Alert objects from SQLite
        # In Prod mode, wait for Prod implementation
        links = InvestigationAlert.objects.filter(investigation_id=inv_id)
        alert_ids = [link.alert_id for link in links]
        
        # Casting ids to appropriate type if needed
        # Assuming Alert ID is int for SQLite demo
        try:
            alert_ids_int = [int(aid) for aid in alert_ids]
            alerts = Alert.objects.filter(pk__in=alert_ids_int)
            return AlertSerializer(alerts, many=True).data
        except ValueError:
            return []

    def get_timeline(self, inv_id):
        timeline = InvestigationTimeline.objects.filter(investigation_id=inv_id).order_by('-timestamp')
        return InvestigationTimelineSerializer(timeline, many=True).data

    def add_note(self, inv_id, text, user):
        try:
            inv = Investigation.objects.get(pk=inv_id)
            note = Note.objects.create(investigation=inv, text=text, author=user)
            InvestigationTimeline.objects.create(
                investigation=inv, type="note_added", description="Note added", user=user
            )
            return NoteSerializer(note).data
        except:
            return None

    def get_notes(self, inv_id):
        notes = Note.objects.filter(investigation_id=inv_id).order_by('-created_at')
        return NoteSerializer(notes, many=True).data
