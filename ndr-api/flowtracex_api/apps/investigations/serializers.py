from rest_framework import serializers
from .models import Investigation, InvestigationTimeline, Note, EvidenceMeta
from apps.authentication.serializers import UserSerializer

class InvestigationTimelineSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = InvestigationTimeline
        fields = '__all__'

class NoteSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    class Meta:
        model = Note
        fields = '__all__'

class EvidenceMetaSerializer(serializers.ModelSerializer):
    uploaded_by = UserSerializer(read_only=True)
    class Meta:
        model = EvidenceMeta
        fields = '__all__'

class InvestigationSerializer(serializers.ModelSerializer):
    assigned_to = UserSerializer(read_only=True)
    owner = UserSerializer(read_only=True)
    
    # These fields will be populated by repo/service
    alert_count = serializers.IntegerField(required=False, read_only=True)
    asset_count = serializers.IntegerField(required=False, read_only=True)
    
    class Meta:
        model = Investigation
        fields = '__all__'
