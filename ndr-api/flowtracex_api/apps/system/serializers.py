from rest_framework import serializers
from .models import SystemIdentity, Preferences, APIKey, AuditLog

class SystemIdentitySerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemIdentity
        fields = '__all__'

class PreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Preferences
        fields = '__all__'
        read_only_fields = ('user',)

class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ['id', 'name', 'key_prefix', 'created_at', 'last_used_at', 'expires_at']

class AuditLogSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    class Meta:
        model = AuditLog
        fields = '__all__'
