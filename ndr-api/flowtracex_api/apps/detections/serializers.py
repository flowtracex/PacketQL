from rest_framework import serializers
from .models import Alert, AlertSignal
from apps.authentication.serializers import UserSerializer

class AlertSignalSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertSignal
        fields = '__all__'

class AlertSerializer(serializers.ModelSerializer):
    assigned_to = UserSerializer(read_only=True)
    signals = AlertSignalSerializer(many=True, read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'
