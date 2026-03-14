from rest_framework import serializers
from .models import Notification, MitreTactic, MitreTechnique
from django.contrib.auth import get_user_model

User = get_user_model()

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'

class MitreTacticSerializer(serializers.ModelSerializer):
    class Meta:
        model = MitreTactic
        fields = '__all__'

class MitreTechniqueSerializer(serializers.ModelSerializer):
    class Meta:
        model = MitreTechnique
        fields = '__all__'

class AnalystSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='full_name')
    class Meta:
        model = User
        fields = ['id', 'name', 'avatar', 'role']
