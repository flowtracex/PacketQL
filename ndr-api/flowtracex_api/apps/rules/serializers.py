from rest_framework import serializers
from .models import Rule, RuleStats
from apps.authentication.serializers import UserSerializer

class RuleStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleStats
        fields = '__all__'

class RuleSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    stats = RuleStatsSerializer(read_only=True)
    
    class Meta:
        model = Rule
        fields = '__all__'
