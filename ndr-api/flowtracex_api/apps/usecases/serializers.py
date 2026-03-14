from rest_framework import serializers
from .models import UseCase, UseCaseStage

class UseCaseStageSerializer(serializers.ModelSerializer):
    class Meta:
        model = UseCaseStage
        fields = '__all__'

class UseCaseSerializer(serializers.ModelSerializer):
    stages = UseCaseStageSerializer(many=True, read_only=True)
    class Meta:
        model = UseCase
        fields = '__all__'
