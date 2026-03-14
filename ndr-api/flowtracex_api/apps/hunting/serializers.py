from rest_framework import serializers
from .models import Hunt

class HuntSerializer(serializers.ModelSerializer):
    # Return author as a simple string (username) for frontend compatibility
    author = serializers.SerializerMethodField()

    class Meta:
        model = Hunt
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']

    def get_author(self, obj):
        if obj.author:
            return obj.author.username
        return 'Unknown'
