from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add extra user data to response
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'fullName': self.user.full_name,
            'role': self.user.role,
            'avatar': self.user.avatar
        }
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'full_name', 'role', 'avatar', 'last_login']
        read_only_fields = ['last_login']

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'avatar']
