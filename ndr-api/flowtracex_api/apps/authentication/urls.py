from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    CustomTokenObtainPairView,
    LogoutView,
    UserDetailView,
    ChangePasswordView
)

urlpatterns = [
    path('auth/login', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout', LogoutView.as_view(), name='auth_logout'),
    path('auth/me', UserDetailView.as_view(), name='auth_me'),
    path('auth/change-password', ChangePasswordView.as_view(), name='auth_change_password'),
]
