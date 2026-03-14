from django.urls import path
from .views import (
    AssetListView,
    AssetDetailView,
    AssetAnalyticsView,
    AssetActionView,
    AssetConfigLogView
)

urlpatterns = [
    path('assets', AssetListView.as_view(), name='asset_list'),
    path('assets/analytics', AssetAnalyticsView.as_view(), name='asset_analytics'),
    path('assets/<str:ip>', AssetDetailView.as_view(), name='asset_detail'), # Use str:ip because IP contains dots
    path('assets/<str:ip>/isolate', AssetActionView.as_view(action='isolate'), name='asset_isolate'),
    path('assets/<str:ip>/review', AssetActionView.as_view(action='review'), name='asset_review'),
    path('assets/<str:ip>/config-log', AssetConfigLogView.as_view(), name='asset_config_log'),
]
