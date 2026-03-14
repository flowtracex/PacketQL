from django.urls import path
from .views import (
    LogSearchView,
    LogAnalyticsView,
    LogLiveStreamView
)

urlpatterns = [
    path('logs/search', LogSearchView.as_view(), name='log_search'),
    path('logs/analytics', LogAnalyticsView.as_view(), name='log_analytics'),
    path('logs/live', LogLiveStreamView.as_view(), name='log_live'),
]
