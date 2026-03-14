from django.urls import path
from .views import (
    GlobalSearchView,
    AnalystListView,
    NotificationListView,
    NotificationReadView,
    MitreTacticListView,
    MitreTechniqueListView
)

urlpatterns = [
    path('common/search', GlobalSearchView.as_view(), name='global_search'),
    path('common/analysts', AnalystListView.as_view(), name='analyst_list'),
    path('common/notifications', NotificationListView.as_view(), name='notifications'),
    path('common/notifications/<int:pk>/read', NotificationReadView.as_view(), name='notification_read'),
    path('common/mitre/tactics', MitreTacticListView.as_view(), name='mitre_tactics'),
    path('common/mitre/techniques', MitreTechniqueListView.as_view(), name='mitre_techniques'),
]
