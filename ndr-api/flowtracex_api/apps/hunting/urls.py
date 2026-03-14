from django.urls import path
from .views import (
    HuntListView,
    HuntDetailView,
    HuntRunView,
    HuntCategoriesView,
    HuntTemplatesView,
    HuntRunsView,
    HuntRunDetailView,
    LogEntryLookupView
)

urlpatterns = [
    path('hunting/hunts', HuntListView.as_view(), name='hunt_list'),
    path('hunting/hunts/<int:pk>', HuntDetailView.as_view(), name='hunt_detail'),
    path('hunting/hunts/<int:pk>/runs', HuntRunsView.as_view(), name='hunt_runs'),
    path('hunting/runs/<int:pk>', HuntRunDetailView.as_view(), name='hunt_run_detail'),
    path('hunting/run', HuntRunView.as_view(), name='hunt_run'),
    path('hunting/categories', HuntCategoriesView.as_view(), name='hunt_categories'),
    path('hunting/templates', HuntTemplatesView.as_view(), name='hunt_templates'),
    path('hunting/log-entry/<str:uid>', LogEntryLookupView.as_view(), name='log_entry_lookup'),
]

