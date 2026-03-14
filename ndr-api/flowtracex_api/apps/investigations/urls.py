from django.urls import path
from .views import (
    InvestigationListView,
    InvestigationDetailView,
    InvestigationActionView,
    InvestigationAlertsView,
    InvestigationTimelineView,
    InvestigationNotesView,
    InvestigationEvidenceView
)

urlpatterns = [
    path('investigations', InvestigationListView.as_view(), name='investigation_list'),
    path('investigations/analytics', InvestigationListView.as_view()), # Placeholder
    path('investigations/<int:pk>', InvestigationDetailView.as_view(), name='investigation_detail'),
    path('investigations/<int:pk>/resolve', InvestigationActionView.as_view(action='resolve'), name='investigation_resolve'),
    path('investigations/<int:pk>/escalate', InvestigationActionView.as_view(action='escalate'), name='investigation_escalate'),
    path('investigations/<int:pk>/isolate-host', InvestigationActionView.as_view(action='isolate'), name='investigation_isolate'),
    path('investigations/<int:pk>/verdict', InvestigationActionView.as_view(action='verdict'), name='investigation_verdict'),
    path('investigations/<int:pk>/alerts', InvestigationAlertsView.as_view(), name='investigation_alerts'),
    path('investigations/<int:pk>/timeline', InvestigationTimelineView.as_view(), name='investigation_timeline'),
    path('investigations/<int:pk>/notes', InvestigationNotesView.as_view(), name='investigation_notes'),
    path('investigations/<int:pk>/evidence', InvestigationEvidenceView.as_view(), name='investigation_evidence'),
    # Download evidence endpoint skipped for brevity, similar to detail
]
