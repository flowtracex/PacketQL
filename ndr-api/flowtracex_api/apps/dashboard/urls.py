from django.urls import path
from .views import (
    DashboardOverviewView,
    DashboardTrafficView,
    DashboardProtocolView,
    DashboardCoverageView
)

urlpatterns = [
    path('dashboard/overview', DashboardOverviewView.as_view(), name='dashboard_overview'),
    path('dashboard/network-traffic', DashboardTrafficView.as_view(), name='dashboard_traffic'),
    path('dashboard/protocol-distribution', DashboardProtocolView.as_view(), name='dashboard_protocols'),
    path('dashboard/deep-inspection', DashboardCoverageView.as_view(), name='dashboard_coverage'),
]
