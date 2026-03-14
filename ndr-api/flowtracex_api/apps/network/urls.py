from django.urls import path
from .views import (
    NetworkTopologyView,
    NetworkServicesView,
    NetworkFlowsView,
    NetworkAnalyticsView,
    NetworkPCAPView
)

urlpatterns = [
    path('network/topology', NetworkTopologyView.as_view(), name='network_topology'),
    path('network/services', NetworkServicesView.as_view(), name='network_services'),
    path('network/flows', NetworkFlowsView.as_view(), name='network_flows'),
    path('network/analytics', NetworkAnalyticsView.as_view(), name='network_analytics'),
    path('network/pcap/<str:pk>', NetworkPCAPView.as_view(), name='network_pcap'), # str:pk because ID might be uuid or string
]
