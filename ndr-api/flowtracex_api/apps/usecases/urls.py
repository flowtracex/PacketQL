from django.urls import path
from .views import (
    UseCaseListView,
    UseCaseDetailView,
    SignalListView,
    SignalDetailView,
)

urlpatterns = [
    path('usecases/', UseCaseListView.as_view(), name='usecase_list'),
    # Signals must come before the str:pk catch-all
    path('usecases/signals/', SignalListView.as_view(), name='signal_list'),
    path('usecases/signals/<str:pk>/', SignalDetailView.as_view(), name='signal_detail'),
    path('usecases/<str:pk>/', UseCaseDetailView.as_view(), name='usecase_detail'),
]
