from django.urls import path
from . import views

urlpatterns = [
    # Global settings
    path('control-plane/global/', views.GlobalSettingsView.as_view(), name='control-plane-global'),

    # Signals
    path('control-plane/signals/', views.SignalControlListView.as_view(), name='control-plane-signals'),
    path('control-plane/signals/<str:signal_id>/', views.SignalControlDetailView.as_view(), name='control-plane-signal-detail'),
    path('control-plane/signals/<str:signal_id>/suppress/', views.SignalSuppressView.as_view(), name='control-plane-signal-suppress'),

    # Use cases
    path('control-plane/usecases/', views.UseCaseControlListView.as_view(), name='control-plane-usecases'),
    path('control-plane/usecases/<str:uc_id>/', views.UseCaseControlDetailView.as_view(), name='control-plane-usecase-detail'),
    path('control-plane/usecases/<str:uc_id>/suppress/', views.UseCaseSuppressView.as_view(), name='control-plane-usecase-suppress'),

    # Suppressions center
    path('control-plane/suppressions/', views.SuppressionCenterView.as_view(), name='control-plane-suppressions'),

    # Presets
    path('control-plane/presets/<str:preset_name>/', views.PresetApplyView.as_view(), name='control-plane-preset'),
]
