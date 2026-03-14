from django.apps import AppConfig


class ControlPlaneConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.control_plane'
    verbose_name = 'Control Plane'
