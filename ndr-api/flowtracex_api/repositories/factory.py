from django.conf import settings
from typing import Type

from repositories.base.dashboard_repo import DashboardRepository
from repositories.demo.dashboard_repo import DemoDashboardRepository
from repositories.production.dashboard_repo import ProductionDashboardRepository

from repositories.base.detection_repo import DetectionRepository
from repositories.demo.detection_repo import DemoDetectionRepository
from repositories.production.detection_repo import ProductionDetectionRepository

from repositories.base.hunting_repo import HuntingRepository
from repositories.demo.hunting_repo import DemoHuntingRepository
from repositories.production.hunting_repo import ProductionHuntingRepository

from repositories.base.log_repo import LogRepository
from repositories.demo.log_repo import DemoLogRepository
from repositories.production.log_repo import ProductionLogRepository


class RepositoryFactory:
    """
    Factory to instantiate repositories based on APP_MODE.
    """

    @staticmethod
    def get_dashboard_repository() -> DashboardRepository:
        mode = getattr(settings, 'APP_MODE', 'demo')
        if mode == 'production':
            return ProductionDashboardRepository()
        return DemoDashboardRepository()
    
    @staticmethod
    def get_detection_repository() -> DetectionRepository:
        mode = getattr(settings, 'APP_MODE', 'demo')
        if mode == 'production':
            return ProductionDetectionRepository()
        return DemoDetectionRepository()

    @staticmethod
    def get_hunting_repository() -> HuntingRepository:
        mode = getattr(settings, 'APP_MODE', 'demo')
        if mode == 'production':
            return ProductionHuntingRepository()
        return DemoHuntingRepository()

    @staticmethod
    def get_log_repository() -> LogRepository:
        mode = getattr(settings, 'APP_MODE', 'demo')
        if mode == 'production':
            return ProductionLogRepository()
        return DemoLogRepository()
