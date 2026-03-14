"""
Use Case + Signal Repository — reads from Redis (synced by ndr-baseline detection-sync job).
"""
import json
import redis
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


def _get_redis():
    try:
        return redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True,
        )
    except Exception as e:
        logger.error(f"Redis connection error: {e}")
        return None


class UseCaseRepository:
    """Reads system use cases and signals from Redis."""

    def list_usecases(self):
        r = _get_redis()
        if not r:
            return []
        try:
            raw = r.get("ndr:system:usecases")
            return json.loads(raw) if raw else []
        except Exception as e:
            logger.error(f"Error listing use cases: {e}")
            return []

    def get_usecase(self, uc_id):
        r = _get_redis()
        if not r:
            return None
        try:
            raw = r.get(f"ndr:system:usecase:{uc_id}")
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error(f"Error getting use case {uc_id}: {e}")
            return None

    def list_signals(self):
        r = _get_redis()
        if not r:
            return []
        try:
            raw = r.get("ndr:system:signals")
            return json.loads(raw) if raw else []
        except Exception as e:
            logger.error(f"Error listing signals: {e}")
            return []

    def get_signal(self, sig_id):
        r = _get_redis()
        if not r:
            return None
        try:
            raw = r.get(f"ndr:system:signal:{sig_id}")
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error(f"Error getting signal {sig_id}: {e}")
            return None
