import redis
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class RedisClient:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                decode_responses=True
            )
        return cls._instance

    @staticmethod
    def get(key):
        try:
            client = RedisClient.get_instance()
            return client.get(key)
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None

    @staticmethod
    def set(key, value, ex=None):
        try:
            client = RedisClient.get_instance()
            return client.set(key, value, ex=ex)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    @staticmethod
    def delete(key):
        try:
            client = RedisClient.get_instance()
            return client.delete(key)
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    @staticmethod
    def keys(pattern='*'):
        try:
            client = RedisClient.get_instance()
            return client.keys(pattern)
        except Exception as e:
            logger.error(f"Redis keys error: {e}")
            return []

    @staticmethod
    def hgetall(key):
        try:
            client = RedisClient.get_instance()
            return client.hgetall(key)
        except Exception as e:
            logger.error(f"Redis hgetall error: {e}")
            return {}

    @staticmethod
    def hget(key, field):
        try:
            client = RedisClient.get_instance()
            return client.hget(key, field)
        except Exception as e:
            logger.error(f"Redis hget error: {e}")
            return None

    @staticmethod
    def scan_keys(pattern='*', count=500):
        """Iterate keys matching pattern using SCAN (safer than KEYS for large datasets)."""
        try:
            client = RedisClient.get_instance()
            all_keys = []
            cursor = 0
            while True:
                cursor, batch = client.scan(cursor=cursor, match=pattern, count=count)
                all_keys.extend(batch)
                if cursor == 0:
                    break
            return all_keys
        except Exception as e:
            logger.error(f"Redis scan error: {e}")
            return []

    @classmethod
    @property
    def client(cls):
        return cls.get_instance()
