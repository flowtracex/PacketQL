import fnmatch
import logging
import time

logger = logging.getLogger(__name__)


class _LocalStore:
    def __init__(self):
        self._values = {}
        self._expires = {}

    def _purge_expired(self):
        now = time.time()
        expired = [key for key, exp in self._expires.items() if exp is not None and exp <= now]
        for key in expired:
            self._values.pop(key, None)
            self._expires.pop(key, None)

    def get(self, key):
        self._purge_expired()
        value = self._values.get(key)
        if isinstance(value, dict):
            return None
        return value

    def set(self, key, value, ex=None):
        self._purge_expired()
        self._values[key] = value
        self._expires[key] = time.time() + ex if ex else None
        return True

    def delete(self, key):
        self._purge_expired()
        existed = key in self._values
        self._values.pop(key, None)
        self._expires.pop(key, None)
        return 1 if existed else 0

    def keys(self, pattern="*"):
        self._purge_expired()
        return [key for key in self._values.keys() if fnmatch.fnmatch(key, pattern)]

    def scan(self, cursor=0, match="*", count=500):
        self._purge_expired()
        keys = self.keys(match)
        start = int(cursor)
        batch = keys[start:start + count]
        next_cursor = 0 if start + count >= len(keys) else start + count
        return next_cursor, batch

    def hgetall(self, key):
        self._purge_expired()
        value = self._values.get(key)
        return dict(value) if isinstance(value, dict) else {}

    def hget(self, key, field):
        self._purge_expired()
        value = self._values.get(key)
        if isinstance(value, dict):
            return value.get(field)
        return None

    def ttl(self, key):
        self._purge_expired()
        if key not in self._values:
            return -2
        exp = self._expires.get(key)
        if exp is None:
            return -1
        return max(0, int(exp - time.time()))

    def ping(self):
        return True

    def type(self, key):
        self._purge_expired()
        value = self._values.get(key)
        if value is None:
            return "none"
        if isinstance(value, dict):
            return "hash"
        return "string"


class StateStoreClient:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = _LocalStore()
            logger.info("Initialized local in-process state store")
        return cls._instance

    @staticmethod
    def get(key):
        return StateStoreClient.get_instance().get(key)

    @staticmethod
    def set(key, value, ex=None):
        return StateStoreClient.get_instance().set(key, value, ex=ex)

    @staticmethod
    def delete(key):
        return StateStoreClient.get_instance().delete(key)

    @staticmethod
    def keys(pattern="*"):
        return StateStoreClient.get_instance().keys(pattern)

    @staticmethod
    def hgetall(key):
        return StateStoreClient.get_instance().hgetall(key)

    @staticmethod
    def hget(key, field):
        return StateStoreClient.get_instance().hget(key, field)

    @staticmethod
    def scan_keys(pattern="*", count=500):
        client = StateStoreClient.get_instance()
        all_keys = []
        cursor = 0
        while True:
            cursor, batch = client.scan(cursor=cursor, match=pattern, count=count)
            all_keys.extend(batch)
            if cursor == 0:
                break
        return all_keys

    @classmethod
    @property
    def client(cls):
        return cls.get_instance()
