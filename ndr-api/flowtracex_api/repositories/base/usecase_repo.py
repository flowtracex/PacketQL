"""
Use Case + Signal Repository — reads from local control-plane state.
"""
import json
import logging
from clients.state_store_client import StateStoreClient

logger = logging.getLogger(__name__)


class UseCaseRepository:
    """Reads system use cases and signals from local state."""

    def list_usecases(self):
        try:
            raw = StateStoreClient.get("ndr:system:usecases")
            return json.loads(raw) if raw else []
        except Exception as e:
            logger.error(f"Error listing use cases: {e}")
            return []

    def get_usecase(self, uc_id):
        try:
            raw = StateStoreClient.get(f"ndr:system:usecase:{uc_id}")
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error(f"Error getting use case {uc_id}: {e}")
            return None

    def list_signals(self):
        try:
            raw = StateStoreClient.get("ndr:system:signals")
            return json.loads(raw) if raw else []
        except Exception as e:
            logger.error(f"Error listing signals: {e}")
            return []

    def get_signal(self, sig_id):
        try:
            raw = StateStoreClient.get(f"ndr:system:signal:{sig_id}")
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error(f"Error getting signal {sig_id}: {e}")
            return None
