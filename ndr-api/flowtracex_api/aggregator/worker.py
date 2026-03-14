import time
import logging
from django.conf import settings
from apps.rules.models import Rule, RuleStats
from clients.duckdb_client import DuckDBClient
from clients.redis_client import RedisClient

logger = logging.getLogger('aggregator')

class AggregatorWorker:
    def run_forever(self):
        logger.info("Starting Aggregator Worker...")
        while True:
            try:
                self.update_rule_stats()
                self.update_network_analytics()
                time.sleep(60) # Run every minute
            except Exception as e:
                logger.error(f"Aggregator error: {e}")
                time.sleep(10)

    def update_rule_stats(self):
        if settings.APP_MODE == 'demo':
            return # No-op for demo
            
        logger.info("Updating Rule Stats...")
        # 1. Get all enabled rules
        rules = Rule.objects.filter(enabled=True)
        
        for rule in rules:
            # 2. Query DuckDB for alert counts for this rule
            # Placeholder query
            # count = DuckDBClient.execute_query(f"SELECT COUNT(*) FROM alerts WHERE rule_id={rule.id}")
            count = 0 
            
            # 3. Update SQLite RuleStats
            stats, created = RuleStats.objects.get_or_create(rule=rule)
            stats.detections_24h = count
            stats.save()

    def update_network_analytics(self):
         if settings.APP_MODE == 'demo':
            return
            
         # Calculate network stats from DuckDB and cache in Redis
         # stats = ...
         # RedisClient.set("network:analytics", json.dumps(stats))
         pass
