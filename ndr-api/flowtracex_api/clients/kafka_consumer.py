from kafka import KafkaConsumer
from django.conf import settings
import json
import logging

logger = logging.getLogger(__name__)

class KafkaLogConsumer:
    @staticmethod
    def get_consumer(topic=None):
        if not topic:
            topic = settings.KAFKA_TOPIC_LOGS
            
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                group_id='raceflowx-live-stream-group',
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            return consumer
        except Exception as e:
            logger.error(f"Kafka consumer connection error: {e}")
            return None

    @staticmethod
    def stream_logs():
        consumer = KafkaLogConsumer.get_consumer()
        if consumer:
            for message in consumer:
                yield f"data: {json.dumps(message.value)}\n\n"
