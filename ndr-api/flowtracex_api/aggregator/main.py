import os
import django
import sys

# Setup Django environment
sys.path.append('/opt/node_frontend/python_dev/flowtracex_api')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'flowtracex_api.settings')
django.setup()

from aggregator.worker import AggregatorWorker

if __name__ == '__main__':
    worker = AggregatorWorker()
    worker.run_forever()
