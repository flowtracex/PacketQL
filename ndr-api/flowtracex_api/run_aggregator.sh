#!/bin/bash
export APP_MODE=demo
export PYTHONUNBUFFERED=1
cd /opt/node_frontend/python_dev/flowtracex_api
python3 aggregator/main.py > aggregator.log 2>&1 &
echo $! > aggregator.pid
echo "Aggregator started with PID $(cat aggregator.pid)"
