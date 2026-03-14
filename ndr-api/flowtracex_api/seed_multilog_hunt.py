"""
Seed a multi-log correlation hunt that joins conn + dns + http tables.
Run: python3 seed_multilog_hunt.py
"""
import os, sys, django, requests

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'flowtracex_api.settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

API = 'http://localhost:8000/api/v1'

# Multi-log correlation hunt: DNS lookups that led to HTTP connections
# This joins dns and http via src_ip to find hosts doing both DNS resolution and HTTP requests
hunt_data = {
    "name": "DNS-to-HTTP Correlation: Suspicious Browsing",
    "hypothesis": "Identify hosts that performed DNS lookups and then made HTTP connections to the resolved hosts, indicating potential C2 beacon or data exfiltration behavior",
    "type": "sql",
    "log_source": "dns",
    "sql_query": """SELECT 
    d.src_ip AS source_host,
    d.query AS dns_query,
    d.answers AS dns_answer,
    h.host AS http_host,
    h.method AS http_method,
    h.uri AS http_uri,
    h.status_code,
    h.user_agent,
    c.dst_port AS conn_port,
    c.service AS conn_service,
    c.duration AS conn_duration,
    c.orig_bytes AS bytes_sent,
    c.resp_bytes AS bytes_received,
    d.uid AS dns_uid,
    h.uid AS http_uid,
    c.uid AS conn_uid
FROM dns d
JOIN http h ON d.src_ip = h.src_ip
JOIN conn c ON d.src_ip = c.src_ip AND h.dst_ip = c.dst_ip
ORDER BY d.src_ip, d.ts
LIMIT 50""",
    "conditions": [],
    "time_range": "Last 24h",
    "status": "created"
}

print("Creating multi-log correlation hunt...")
resp = requests.post(f"{API}/hunting/hunts", json=hunt_data)
if resp.status_code == 201:
    hunt = resp.json()
    hunt_id = hunt['id']
    print(f"  Created hunt ID: {hunt_id}")
    
    # Run it
    print("  Running hunt...")
    run_resp = requests.post(f"{API}/hunting/run", json={
        "hunt_id": str(hunt_id),
        "query_type": "sql",
        "query": hunt_data["sql_query"],
        "log_source": "dns"
    })
    
    if run_resp.status_code == 200:
        result = run_resp.json()
        print(f"  Results: {result.get('total', 0)} matches")
        print(f"  Execution: {result.get('executionTime', 'N/A')}")
        if result.get('results'):
            print(f"\n  Sample result (first row):")
            row = result['results'][0]
            for k, v in row.items():
                print(f"    {k}: {v}")
    else:
        print(f"  Run failed: {run_resp.status_code} - {run_resp.text}")
else:
    print(f"  Create failed: {resp.status_code} - {resp.text}")

print("\nDone!")
