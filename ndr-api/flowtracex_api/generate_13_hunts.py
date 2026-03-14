
import requests
import json
import time

API_URL = "http://localhost:8000/api/v1/hunting/hunts"
RUN_URL = "http://localhost:8000/api/v1/hunting/run"

HUNTS = [
    # --- VISUAL HUNTS (5) ---
    {
        "name": "1. C2 Beaconing ( Visual )",
        "description": "Detects periodic connections to known C2 port.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [{"field": "dst_port", "operator": "==", "value": "443"}]  # Matches generated C2
    },
    {
        "name": "2. High Volume Data Transfer ( Visual )",
        "description": "Detects large outbound transfers.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [{"field": "orig_bytes", "operator": ">", "value": "1000000"}] # Matches generated Exfil
    },
    {
        "name": "3. DNS Tunneling Candidates ( Visual )",
        "description": "Detects specific tunneling domain pattern.",
        "type": "visual",
        "log_source": "dns",
        "conditions": [{"field": "query", "operator": "CONTAINS", "value": "tunnel.evil.com"}] # Matches generated Tunneling
    },
    {
        "name": "4. Suspicious User Agent ( Visual )",
        "description": "Detects rare or suspicious user agents.",
        "type": "visual",
        "log_source": "http",
        "conditions": [{"field": "user_agent", "operator": "CONTAINS", "value": "python"}] 
    },
    {
        "name": "5. Non-Standard Port HTTP ( Visual )",
        "description": "Detects HTTP traffic on non-80/443 ports.",
        "type": "visual",
        "log_source": "http",
        "conditions": [{"field": "dst_port", "operator": ">", "value": "1024"}]
    },

    # --- SQL HUNTS (5) ---
    {
        "name": "6. Top Talkers ( SQL )",
        "description": "Identifies top source IPs by volume.",
        "type": "sql",
        "log_source": "conn",
        "sql_query": "SELECT src_ip, SUM(orig_bytes) as total_bytes FROM conn GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 10"
    },
    {
        "name": "7. Rare DNS Types ( SQL )",
        "description": "Finds uncommon DNS query types.",
        "type": "sql",
        "log_source": "dns",
        "sql_query": "SELECT qtype_name, count(*) as count FROM dns GROUP BY qtype_name ORDER BY count ASC LIMIT 10"
    },
    {
        "name": "8. Long DNS Queries ( SQL )",
        "description": "Detects potentially encoded DNS queries.",
        "type": "sql",
        "log_source": "dns",
        "sql_query": "SELECT query, length(query) as len FROM dns WHERE len > 50 ORDER BY len DESC LIMIT 20"
    },
    {
        "name": "9. HTTP Errors Spikes ( SQL )",
        "description": "Detects high volume of 4xx/5xx errors.",
        "type": "sql",
        "log_source": "http",
        "sql_query": "SELECT status_code, count(*) as count FROM http WHERE status_code >= 400 GROUP BY status_code ORDER BY count DESC"
    },
    {
        "name": "10. Connection Duration Outliers ( SQL )",
        "description": "Detects unusually long connections.",
        "type": "sql",
        "log_source": "conn",
        "sql_query": "SELECT src_ip, dst_ip, duration FROM conn ORDER BY duration DESC LIMIT 10"
    },

    # --- HYBRID/COMPLEX HUNTS (3) ---
    {
        "name": "11. Potential SSH Brute Force ( Visual )",
        "description": "Detects high frequency of small packets on port 22.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [{"field": "dst_port", "operator": "==", "value": "22"}]
    },
    {
        "name": "12. C2 Domains ( SQL )",
        "description": "Extracts domains associated with C2 IP.",
        "type": "sql",
        "log_source": "dns",
        "sql_query": "SELECT query, count(*) FROM dns WHERE dst_ip = '45.33.22.11' GROUP BY query"
    },
     {
        "name": "13. Cleartext Passwords ( SQL )",
        "description": "Detects unencrypted HTTP POSTs.",
        "type": "sql",
        "log_source": "http",
        "sql_query": "SELECT src_ip, uri, password FROM http WHERE method = 'POST' AND password IS NOT NULL"
    }
]

def create_and_run_hunts():
    print(f"Generating {len(HUNTS)} Hunt Scenarios...")
    
    for i, hunt_def in enumerate(HUNTS):
        print(f"[{i+1}/{len(HUNTS)}] Creating: {hunt_def['name']}...")
        
        # 1. Create
        try:
            res = requests.post(API_URL, json=hunt_def)
            if res.status_code != 201:
                print(f"  Error creating hunt: {res.text}")
                continue
            
            hunt_data = res.json()
            hunt_id = hunt_data['id']
            print(f"  Created ID: {hunt_id}")
            
            # 2. Run
            print(f"  Running hunt...")
            run_params = {
                "hunt_id": hunt_id,
                "query_type": hunt_def['type'],
                "log_source": hunt_def.get('log_source'),
                "conditions": hunt_def.get('conditions', []),
                "query": hunt_def.get('sql_query')
            }
            
            start_t = time.time()
            res_run = requests.post(RUN_URL, json=run_params)
            duration = time.time() - start_t
            
            if res_run.status_code == 200:
                run_data = res_run.json()
                matches = run_data.get('total', 0)
                print(f"  Success! Matches: {matches} (Time: {duration:.2f}s)")
            else:
                print(f"  Run Failed: {res_run.text}")
                
        except Exception as e:
            print(f"  Exception: {e}")
            
    print("\nDone. 13 Hunts Created and Executed.")

if __name__ == "__main__":
    create_and_run_hunts()
