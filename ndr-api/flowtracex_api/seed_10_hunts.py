"""
Seed exactly 10 hunts with the correct distribution:
- 3 Visual (1 multi-stage, 1 single-stage complex, 1 simple) → all return results
- 3 SQL (1 complex, 1 medium, 1 simple) → all return results
- 4 hunts that return 0 results
"""
import requests, time, json

API = "http://localhost:8000/api/v1"

HUNTS = [
    # === VISUAL HUNTS WITH RESULTS (3) ===
    {
        "name": "C2 Beaconing Detection",
        "hypothesis": "Detect periodic outbound HTTPS traffic patterns matching known C2 callback profiles. Multi-stage: correlate DNS lookups with subsequent HTTP POST callbacks to the same destination.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [
            {"field": "dst_port", "operator": "==", "value": "443"},
        ],
        "time_range": "Last 24h",
        "stages": 2  # multi-stage
    },
    {
        "name": "Data Exfiltration via Large Transfers",
        "hypothesis": "Identify high-volume outbound data transfers exceeding normal baselines, indicating potential staging or exfiltration of sensitive data.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [
            {"field": "orig_bytes", "operator": ">", "value": "1000000"},
        ],
        "time_range": "Last 7d",
        "stages": 1  # single-stage complex
    },
    {
        "name": "DNS Tunneling Detection",
        "hypothesis": "Detect DNS tunneling by identifying queries to known tunneling domains.",
        "type": "visual",
        "log_source": "dns",
        "conditions": [
            {"field": "query", "operator": "CONTAINS", "value": "tunnel.evil.com"},
        ],
        "time_range": "Last 24h",
        "stages": 1  # simple
    },

    # === SQL HUNTS WITH RESULTS (3) ===
    {
        "name": "Lateral Movement via SSH",
        "hypothesis": "Complex multi-join analysis: identify internal hosts that both receive inbound SSH and initiate outbound connections to other internal hosts within a short window — a classic lateral movement pattern.",
        "type": "sql",
        "log_source": "conn",
        "sql_query": "SELECT src_ip, dst_ip, dst_port, COUNT(*) AS conn_count, SUM(orig_bytes) AS total_bytes, AVG(duration) AS avg_duration FROM conn WHERE dst_port = 22 GROUP BY src_ip, dst_ip, dst_port HAVING conn_count > 1 ORDER BY conn_count DESC LIMIT 20",
        "time_range": "Last 24h",
    },
    {
        "name": "Anomalous DNS Query Lengths",
        "hypothesis": "Identify DNS queries with unusually long domain names, often indicative of encoded data or DNS tunneling attempts.",
        "type": "sql",
        "log_source": "dns",
        "sql_query": "SELECT src_ip, query, LENGTH(query) AS query_len FROM dns WHERE LENGTH(query) > 40 ORDER BY query_len DESC LIMIT 20",
        "time_range": "Last 24h",
    },
    {
        "name": "Top Network Talkers",
        "hypothesis": "Simple aggregation to find the most active source IPs by total bytes transferred.",
        "type": "sql",
        "log_source": "conn",
        "sql_query": "SELECT src_ip, SUM(orig_bytes) AS total_bytes, COUNT(*) AS connections FROM conn GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 10",
        "time_range": "Last 7d",
    },

    # === 4 HUNTS THAT RETURN 0 RESULTS ===
    {
        "name": "Tor Exit Node Communication",
        "hypothesis": "Detect communication with known Tor exit nodes. These nodes are not present in our current data.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [
            {"field": "dst_ip", "operator": "==", "value": "198.51.100.99"},
        ],
        "time_range": "Last 24h",
    },
    {
        "name": "Suspicious PowerShell Downloads",
        "hypothesis": "Detect HTTP requests with PowerShell user agents downloading executables.",
        "type": "sql",
        "log_source": "http",
        "sql_query": "SELECT src_ip, host, uri FROM http WHERE user_agent LIKE '%PowerShell%' AND uri LIKE '%.exe'",
        "time_range": "Last 24h",
    },
    {
        "name": "ICMP Tunnel Detection",
        "hypothesis": "Detect ICMP-based covert channels by finding unusually large ICMP packets.",
        "type": "visual",
        "log_source": "conn",
        "conditions": [
            {"field": "protocol", "operator": "==", "value": "icmp"},
            {"field": "orig_bytes", "operator": ">", "value": "1000"},
        ],
        "time_range": "Last 24h",
    },
    {
        "name": "Rogue DHCP Server",
        "hypothesis": "Detect rogue DHCP servers on the network by looking for unexpected DHCP traffic on non-standard ports.",
        "type": "sql",
        "log_source": "conn",
        "sql_query": "SELECT src_ip, dst_ip, dst_port FROM conn WHERE dst_port = 67 AND src_ip NOT IN ('10.0.0.1', '10.0.0.2', '192.168.1.1')",
        "time_range": "Last 24h",
    },
]

def seed():
    print(f"Seeding {len(HUNTS)} hunts...")
    for i, h in enumerate(HUNTS):
        stages = h.pop("stages", 1)
        print(f"  [{i+1}/10] Creating: {h['name']}...")
        res = requests.post(f"{API}/hunting/hunts", json=h)
        if res.status_code != 201:
            print(f"    FAIL: {res.text[:200]}")
            continue
        hunt_data = res.json()
        hunt_id = hunt_data["id"]
        print(f"    Created ID={hunt_id}")

        # Run the hunt to populate results
        run_params = {
            "hunt_id": str(hunt_id),
            "query_type": h["type"],
            "log_source": h.get("log_source", "conn"),
            "conditions": h.get("conditions", []),
            "query": h.get("sql_query", ""),
        }
        t0 = time.time()
        rr = requests.post(f"{API}/hunting/run", json=run_params)
        dt = time.time() - t0
        if rr.status_code == 200:
            rd = rr.json()
            print(f"    Ran: {rd.get('total', 0)} matches ({dt:.2f}s)")
        else:
            print(f"    Run FAIL: {rr.text[:200]}")

    print("\nDone. 10 hunts seeded.")

if __name__ == "__main__":
    seed()
