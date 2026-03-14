
import duckdb
import os
import random
import time
import datetime
import uuid
import pandas as pd
from pathlib import Path

# Configuration
PARQUET_DATA_DIR = os.environ.get('PARQUET_DATA_DIR', '/opt/node_frontend/data/parquet')
EVENTS_PER_DAY = 10000
DAYS_BACK = 1

# Scenarios
C2_IP = "45.33.22.11"
EXFIL_IP = "192.168.1.50"
TUNNEL_DOMAIN_SUFFIX = ".tunnel.evil.com"

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def random_ip():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def random_ext_ip():
    return f"{random.randint(1, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_conn_data(date):
    data = []
    # Fix: Convert date to datetime at midnight
    dt = datetime.datetime.combine(date, datetime.time.min)
    base_ts = dt.timestamp()
    
    for i in range(EVENTS_PER_DAY):
        ts = base_ts + random.randint(0, 86400)
        uid = str(uuid.uuid4())[:18]
        src_ip = random_ip()
        
        # Scenario: Data Exfiltration
        if i % 500 == 0:
            dst_ip = EXFIL_IP
            dst_port = random.choice([22, 443, 8080])
            proto = "tcp"
            service = "ssl"
            orig_bytes = random.randint(10_000_000, 500_000_000) # 10MB - 500MB
            conn_state = "S1"
        # Scenario: C2 Beaconing (periodic)
        elif i % 50 == 0:
            dst_ip = C2_IP
            dst_port = 443
            proto = "tcp"
            service = "ssl"
            orig_bytes = random.randint(100, 500)
            conn_state = "S1"
        else:
            dst_ip = random_ext_ip()
            dst_port = random.choice([80, 443, 53, 22, 8080])
            proto = "tcp" if dst_port in [80, 443, 22] else "udp"
            service = {80: "http", 443: "ssl", 53: "dns", 22: "ssh"}.get(dst_port, "other")
            orig_bytes = random.randint(0, 5000)
            conn_state = random.choice(["S0", "S1", "SF", "REJ"])

        data.append({
            'ts': datetime.datetime.fromtimestamp(ts),
            'uid': uid,
            'src_ip': src_ip,
            'src_port': random.randint(1024, 65535),
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': proto,
            'service': service,
            'duration': round(random.random() * 10, 3),
            'orig_bytes': orig_bytes,
            'resp_bytes': random.randint(0, 5000),
            'conn_state': conn_state,
            'missed_bytes': 0,
            'history': "Dd",
            'orig_pkts': random.randint(1, 100),
            'orig_ip_bytes': random.randint(40, 15000),
            'resp_pkts': random.randint(1, 100),
            'resp_ip_bytes': random.randint(40, 15000),
            'tunnel_parents': None,
            'ingest_time': datetime.datetime.now()
        })
    return data

def generate_dns_data(date):
    data = []
    dt = datetime.datetime.combine(date, datetime.time.min)
    base_ts = dt.timestamp()
    
    for i in range(int(EVENTS_PER_DAY / 2)):
        ts = base_ts + random.randint(0, 86400)
        uid = str(uuid.uuid4())[:18]
        src_ip = random_ip()
        
        # Scenario: DNS Tunneling
        if i % 100 == 0:
            query_len = random.randint(50, 200)
            query = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=query_len)) + TUNNEL_DOMAIN_SUFFIX
            qtype = 1 # A
            qtype_name = "A"
        else:
            query = random.choice(["google.com", "facebook.com", "api.traceflowx.local", "update.windows.com"])
            qtype = random.choice([1, 28, 15]) # A, AAAA, MX
            qtype_name = {1: "A", 28: "AAAA", 15: "MX"}.get(qtype, "A")
            
        data.append({
            'ts': datetime.datetime.fromtimestamp(ts),
            'uid': uid,
            'src_ip': src_ip,
            'src_port': random.randint(1024, 65535),
            'dst_ip': "8.8.8.8",
            'dst_port': 53,
            'protocol': "udp",
            'trans_id': random.randint(0, 65535),
            'rtt': round(random.random(), 3),
            'query': query,
            'qclass': 1,
            'qclass_name': "C_INTERNET",
            'qtype': qtype,
            'qtype_name': qtype_name,
            'rcode': 0,
            'rcode_name': "NOERROR",
            'AA': False,
            'TC': False,
            'RD': True,
            'RA': True,
            'Z': 0,
            'answers': "1.1.1.1",
            'TTLs': "300",
            'rejected': False,
            'ingest_time': datetime.datetime.now()
        })
    return data

def generate_http_data(date):
    data = []
    dt = datetime.datetime.combine(date, datetime.time.min)
    base_ts = dt.timestamp()
    
    for i in range(int(EVENTS_PER_DAY / 2)):
        ts = base_ts + random.randint(0, 86400)
        uid = str(uuid.uuid4())[:18]
        src_ip = random_ip()
        
        data.append({
            'ts': datetime.datetime.fromtimestamp(ts),
            'uid': uid,
            'src_ip': src_ip,
            'src_port': random.randint(1024, 65535),
            'dst_ip': random_ext_ip(),
            'dst_port': 80,
            'trans_depth': 1,
            'method': random.choice(["GET", "POST"]),
            'host': random.choice(["example.com", "test.com"]),
            'uri': "/",
            'referrer': "-",
            'user_agent': "Mozilla/5.0",
            'request_body_len': 0,
            'response_body_len': random.randint(0, 10000),
            'status_code': 200,
            'status_msg': "OK",
            'info_code': None,
            'info_msg': None,
            'tags': [],
            'username': "-",
            'password': "-",
            'proxied': None,
            'ingest_time': datetime.datetime.now()
        })
    return data

def main():
    print(f"Generating Parquet data in {PARQUET_DATA_DIR}...")
    con = duckdb.connect()
    
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=DAYS_BACK)
    
    for i in range(DAYS_BACK + 1):
        current_date = start_date + datetime.timedelta(days=i)
        year = current_date.year
        month = current_date.month
        day = current_date.day
        
        print(f"Processing {current_date}...")
        
        # 1. Conn
        conn_data = generate_conn_data(current_date)
        conn_path = os.path.join(PARQUET_DATA_DIR, f"conn/year={year}/month={month}/day={day}/hour=00")
        ensure_dir(conn_path)
        # Fix: Convert to Pandas DF
        df_conn = pd.DataFrame(conn_data)
        con.register('conn_mem', df_conn)
        con.execute(f"COPY conn_mem TO '{conn_path}/data.parquet' (FORMAT PARQUET)")
        print(f"  Generated {len(conn_data)} conn events")

        # 2. DNS
        dns_data = generate_dns_data(current_date)
        dns_path = os.path.join(PARQUET_DATA_DIR, f"dns/year={year}/month={month}/day={day}/hour=00")
        ensure_dir(dns_path)
        # Fix: Convert to Pandas DF
        df_dns = pd.DataFrame(dns_data)
        con.register('dns_mem', df_dns)
        con.execute(f"COPY dns_mem TO '{dns_path}/data.parquet' (FORMAT PARQUET)")
        print(f"  Generated {len(dns_data)} dns events")
        
        # 3. HTTP
        http_data = generate_http_data(current_date)
        http_path = os.path.join(PARQUET_DATA_DIR, f"http/year={year}/month={month}/day={day}/hour=00")
        ensure_dir(http_path)
        # Fix: Convert to Pandas DF
        df_http = pd.DataFrame(http_data)
        con.register('http_mem', df_http)
        con.execute(f"COPY http_mem TO '{http_path}/data.parquet' (FORMAT PARQUET)")
        print(f"  Generated {len(http_data)} http events")

    print("Data generation complete.")

if __name__ == "__main__":
    main()
