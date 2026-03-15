window.PacketQLDemoData = {
  sources: [
    {
      id: "4sics-geeklounge-151020",
      name: "4SICS-GeekLounge-151020.pcap",
      uploadedAt: "2026-03-15 10:24 UTC",
      processedAt: "2026-03-15 10:28 UTC",
      size: "24.5 MB",
      totalEvents: 27612,
      ingestRate: "1184 EPS",
      topSourceIp: "10.10.10.30",
      topDomain: "time.nist.gov",
      tables: [
        ["dns", 15139],
        ["conn", 12444],
        ["notice", 29],
        ["http", 842],
        ["ssl", 634],
        ["dhcp", 0]
      ],
      dashboard: {
        queriedDomains: [
          ["time.nist.gov", 12331],
          ["localhost", 2485],
          ["ntp1.dlink.com", 246],
          ["clients4.google.com", 8],
          ["ssl.gstatic.com", 5]
        ],
        topSourceIps: [
          ["10.10.10.30", 7199],
          ["10.10.10.10", 2577],
          ["192.168.89.2", 2571],
          ["192.168.88.52", 84],
          ["192.168.88.61", 8]
        ],
        topDestinationIps: [
          ["10.10.10.10", 7201],
          ["10.10.10.30", 2577],
          ["8.8.8.8", 2567],
          ["192.168.88.1", 91],
          ["17.253.34.253", 4]
        ]
      },
      logs: [
        {
          time: "2026-03-15T10:24:53Z",
          source: "dns",
          src_ip: "10.10.10.30",
          dst_ip: "8.8.8.8",
          protocol: "udp",
          summary: "time.nist.gov",
          query: "time.nist.gov",
          uid: "C8demo001",
          answer: "132.163.96.1",
          rcode: "NOERROR"
        },
        {
          time: "2026-03-15T10:24:58Z",
          source: "conn",
          src_ip: "10.10.10.30",
          dst_ip: "10.10.10.10",
          protocol: "tcp",
          summary: "internal connection established",
          uid: "C8demo002",
          service: "ssl",
          dst_port: 443,
          conn_state: "SF"
        },
        {
          time: "2026-03-15T10:25:03Z",
          source: "dns",
          src_ip: "192.168.89.2",
          dst_ip: "8.8.8.8",
          protocol: "udp",
          summary: "clients4.google.com",
          query: "clients4.google.com",
          uid: "C8demo003",
          answer: "142.251.40.238",
          rcode: "NOERROR"
        },
        {
          time: "2026-03-15T10:25:13Z",
          source: "notice",
          src_ip: "10.10.10.30",
          dst_ip: "10.10.10.10",
          protocol: "tcp",
          summary: "SSL certificate validation notice",
          uid: "C8demo004",
          note: "SSL::Invalid_Server_Cert"
        },
        {
          time: "2026-03-15T10:25:33Z",
          source: "http",
          src_ip: "10.10.10.10",
          dst_ip: "17.253.34.253",
          protocol: "tcp",
          summary: "GET /generate_204",
          uid: "C8demo005",
          host: "clients4.google.com",
          method: "GET",
          status_code: 204
        }
      ],
      sqlSamples: {
        "Top DNS Domains": {
          sql: "SELECT query, COUNT(*) AS hits FROM dns GROUP BY query ORDER BY hits DESC LIMIT 5;",
          columns: ["query", "hits"],
          rows: [
            ["time.nist.gov", 12331],
            ["localhost", 2485],
            ["ntp1.dlink.com", 246],
            ["clients4.google.com", 8],
            ["ssl.gstatic.com", 5]
          ]
        },
        "Top Source IPs": {
          sql: "SELECT src_ip, COUNT(*) AS hits FROM conn GROUP BY src_ip ORDER BY hits DESC LIMIT 5;",
          columns: ["src_ip", "hits"],
          rows: [
            ["10.10.10.30", 7199],
            ["10.10.10.10", 2577],
            ["192.168.89.2", 2571],
            ["192.168.88.52", 84],
            ["192.168.88.61", 8]
          ]
        },
        "Interesting Connections": {
          sql: "SELECT src_ip, dst_ip, dst_port, conn_state FROM conn WHERE dst_port NOT IN (53,80,443) LIMIT 5;",
          columns: ["src_ip", "dst_ip", "dst_port", "conn_state"],
          rows: [
            ["192.168.88.1", "10.10.10.30", 123, "SF"],
            ["10.10.10.30", "192.168.88.1", 123, "SF"],
            ["192.168.89.2", "8.8.8.8", 53, "SF"],
            ["10.10.10.10", "17.253.34.253", 5223, "SF"],
            ["10.10.10.10", "10.10.10.30", 445, "REJ"]
          ]
        }
      },
      pipeline: {
        trackedSources: 2,
        parsedRows: 27612,
        droppedPackets: 0,
        errorSources: 0,
        processingStatus: [
          ["4SICS-GeekLounge-151020.pcap", "Ready", 27612, "2026-03-15 10:28 UTC", "Kafka-first ingest succeeded via native Zeek writer."]
        ],
        droppedEvents: [],
        errors: []
      }
    },
    {
      id: "dhcp-demo",
      name: "dhcp.pcap",
      uploadedAt: "2026-03-15 10:24 UTC",
      processedAt: "2026-03-15 10:24 UTC",
      size: "1.4 KB",
      totalEvents: 5,
      ingestRate: "27 EPS",
      topSourceIp: "192.168.0.10",
      topDomain: "none",
      tables: [
        ["dhcp", 2],
        ["conn", 2],
        ["notice", 1]
      ],
      dashboard: {
        queriedDomains: [["none", 0]],
        topSourceIps: [["192.168.0.10", 2], ["255.255.255.255", 1]],
        topDestinationIps: [["255.255.255.255", 2], ["192.168.0.1", 1]]
      },
      logs: [
        {
          time: "2026-03-15T10:24:10Z",
          source: "dhcp",
          src_ip: "0.0.0.0",
          dst_ip: "255.255.255.255",
          protocol: "udp",
          summary: "DHCP DISCOVER",
          uid: "DHCP001",
          mac: "00:0B:82:01:FC:42",
          host_name: "demo-laptop"
        },
        {
          time: "2026-03-15T10:24:13Z",
          source: "notice",
          src_ip: "192.168.0.10",
          dst_ip: "192.168.0.1",
          protocol: "udp",
          summary: "DHCP lease registered",
          uid: "DHCP002",
          lease_seconds: 3600
        }
      ],
      sqlSamples: {
        "DHCP Lease Activity": {
          sql: "SELECT mac, host_name FROM dhcp LIMIT 5;",
          columns: ["mac", "host_name"],
          rows: [["00:0B:82:01:FC:42", "demo-laptop"]]
        },
        "All Events": {
          sql: "SELECT log_type, COUNT(*) AS hits FROM all_logs GROUP BY log_type ORDER BY hits DESC;",
          columns: ["log_type", "hits"],
          rows: [["dhcp", 2], ["conn", 2], ["notice", 1]]
        }
      },
      pipeline: {
        trackedSources: 1,
        parsedRows: 5,
        droppedPackets: 0,
        errorSources: 0,
        processingStatus: [
          ["dhcp.pcap", "Ready", 5, "2026-03-15 10:24 UTC", "Small validation capture processed successfully."]
        ],
        droppedEvents: [],
        errors: []
      }
    }
  ]
};
