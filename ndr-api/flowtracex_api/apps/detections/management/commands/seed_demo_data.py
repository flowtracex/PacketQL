from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.detections.models import Alert, AlertSignal
from apps.assets.models import Asset
from apps.investigations.models import Investigation
from apps.hunting.models import Hunt
from apps.rules.models import Rule
from apps.logs.models import LogEntry
import random
from django.utils import timezone
from datetime import timedelta

User = get_user_model()

class Command(BaseCommand):
    help = 'Seed demo data for the RaceflowX platform'

    def handle(self, *args, **options):
        self.stdout.write('Seeding demo data...')

        # Create demo user
        user, created = User.objects.get_or_create(
            username='analyst',
            defaults={'email': 'analyst@raceflowx.local', 'role': 'analyst'}
        )
        if created:
            user.set_password('demo1234')
            user.save()
            self.stdout.write(self.style.SUCCESS('  Created demo user: analyst / demo1234'))
        else:
            self.stdout.write('  Demo user already exists')

        # Seed Alerts
        severities = ['critical', 'high', 'medium', 'low']
        statuses = ['open', 'investigating', 'resolved']
        tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                    'Collection', 'Command and Control', 'Exfiltration', 'Impact']
        mitre_ids = ['T1190', 'T1059', 'T1547', 'T1068', 'T1070', 'T1110', 'T1046', 'T1021',
                     'T1005', 'T1071', 'T1048', 'T1486']
        alert_names = [
            'Suspicious DNS Tunneling Activity',
            'Potential C2 Beacon Detected',
            'Brute Force Authentication Attempt',
            'Unusual Outbound Data Transfer (5.2GB)',
            'Lateral Movement via SMB',
            'Privilege Escalation Attempt',
            'Malware Callback to Known C2 IP',
            'Port Scan from Internal Host',
            'Unauthorized RDP Connection',
            'Suspicious PowerShell Execution',
            'Data Exfiltration via DNS',
            'Abnormal SSL Certificate Detected',
            'Kerberoasting Attack Detected',
            'Pass-the-Hash Attempt',
            'Web Shell Upload Detected',
        ]

        if Alert.objects.count() == 0:
            for i in range(15):
                sev = severities[i % len(severities)]
                tactic_idx = i % len(tactics)
                alert = Alert.objects.create(
                    name=alert_names[i],
                    description=f'Automated detection of {alert_names[i].lower()}. '
                                f'Source analysis indicates potential threat activity.',
                    severity=sev,
                    status=statuses[i % len(statuses)],
                    confidence=random.randint(60, 99),
                    mitre_id=mitre_ids[tactic_idx],
                    mitre_tactic=tactics[tactic_idx],
                    source_ip=f'10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}',
                    destination_ip=f'{random.choice(["192.168", "172.16", "10.0"])}.{random.randint(1,254)}.{random.randint(1,254)}',
                    timestamp=timezone.now() - timedelta(hours=random.randint(0, 72)),
                    blast_radius={
                        'affectedAssets': random.randint(1, 15),
                        'segments': ['DMZ', 'Internal', 'Production'][:random.randint(1, 3)],
                        'externalIps': random.randint(0, 5)
                    },
                    asset_context={
                        'subnet': f'10.{random.randint(0,255)}.0.0/16',
                        'firstSeen': (timezone.now() - timedelta(days=random.randint(30, 365))).isoformat(),
                        'previousAlerts': random.randint(0, 12),
                        'riskScore': random.randint(20, 95),
                    },
                    risk_context={}
                )
                # Add signals per alert
                for j in range(random.randint(1, 3)):
                    AlertSignal.objects.create(
                        alert=alert,
                        name=f'Signal {j+1}: {random.choice(["Anomalous traffic pattern", "Known IOC match", "Behavioral deviation", "Threshold breach"])}',
                        explanation=f'Detection logic triggered based on network flow analysis.',
                        detection_logic={'monitored': 'network_flows', 'suspiciousWhen': 'threshold_exceeded'},
                        evidence=[{'type': 'flow', 'timestamp': timezone.now().isoformat()}]
                    )
            self.stdout.write(self.style.SUCCESS(f'  Created {Alert.objects.count()} alerts'))
        else:
            self.stdout.write(f'  Alerts already exist ({Alert.objects.count()}), skipping')

        # Seed Assets
        if Asset.objects.count() == 0:
            asset_types = ['server', 'workstation', 'network_device', 'iot']
            for i in range(20):
                Asset.objects.create(
                    hostname=f'{random.choice(["srv", "ws", "fw", "sw"])}-{random.randint(100,999)}',
                    ip=f'10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}',
                    type=random.choice(asset_types),
                    os=random.choice(['Ubuntu 22.04', 'Windows Server 2022', 'CentOS 8', 'Cisco IOS']),
                    risk_score=random.randint(10, 95),
                    is_threat=random.random() > 0.7,
                )
            self.stdout.write(self.style.SUCCESS(f'  Created {Asset.objects.count()} assets'))
        else:
            self.stdout.write(f'  Assets already exist ({Asset.objects.count()}), skipping')

        # Seed Rules
        if Rule.objects.count() == 0:
            rule_types = ['custom_query', 'threshold', 'ml']
            for i in range(8):
                Rule.objects.create(
                    name=f'Rule {i+1}: {random.choice(["DNS Tunnel Detection", "C2 Beacon", "Brute Force", "Data Exfil", "Lateral Movement", "Port Scan", "Privilege Esc", "Malware Callback"])}',
                    description=f'Automated detection rule for network security monitoring.',
                    type=random.choice(['threshold', 'query']),
                    severity=random.choice(severities),
                    enabled=True,
                    mitre_tactic=random.choice(tactics),
                    query=f'SELECT * FROM flows WHERE bytes_out > 1000000',
                )
            self.stdout.write(self.style.SUCCESS(f'  Created {Rule.objects.count()} rules'))
        else:
            self.stdout.write(f'  Rules already exist ({Rule.objects.count()}), skipping')

        # Seed Investigations
        if Investigation.objects.count() == 0:
            inv_statuses = ['new', 'active', 'escalated', 'on-hold', 'closed']
            for i in range(5):
                Investigation.objects.create(
                    name=f'Investigation: {random.choice(["C2 Activity", "Data Breach", "Lateral Movement", "Insider Threat", "Ransomware"])}',
                    description='Security investigation opened based on correlated alert activity.',
                    status=random.choice(inv_statuses),
                    severity=random.choice(severities),
                    owner=user,
                )
            self.stdout.write(self.style.SUCCESS(f'  Created {Investigation.objects.count()} investigations'))
        else:
            self.stdout.write(f'  Investigations already exist ({Investigation.objects.count()}), skipping')

        # Seed Hunts
        if Hunt.objects.count() == 0:
            for i in range(5):
                Hunt.objects.create(
                    name=f'Hunt: {random.choice(["DNS Exfil Scan", "C2 Beacon Sweep", "Lateral Movement Trace", "Privilege Escalation Probe", "Data Staging Detection"])}',
                    description='Proactive threat hunting query for SOC analysts.',
                    type=random.choice(['visual', 'sql']),
                    query='SELECT src_ip, dst_ip, bytes FROM flows WHERE bytes > 10000000',
                )
            self.stdout.write(self.style.SUCCESS(f'  Created {Hunt.objects.count()} hunts'))
        else:
            self.stdout.write(f'  Hunts already exist ({Hunt.objects.count()}), skipping')

        self.stdout.write(self.style.SUCCESS('Demo data seeding complete!'))
