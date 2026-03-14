# ndr-tools

Minimal operations folder for this PCAPQL repo.

## Kept

- `services/install_services.sh`
- `services/ndr-enrich.service`
- `services/ndr-api.service`
- `services/ndr-frontend.service`

## Install and start services

```bash
cd /opt/tools/pcapql/ndr-tools/services
sudo bash install_services.sh --start
```

## Manage services

```bash
systemctl status ndr-{enrich,api,frontend}
systemctl restart ndr-{enrich,api,frontend}
journalctl -u ndr-enrich -f
```
