# DmarcWatch — Install

Single Linux binary, SQLite storage, no external services.

## 1. Run it

```
tar -xzf dmarcwatch-0.1.0-linux-amd64.tar.gz
cd dmarcwatch-0.1.0
./dmarcwatch
```

Open http://127.0.0.1:8429. That's the whole install.

Useful flags:

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | `127.0.0.1:8429` | Dashboard address (keep it on localhost or behind your reverse proxy) |
| `-db` | `dmarcwatch.db` | SQLite database path |
| `-license` | `dmarcwatch-license.key` | License key file (licensed builds) |
| `-webhook` | — | Webhook URL for new findings |
| `-syslog` | — | Syslog `host:port` for findings (point at Loglight to correlate) |
| `-syslog-network` | `udp` | Syslog transport: `udp` or `tcp` |

## 2. Run it as a service (systemd)

```
sudo useradd -r -s /usr/sbin/nologin dmarcwatch
sudo mkdir -p /var/lib/dmarcwatch && sudo chown dmarcwatch: /var/lib/dmarcwatch
sudo install -m 0755 dmarcwatch /usr/local/bin/dmarcwatch

sudo tee /etc/systemd/system/dmarcwatch.service >/dev/null <<'EOF'
[Unit]
Description=DmarcWatch — self-hosted DMARC monitoring
After=network-online.target

[Service]
User=dmarcwatch
WorkingDirectory=/var/lib/dmarcwatch
ExecStart=/usr/local/bin/dmarcwatch -db /var/lib/dmarcwatch/dmarcwatch.db -license /var/lib/dmarcwatch/dmarcwatch-license.key
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now dmarcwatch
```

## 3. Activate a license (Pro/Team builds)

Paste your key (`SNTL1-…`) into the License box at the bottom of the dashboard.
Activation is instant and validates offline — no phone-home. The free build
from GitHub has no activation; use the delivered licensed binary with your key.

## 4. Point DMARC reports at yourself

Publish (or extend) your DMARC record so reports flow to a mailbox you control:

```
_dmarc.yourdomain.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com"
```

Generators send one report per day per receiver. Save the attachments and
upload them in the dashboard — `.xml`, `.xml.gz`, and `.zip` all work, up to 50
files per upload, duplicates skipped automatically.

## Verify your download

```
sha256sum -c SHA256SUMS
```
