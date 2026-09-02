# DmarcWatch

**Self-hosted DMARC monitoring — see who sends mail as your domain, catch spoofing, and get to p=reject without breaking real mail.**

Every mailbox provider that receives mail for your domain will happily tell you
who has been sending as you — that's what DMARC aggregate (RUA) reports are.
Almost nobody reads them, because they arrive as zipped XML in a mailbox no one
opens. So domains sit at `p=none` for years, spoofed mail keeps landing, and
the one dataset that answers "is anyone impersonating us?" rots unread.

DmarcWatch reads them. Upload the report files (raw `.xml`, `.xml.gz`, or
`.zip` — exactly as generators like Google and Microsoft send them) and it
answers the four questions DMARC monitoring exists for:

1. **Who sends mail as this domain** — every source IP, with volume and
   SPF/DKIM alignment, over the last 30 days.
2. **Is anyone spoofing it** — sources failing both aligned SPF and DKIM at
   volume become a High finding, not a row in an unread XML file.
3. **Did a new sender appear** — a new source (the marketing SaaS someone
   signed up for on a credit card) is flagged the week it starts.
4. **Are you ready to tighten the policy** — when alignment holds ≥98% across
   multiple reporters, DmarcWatch tells you it's safe to move from `p=none`
   to `p=quarantine`, and from there to `p=reject`.

It also notices the failure mode nobody watches for: **reports that stop
arriving** (a broken `rua=` address or a dead mailbox looks exactly like "all
clear" until you check).

Self-hosted, single binary, SQLite storage, no telemetry. Your mail metadata
never leaves your machine.

## Quick start

Download the latest release, then:

```
tar -xzf dmarcwatch-free-*.tar.gz
./dmarcwatch
```

Dashboard: http://127.0.0.1:8429 — add your domain, upload report files, read
the findings.

Or build from source (Go 1.24+; CGO is required by the SQLite driver):

```
go build ./cmd/dmarcwatch
```

Or Docker:

```
docker build -t dmarcwatch .
docker run -d -p 127.0.0.1:8429:8429 -v dmarcwatch-data:/data dmarcwatch
```

## Getting the report files

Publish a DMARC record with a `rua=` address you control, e.g.:

```
_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

Reports arrive at that mailbox daily as attachments. Download them (or export
the mailbox) and upload the files in the dashboard — up to 50 per upload, and
duplicates are detected, so re-uploading a whole folder is safe. IMAP polling
is on the roadmap; the honest current answer is that ingestion is manual.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| `dmarc.spoofing` | High | A source sent ≥10 messages failing both aligned SPF and DKIM |
| `dmarc.new-source` | Medium | A new sending source appeared in the last 7 days |
| `dmarc.alignment-drop` | Medium | This week's aligned rate is ≥10 points below the 30-day average |
| `dmarc.no-reports` | Medium | No reports received for 7+ days — collection is broken |
| `dmarc.policy` | Low/Info | `p=none` in force, with a concrete answer to "am I ready to tighten?" |
| `dmarc.no-data` | Info | Domain added but no reports ingested yet |

Findings auto-resolve when the condition clears, and every finding carries a
remediation — what to do, not just what's wrong.

## Notifications

`-webhook <url>` pushes new findings to any webhook. `-syslog <host:port>`
emits one syslog frame per finding — point it at
[Loglight](https://github.com/nizartuanku/loglight) to correlate DMARC findings
with the rest of your logs.

## Editions

| | Free (this build) | Pro | Team |
|---|---|---|---|
| Domains | 1 | 10 | Unlimited |
| History | 30 days | 365 days | Unlimited |
| Channels | webhook, syslog | + email, Slack, Telegram | + PagerDuty, Teams |
| On-demand rescan | — | ✓ | ✓ |

This open-source build is the permanent free edition — it has **no license
activation**. Pro and Team builds are delivered separately:
https://whop.com/nizar-tuanku/dmarcwatch?utm_source=github

## Honest limits

- Ingestion is upload-only in v0 — no IMAP polling yet, no forensic (RUF)
  reports, no PTR/enrichment of source IPs.
- Thresholds (spoofing volume, readiness at 98%) are fixed in v0.
- Analysis windows are 7/30 days; retention beyond the tier's horizon is
  pruned.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
