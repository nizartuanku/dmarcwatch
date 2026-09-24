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

**Whop sells paid licences only.** Free: github.com/nizartuanku/dmarcwatch — this repository is the free edition, Apache-2.0, no time limit; nothing on Whop is free, so try it here first.

## AI Assist (optional)

DmarcWatch can explain a finding in plain language with a small language model that runs on
your own hardware. It is off by default. Turn it on by starting a
[hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar and pointing DmarcWatch at it:

```sh
dmarcwatch -ai-assist-url http://127.0.0.1:8435
```

Each finding then gets an **✨ Explain** button. The model writes what the finding means and
what to verify before you act. It also gets a fixed disclaimer.

- **The engine still decides.** The model receives one finding after DmarcWatch has produced it.
  It cannot add, remove, re-score or close a finding. If the sidecar is off, slow or broken,
  the button shows a short note and nothing else changes.
- **What leaves the process.** One finding: its check, title, target, severity, status,
  remediation and a sanitised copy of its evidence. Keys that look like secrets (password,
  token, secret, private, credential, cookie, session, signature and similar) are dropped
  first. Nothing goes to the internet. The sidecar runs where you run it.
- **Editions.** The free edition works with a sidecar on the same host. That is the `lab`
  profile, SmolLM3-3B. Pro and Team can also use one dedicated AI host for several products,
  or your own OpenAI-compatible endpoint, through `-ai-assist-key-file`. The recommended
  profile there is `smb` (Phi-4-mini-instruct). Enterprise uses Qwen3 or your own endpoint.
- **Language.** `-ai-assist-lang id` writes in Bahasa Indonesia. On the free SmolLM3 profile
  Indonesian is experimental. English is recommended there.
- **Honest limit.** Small local models sometimes add general background that is not in the
  evidence. For example, they may name a well-known attack, and that background can be wrong.
  Treat the explanation as a starting point. The finding, its evidence and its fix text remain
  the record, which is why every explanation carries the "verify against raw findings" line.
- **Speed.** On a CPU-only machine an explanation takes about 15–50 seconds, depending on the
  model. Measurements are in hexward-ai's `docs/TIERS.md`.

Environment equivalents: `DMARCWATCH_AI_ASSIST_URL`, `DMARCWATCH_AI_ASSIST_KEY_FILE`,
`DMARCWATCH_AI_ASSIST_LANG`, `DMARCWATCH_AI_ASSIST_NO_THINKING=1`.

## Honest limits

- Ingestion is upload-only in v0 — no IMAP polling yet, no forensic (RUF)
  reports, no PTR/enrichment of source IPs.
- Thresholds (spoofing volume, readiness at 98%) are fixed in v0.
- Analysis windows are 7/30 days; retention beyond the tier's horizon is
  pruned.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
