# DmarcWatch — User Guide

## The workflow

1. **Add your domain** in the Domains box (`example.com`). You can paste an
   email address — the domain is what gets watched.
2. **Upload report files** in the DMARC reports panel. These are the aggregate
   (RUA) files that arrive at the `rua=` mailbox in your DMARC record. Raw
   `.xml`, `.xml.gz`, and `.zip` are all accepted; duplicates are detected, so
   uploading an entire folder again is safe. Reports for domains you haven't
   added are skipped and named in the result line — nothing is silently
   dropped.
3. **Read the findings.** Each one states the problem, the evidence, and the
   fix. Findings auto-resolve when the underlying condition clears.

## Reading the domain table

| Column | Meaning |
|---|---|
| Policy | The `p=` value receivers currently see (`none` / `quarantine` / `reject`) |
| Msgs (30d) | Messages covered by reports in the last 30 days |
| Aligned | % of those messages passing DMARC (aligned SPF **or** DKIM) |
| Sources | Distinct sending IPs in the window |
| Last report | End date of the newest report — if this goes stale, collection broke |

**Sources** opens the per-source table. The `Fail both` column is the one to
watch: a source whose traffic fails both aligned SPF and DKIM is either a
spoofer or a badly broken legitimate sender — both need attention.

## The findings, and what to do about them

**Suspected spoofing (High).** A source sent 10+ messages failing both
mechanisms, and nearly all its traffic fails. First rule out a forwarder or a
legitimate system nobody documented (printers and ticketing systems are classic
culprits). If it's unknown, that's your domain being spoofed — the fix is not
to chase the IP but to tighten your policy so receivers refuse the mail.

**New sending source (Medium).** A source that passes alignment appeared in the
last 7 days. Usually it's a newly onboarded SaaS. Confirm someone owns it;
suppress the finding if it's expected.

**Alignment dropped (Medium).** This week is ≥10 points below the 30-day
average. Typical causes: a DKIM key rotation that went wrong, an SPF record
edit that dropped an include, or a new unaligned sender ramping up. The sources
table shows who's driving it.

**No reports received (Medium).** Silence isn't success. Check the `rua=`
address in your DMARC record, the mailbox it points at, and whether uploads
simply stopped.

**Policy progress (Low/Info).** The point of all this. At `p=none` DmarcWatch
tracks your aligned rate and tells you plainly when you're ready for
`p=quarantine` (≥98% aligned over 30 days, across at least 2 reporting orgs,
with real volume). At `p=quarantine` it tells you when `p=reject` is safe.
Move one step at a time; each step is a small DNS change:

```
p=none  →  p=quarantine  →  p=reject
```

## Notifications

- `-webhook <url>` — JSON POST per new finding, any tier.
- `-syslog <host:port>` — one syslog frame per finding. Point it at Loglight
  (`-syslog loglight-host:5514`) and a DmarcWatch spoofing finding lands in the
  same correlation timeline as your auth logs and honeypot trips.

## Suppress vs acknowledge

- **Acknowledge** — "seen it, working on it". Stays visible.
- **Suppress** — "expected, don't show me again" (e.g. a known forwarder that
  always fails alignment). Suppressed findings never notify.
