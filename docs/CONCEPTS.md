# DmarcWatch — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 12 September 2026*

---

## Every receiving mail server already tells you who sends as you

If a domain publishes a DMARC record with a `rua=` address, then every large mailbox provider that
receives mail claiming to be from that domain sends back a daily report: which addresses sent, how
many messages, and whether each one passed the two checks that prove the sender was authorised.

That is a remarkable thing to be given for free. It is the only dataset that answers "is anyone
impersonating us right now", and it arrives without asking, from Google, Microsoft, Yahoo and
dozens of others, every single day.

It arrives as zipped XML in a mailbox nobody opens.

## Which is why so many domains sit at p=none for years

A DMARC record carries a policy telling receivers what to do with mail that fails: `p=none` means
"deliver it anyway and tell me", `p=quarantine` means "put it in junk", `p=reject` means "refuse
it". Only the last two actually stop anybody impersonating the domain.

Almost everyone publishes `p=none` first, and correctly so — tightening the policy before you know
who your legitimate senders are will silently break the invoicing system, the CRM, the newsletter
tool and the payroll provider, all of which send as your domain and none of which anyone
remembers. The intention is always to read the reports for a few weeks and then tighten.

The reports are unreadable by hand, so the few weeks become three years. The domain stays
spoofable, and the reports that would have shown it keep piling up unread.

## What the reports are actually being read for

There are only four questions worth asking of them, and DmarcWatch is built around those four.

**Who sends as this domain.** Every source address seen in the last 30 days, with its volume and
whether SPF and DKIM aligned. This is the inventory nobody has and everybody needs before touching
the policy.

**Is anyone spoofing it.** A source is called out when it sent at least ten messages that failed
both aligned checks *and* at least 90% of that source's own traffic failed. Both conditions matter:
volume alone catches a misconfigured legitimate sender, and a failure rate alone catches a single
stray message. Together they describe something sending as you that cannot prove it is you.

**Did a new sender appear.** A source that was not there before shows up the week it starts, once
there is enough history to make "new" meaningful. This is how the marketing tool someone signed up
for on a personal credit card gets noticed — before it is either authorised or blocked by a policy
change nobody warned them about.

**Are you ready to tighten.** This is the question the whole exercise exists to answer, so the rule
is written out rather than hidden behind a score: at least 100 messages in the window, seen by at
least two independent reporting organisations, with an aligned rate of 98% or better. Below that,
the advice is to keep collecting; at or above it, the recommendation is to move to `p=quarantine`
and then `p=reject`. Two reporters, not one, because a single provider's view of your mail is not
evidence about everybody else's.

## The failure that looks exactly like success

There is a fifth thing worth watching, and it is the one no dashboard is built for: reports that
stop arriving.

A `rua=` address with a typo, a reporting mailbox that filled up, a mail rule that quietly files
the attachments away — each produces the same picture as a perfectly healthy domain. No reports, no
sources failing, no findings, nothing to worry about.

DmarcWatch raises a finding when nothing has been ingested for seven days, because an empty screen
should never be mistaken for good news. This is the same principle applied throughout the Hexward
line: a check that cannot see is not a check that passed.

## Findings that clear themselves, and carry the fix

Every finding is recomputed from the data on each run and disappears when the condition it
described stops being true. Nothing is ticked off by hand and nothing stays green because somebody
dismissed it.

Each one also carries a remediation — the sentence describing what to do — because "alignment
dropped ten points" is a measurement, and the person reading it at 9am needs an action.

## Where the data stays

Aggregate reports are metadata about your mail: who your senders are, which providers you use,
what your volumes look like. It is not the content of anyone's email, and it is still a description
of your organisation that you have no reason to hand to a third party.

DmarcWatch is one binary with a local SQLite file, no telemetry and no outbound connection. You
upload report files into it and nothing leaves.

## What it does not do yet, said plainly

Ingestion is upload-only. You download the attachments from the reporting mailbox and upload them —
up to 50 files at a time, duplicates detected, so re-uploading a whole folder is safe. IMAP polling
is on the roadmap and is not here yet; the honest current answer is that this step is manual.

There are no forensic (RUF) reports and no enrichment of source addresses. The thresholds described
above are fixed constants in this version rather than per-domain settings, which is a deliberate v0
choice: they are the numbers people argue about, and getting them adjustable before they have been
argued about would be guessing.

## What changes once you are using it

Before: a folder of zipped XML nobody opens, and a policy that has said `p=none` since the domain
was set up.

After: a list of everyone sending as your domain, a flag the week a new one appears, an explicit
answer to whether it is safe to tighten yet, and an alarm if the reports themselves stop.

## Try it on one domain

```
curl -LO https://github.com/nizartuanku/dmarcwatch/releases/latest/download/dmarcwatch-free-0.1.0-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/dmarcwatch/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf dmarcwatch-free-0.1.0-linux-amd64.tar.gz
./dmarcwatch
```

The dashboard is on `http://127.0.0.1:8429`. Add your domain, upload whatever report files you
already have sitting in the reporting mailbox — raw `.xml`, `.xml.gz` or `.zip`, exactly as the
providers send them — and read the findings.

If the domain has no `rua=` address yet, publish one first and wait a day:

```
_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

The free Apache-2.0 edition monitors one domain with 30 days of history and no time limit. Pro and
Team are paid licences on Whop —
[whop.com/nizar-tuanku/dmarcwatch](https://whop.com/nizar-tuanku/dmarcwatch?utm_source=github);
nothing on Whop is free, so try it here first.

Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/dmarcwatch

## Terms used above

- DMARC — a public DNS record saying how receivers should treat mail that claims to be from your domain but cannot prove it, and where to send reports.
- Aggregate (RUA) report — the daily XML summary a receiving provider sends back: sources, volumes and pass/fail counts. No message content.
- SPF — a DNS record listing the servers allowed to send for your domain.
- DKIM — a cryptographic signature on the message itself, verified against a key published in your DNS.
- Alignment — the check that the domain SPF or DKIM proved is the same domain the reader sees in the From line. Passing SPF for some other domain is not alignment.
- p=none / p=quarantine / p=reject — the three DMARC policies: report only, send to junk, refuse outright.
