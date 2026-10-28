# Changelog

## 0.1.3 — 2026-10-28

- **Send findings to your SIEM, in every edition.** Findings now leave DmarcWatch as [Hexward Finding Schema](https://github.com/nizartuanku/hexward-core/blob/main/SCHEMA.md) events (`hexward.finding/1`), the shape every Hexward tool shares. New outputs: an NDJSON file (`-export-file`) for a Wazuh agent, Splunk Universal Forwarder or Elastic Agent; Splunk HTTP Event Collector (`-hec-url`, `-hec-token-file`); syslog as HFS JSON or CEF (`-syslog-format json|cef`), RFC 5424 by default or 3164, over udp, tcp or tls with verified certificates; and webhook v2 (`-webhook-format v2`). Ready-made content: [hexward-wazuh](https://github.com/nizartuanku/hexward-wazuh) and [TA-hexward](https://github.com/nizartuanku/TA-hexward).
- **New `GET /api/findings/export`** returns the current findings as HFS `snapshot` events (NDJSON), so a SIEM can load existing state before it follows changes.
- **Evidence leaves redacted.** Secret-like evidence keys (password, token, secret, session, …) are dropped at every level before any export; `-export-evidence none` sends no evidence at all.
- **Fix: the webhook secret is now actually sent.** `-webhook-secret-file` sets the `X-Hexward-Token` header for webhook v1 and v2; before, the command line had no way to set it.
- Defaults are unchanged: `-syslog` still sends the original key=value lines (`-syslog-format kv`) and `-webhook` the original digest (`-webhook-format v1`), so Loglight and existing receivers keep working untouched.
- Docs: English is the supported AI Assist language in this release. Bahasa Indonesia
  (`-ai-assist-lang id`) is an unsupported preview; more languages will be added based on demand.

## 0.1.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding.** When DmarcWatch is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.

## 0.1.1 — 2026-09-23

- **Verification identifiers renamed to Hexward.** The HTTP header, DNS TXT label and well-known file used to prove domain ownership still carried the pre-rename brand. They are now `X-Hexward-Token`, `_hexward-verify.<domain>` and `/.well-known/hexward-verify.txt`. Nothing already installed breaks: a challenge is satisfied by either the old or the new identifier, and the webhook sends both headers, so a receiver written against the old name keeps working with no change at either end. The old names are removed on **1 March 2027**.
- **The product page is reachable from inside the product.** When a free-edition limit is reached, the message that reports it now also says where the paid editions are; the dashboard carries the same link in the Licence panel and the footer. It is a product URL, not a plan id, so it keeps working when plans change. No banner, no modal, no countdown.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). Step 1 uses the unauthenticated GitHub API, which allows 60 calls per hour per address; when that runs out the script now names the rate limit instead of reporting "cannot reach".
- **`docs/CONCEPTS.md`** — why domains sit at `p=none`, what has to be true before moving off it, and the rule for leaving it.
- Installation instructions in the README follow the order that was actually tested: verify the checksum, extract, then run.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here.
- Packaging: the `LICENSE` / `license` collision is fixed and the real licence text ships with the source; one copyright holder is named.
- CI runs `gofmt`, `go vet` and `go test` on every push.

## 0.1.0 — 2026-08-21

First public release. DmarcWatch reads DMARC aggregate (RUA) reports and turns them into findings: spoofing at volume, new senders, alignment drops, silent reporting gaps, and `p=reject` readiness. Free build: 1 domain, 30-day history. Dashboard on `http://127.0.0.1:8429`.
