# Metadata first: what gets inspected, and why

This page describes the order this tool inspects anything in, and the record it keeps
so a later reader can check that claim instead of trusting it.

The order is deliberate: **scope, then metadata, then allowlisted fields, then
redaction, then a bounded record, then a provenance trail.** Full payload is a separate
tier you ask for, never a default that arrives silently.

## 1. Identify the permitted scope before parsing

`minimize.inspection_scope()` writes down the basis on which bytes may be read at all:

- the listener is one this tool started on this host;
- the binding is loopback, or a non-loopback binding whose exposure was reviewed;
- the inspection window is bounded (4096 bytes, and never more than that);
- anything not covered is listed as **not permitted**, with a reason: services this tool
  did not start, other hosts, and, when the binding was never reviewed, traffic to that
  port at all.

That block is copied into every record, so an evidence file cannot be quietly re-scoped
after the fact.

## 2. Parse protocol metadata only

`parse_opening()` reads the first line and returns a family, a confidence and the basis
for that confidence:

| Family | Kept | Dropped |
| --- | --- | --- |
| `http` | method, path (secret-looking segments redacted), query **keys**, version | query values, header values, body |
| `ssh` | protocol revision, software banner | anything else on the line |
| `smtp` | greeting verb | domain and arguments |
| `line-protocol` | top-level command token | arguments |
| unknown | SHA-256 of the opening only | the bytes themselves |

Confidence matters: `high` means a parser matched a real grammar, `low` means the record
is a guess and says so.

## 3. Keep only allowlisted application fields

Each kept field carries the question it answers (`field_reasons` in the record). The
allowlist lives in `minimize.ALLOWLIST`; a field not in it is dropped even if a parser
produced it. Session accounting (bytes, frames, duration) is kept because it separates a
scanner from a script without exposing content.

## 4. Redact, and count the redactions

Redaction covers bearer and basic tokens, API-style keys, AWS key ids, JWTs, private key
blocks, `password=`/`token:` assignments, email addresses and long opaque blobs. Peer
addresses keep their /24 prefix and gain a stable 12-hex-character `peer_id` for
correlation, so sessions can be grouped without storing a full address per event.

The record contains **how many** redactions happened and which rule fired, never what was
redacted. A rule firing is itself useful evidence: a token in the query string tells you
the visitor was automating, not typing.

## 5. Bound the record

Field values are capped at 120 characters, fields at 24, redaction entries at 12, and the
inspection window at 4096 bytes. The bounds are written into the record's `bounds` block,
so "bounded" is checkable rather than aspirational.

## 6. Record what was inspected, and why

Every record carries `scope`, `protocol`, `fields`, `field_reasons`, `redactions`,
`not_inspected`, `bounds`, the opening digest, and `why_this_is_enough`. The last one is
the argument, in the file, for not keeping more.

## Then full payload, when it is actually needed

The full tier is a **separate record** with `tier: "full"`, its own byte ceiling
(64 KiB per session by default), a digest of the untruncated bytes, a `truncated` flag,
and a warning naming what it contains: credentials, tokens and third-party personal data.

```bash
# Minimised review of an existing capture: metadata and allowlisted fields only.
reverse-shell-decoy inspect --file captures/session.jsonl --port 22080

# The same, plus the full-payload tier as separate labelled records.
reverse-shell-decoy inspect --file captures/session.jsonl --full --limit 16384
```

Live decoys attach the minimised record to each session automatically. Full payload
remains what it always was: opt-in through `--full-payloads`, and now labelled
`"payload_tier": "full"` where it is stored.

## Why this is worth the extra step

- **Storage.** A minimised record is tens of bytes of fields instead of kilobytes of
  body. A long-running decoy stays reviewable.
- **Privacy.** Captured bodies are where other people's credentials and personal data
  live. Not collecting them means not having to protect, retain or disclose them.
- **Consequences of a compromised journal.** If a sealed journal is later broken or a key
  leaks, what leaks is "GET /admin/login, from 198.51.100.x, 94 bytes, query key `token`
  present" rather than the token itself.

## Limits, stated plainly

- Minimised records answer *what was attempted*, not *whether an exploit worked*. That
  needs the payload tier, and the payload tier has the costs above.
- Redaction is pattern-based. It will miss a secret in an unusual format, and it can
  over-redact an innocent long string. Treat it as a strong default, not a guarantee.
- The peer prefix plus a stable id is pseudonymisation, not anonymisation: someone with
  network logs can re-identify an address.
- Inspecting a file you were given does not make it yours to inspect. The scope block
  records your claim; it cannot make that claim true.
