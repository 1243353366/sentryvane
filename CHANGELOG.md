# CloudSentry changelog

The core Python package and browser portal have separate versions. A public source push, saved portal checkpoint, completed CI run and live publication are different events. Historical results below describe their named source scope, not production containment or every later commit.

## Core 0.1.6 — 2026-11-01

The containment properties, turned from a description into a check. 617 to 639 tests.

1. **`guarantees`.** Seven properties, each with the mechanism that enforces it, the
   observation that demonstrates it and the limit that remains: connection, no host-resource
   access, no unrestricted relay, no command execution, synthetic responses, throttle and
   termination, evidence. `verified` requires a mechanism *and* an observation.
2. **A live probe that misbehaves on purpose.** Loopback only, ephemeral ports: connect, then
   send `cat /etc/passwd` with a canary path, `id`, `$(...)`, backticks and a `CONNECT`
   request, then flood the listener to force throttle denials. It reports what came back and
   reads the records it produced.
3. **A static capability scan.** AST walk over the reachable listener modules counting
   `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `pty.spawn`, `eval`, `exec`, `compile`
   and `__import__`. Non-literal `open()` arguments are listed separately, because that is the
   shape a peer-input-becomes-a-path bug takes. Network calls are counted apart from execution:
   the relay opens exactly one, to its loopback backend.
4. **Failing loudly.** A leaked canary, shell output in a response or a relay that accepts a
   remote target marks the property `failed` and the process exits non-zero. Without a probe,
   properties are `unverified`, never `verified`.
5. **The limit, once.** None of the seven survives a host that is already fully compromised;
   the report says so rather than letting a green table imply containment.

## Core 0.1.5 — 2026-11-01

Two releases of restraint: evidence that is encrypted, and evidence that is barely there.
551 to 617 tests.

**Encrypted evidence on your own machine.**

1. **Sealed evidence (`vault`).** ChaCha20-Poly1305 per file, with the header as associated
   data: version, timestamps, stream, index, plaintext length and SHA-256, source label and a
   non-secret key fingerprint. `seal`, `open`, `verify`, `status`, `manifest`,
   `verify-manifest`. Tampering, truncation, a different key and a substituted file each fail
   with their own message.
2. **Key handling that fails closed.** A group- or world-readable key is refused, a symlinked
   key is refused, a missing encryption backend is an error, and the tool never writes the key.
3. **Honest gaps in the output.** `vault status` names every plaintext file it can still see;
   every seal result records that the plaintext original survived.
4. **TLS on the decoys you own.** `synthetic` and `relay` accept `--tls-cert`/`--tls-key`.
   Sessions record `"transport": "tls"` and the certificate fingerprint. A plaintext client now
   receives no banner at all; half a configuration or a mismatched pair is refused.
5. **The limit, where it matters.** Encryption at rest does not stop an attacker already
   running code as you. `docs/encrypted-evidence.md` says that first.

**Metadata-first inspection (`inspect`).**

6. **Scope before parsing.** `inspection_scope()` records the basis for reading bytes at all:
   a listener this tool started on this host, loopback or reviewed public, inside a bounded
   window. Everything else is listed as not permitted, with a reason, inside every record.
7. **Protocol metadata only.** HTTP method/path/query keys/version, SSH protocol and software,
   SMTP verb, top-level line-protocol command. Bodies, header values and query values are
   never parsed into the record; an unrecognised opening is stored as a digest.
8. **Allowlist with reasons.** Each kept field carries the question it answers; anything not on
   `minimize.ALLOWLIST` is dropped. Bounds are 120-char values, 24 fields, 12 redaction entries,
   4096-byte window, all reported in the record.
9. **Redaction that is counted, not stored.** Bearer/basic tokens, API-style keys, AWS key ids,
   JWTs, private-key blocks, password assignments, emails and long opaque blobs. Peers keep a
   /24 prefix plus a stable id; the record says which rules fired and how often.
10. **Full payload as a separate tier.** `--full-payloads` production is labelled
    `"payload_tier": "full"`; `inspect --full` emits separate `tier: "full"` records with a byte
    ceiling, a `truncated` flag, the digest of the untruncated bytes and a warning naming what
    it contains.

## Core 0.1.4 — 2026-11-01

Observer-integrity release. Adds four capabilities and one honest limit: what the host says
about its own policy, what actually answers on loopback, what returns after it disappears, and
what a deliberately obvious decoy sees. 438 to 549 tests.

1. **Policy divergence (`policy`).** Reads `nft -j list ruleset`, falling back to
   `iptables-save`/`ip6tables-save`, or on Windows `netsh advfirewall` and
   `Get-NetFirewallProfile`, plus network-namespace coverage, and compares it with
   CloudSentry's stated intent. Findings are `DEFAULT_INBOUND_ACCEPT`,
   `DECOY_PORT_REACHABLE`, `UNEXPECTED_INBOUND_ALLOW` (divergence) and `FILTER_UNREADABLE`,
   `PARTIAL_VISIBILITY`, `NAMESPACE_SPLIT` (observation gaps). Verdicts are `MATCH`,
   `DIVERGENT`, `PARTIAL`, `UNKNOWN`. No rule is changed; `all_clear` is always `false`.
2. **Stated trust limit.** A sufficiently privileged attacker can modify both the packet filter
   and the tools that read it, so a host-based observer cannot guarantee trustworthy visibility
   after complete host compromise. Every policy report carries that limitation and a rotation
   recommendation rather than a clean bill of health.
3. **Loopback scan (`scan-loopback`).** Bounded connect scan that refuses non-loopback targets
   by construction, reports `COMPLETE`/`PARTIAL` with `unscanned_ports` counted, and
   cross-checks the procfs inventory: `answering_not_bound`, `bound_but_not_answering`,
   `bound_but_not_scanned`. No service probing, no OS fingerprinting, no raw sockets.
4. **Listener watchdog (`watchdog`).** Bounded snapshots diffed into `BINDING_APPEARED`,
   `BINDING_DISAPPEARED`, `BINDING_CHANGED` and `BINDING_REAPPEARED`, with recurrence linked to
   the first sighting and a replacement on the same binding reported as a change rather than as
   continuity. It never acts: `action: none`, `requires_authorization: true`,
   `terminates_processes: false` on every event and report.
5. **Synthetic decoy fleet (`synthetic`).** Three obviously fake services whose banners state
   that nothing is executed, authenticated or stored. Records interaction shape
   (credential/command/exploit/fingerprint labels, arrival timing, first-line hash), never
   intent or skill, and tags every record `synthetic: true` / `not_host_activity: true` so
   `exclude_synthetic()` keeps the decoy's own invitations out of real-activity counts.
6. **Loopback relay (`relay`).** A rotating front that forwards the same received connection to
   a loopback decoy, bounces the backend banner back, fingerprints the visitor's opening bytes
   passively, and refuses non-loopback targets unless explicitly allowed. Rotation is recorded
   with both presentations named. `no_third_party_transit` is asserted on every record. The
   README's earlier blanket "never proxies" sentence was corrected to describe this precisely.

Deliberately not built: any relay to a remote host, any inbound-traffic reassembly across
sessions, and any automatic response to a returning listener.

## Core 0.1.3 / portal 1.0.1 — 2026-11-01

Listener-assurance and inbound-pacing release. It closes the payload/banner capture and
listener-throttle gaps reported against 0.1.2, and adds the first six observation-completeness
items from the Increment 3 review. Behavioural classification, lineage detection and a
collection watchdog are deliberately deferred (see `docs/observation-completeness.md`).

### Walkthrough: what changes for the operator

1. **Full payload capture, opt-in and bounded.** `--capture-payloads` records the complete inbound
   record (`payload_b64`, `payload_complete`, `payload_omitted_bytes`) plus a per-session
   `capture_sha256`/`capture_byte_count` on the close record. Previously only hashes were kept, so an
   operator could prove a payload existed but never read it back. Capture is off by default, inbound-only,
   same-connection, and bounded by total, per-session and per-record budgets.
2. **Full banners in both directions.** The `connecting` record now carries the complete banner the decoy
   presented (`banner_text`, `banner_sha256`, `banner_byte_count`, `banner_delivered`) and the peer's opening
   bytes (`peer_greeting_b64`, `peer_greeting_sha256`, `peer_greeting_byte_count`,
   `peer_greeting_truncated`, escaped `peer_greeting_utf8`). Greeting bytes are replayed into the session
   through a shim, so a command split across the greeting boundary is never misparsed, and they are excluded
   from the session stream digest so they are not hashed twice.
3. **Every listener is throttled by default.** One shared `InboundThrottle` token bucket paces accepts and
   admitted commands/chunks, globally and per source (IPv6 grouped by `/64`). A throttled peer is closed
   without a response byte and without consuming the lifetime connection allowance. `backup-echo` shares a
   single throttle across both slots. `--no-throttle` opts out.
4. **Socket ownership race detection.** `listeners --assure` takes two independent procfs snapshots and
   reports a binding that disappeared before the recheck, or whose owner set changed, as `UNKNOWN` instead of
   attributing it to whichever process was seen first.
5. **One-to-many ownership.** Every discovered PID that holds a descriptor is reported, with `parent_pid`
   preserved and `fork_related_parent_pids` flagging descriptors inherited across `fork`.
6. **Executable identity from the opened object.** `/proc/<pid>/exe` is opened once and hashed from that
   descriptor, with `fstat` before and after, so `changed_during_hash`, `deleted_in_path` and
   `identity_verified` describe the object actually read. A pathname is never treated as image identity.
7. **Namespace and permission coverage.** Network namespaces of owner processes, the collector's own
   namespace reference, inaccessible namespaces and permission denials are counted, and
   `coverage.state` reports `NO_DATA`/`COMPLETE`/`PARTIAL`/`DEGRADED` with a one-sentence statement.
   An empty result is no longer indistinguishable from a clean host.
8. **Independent cross-verification, honestly degraded.** `--cross-verify` compares procfs against a
   read-only `NETLINK_SOCK_DIAG` dump and reports agreement, per-source-only endpoints and state
   disagreements without preferring either source. Where the kernel does not offer it, the result is
   `available: false` with a reason and `agreement: not_verified`, never a pretend match.
9. **Dependency updates can pass CI again.** `tests/test_review8_ci.py` pinned one exact action SHA per workflow, so every Dependabot pull request failed the repository's own security test. It now checks the property (immutable commit, reviewed action allowlist, one commit per version label, no floating refs) instead of the version, which keeps the control while letting updates land.
10. **Documentation corrections.** The README no longer claims TTL and TCP-option telemetry that the
   application layer cannot see, and the new `docs/response-boundaries.md` records the permanently refused
   capabilities (traffic interception/forced redirection, remote resource consumption, retaliation).

## Core 0.1.2 / portal 1.0.1 — 2026-10-31

Maintenance and hardening release addressing Review 8 items across collectors, honeypot session auditing, launcher configuration, portal regression testing, and CI dependency automation.

### Walkthrough: what changes for the customer

1. **Distinct partial cloud collection status:** When cloud collector results indicate truncated results (`coverage.truncated = True`), the status is explicitly set to `customer_authorized_integration_partial` with reason `bounded_read_only_request_truncated`, ensuring callers keying on status recognize incomplete data.
2. **Explicit overall HTTP read deadline and unenforced warning:** A single total monotonic deadline spans connect, header, and response read phases. If the underlying socket is unavailable for per-read deadline enforcement, an explicit `deadline_unenforced` warning is attached to the collector result.
3. **Core version synchronization:** Bumps core package version to 0.1.2 across `__init__.py`, `pyproject.toml`, evidence manifests, and test assertions.
4. **Decoy session execution audit contract:** `DecoySession.execute_with_event()` now returns `(output, event_or_None)`, cleanly signaling command-limit exhaustion without requiring callers to inspect event length diffs.
5. **Strict token count metric sanitization:** Explicit token metrics require numeric types (`int` or `float`); non-numeric or nested structures masquerading under count keys are pruned.
6. **Launcher Python path override:** Shell scripts support `CLOUDSENTRY_PYTHON` override with mandatory validation that the specified path is absolute and executable.
7. **Portal safety regressions:** Added tests verifying prototype pollution immunity (`__proto__`) and safe handling of hostile markup in customer payloads.
8. **Automated GitHub Actions maintenance:** Added Dependabot configuration for GitHub Actions workflows.
9. **Findings document cleanup:** Scrubbed development environment path leaks and deduplicated/clarified the path coercion helper documentation.
10. **Defensive audit trail focus:** Refined README documentation to emphasize passive audit trails and clear separation of active probing.

## Core 0.1.1 / portal 1.0.1 — 2026-10-30

Patch release following the supplied review of core 0.1.0 at [`4dea59f`](https://github.com/1243353366/cloudsentry/tree/4dea59f2c276d39ac20ed0ec926b6f2548b16389). The portal changes only its release version and visible changelog link; it does not execute local fixes or collect cloud data on its server.

### Walkthrough: what changes for the customer

1. **A later cloud failure no longer erases earlier successful records.** Render now retains completed service-event pages when a later service request fails. The same protection covers bounded Cloudflare and AWS pagination. Results explicitly mark truncated/partial coverage and retain a safe warning. A partial sample is not a clean-account verdict; no live provider access was used to validate these changes.

2. **Redaction preserves more useful evidence while covering known cross-provider credentials.** Local collector output now removes exact credential values from the fixed supported-provider environment-name allowlist, not only the selected provider's names. Explicit token usage/count metrics such as `tokensUsed` and `expirationTokenCount` can survive, while ambiguous secret-bearing fields remain omitted. This does not discover every opaque secret or scan arbitrary environment variables. Review exports before sharing them.

3. **HTTP failure behavior is clearer and more bounded.** Standard urllib HTTPS body reads use a single monotonic deadline rather than a new 15-second window per chunk; the 8 MiB response cap remains. A secure redirect-refusing opener/TLS context is reused without caching credential values or response data. Redirect refusals and HTTP 429 return explicit fixed reasons, without provider bodies or `Location` values. `Retry-After` presence is noted without following it or adding automatic retries. Opaque response wrappers and underlying resolver/custom-I/O behavior do not gain a universal hard cancellation guarantee.

4. **Console audits cannot reuse the previous command's event metadata at the simulator limit.** The service now checks whether the simulator appended a new event before using it. If no event was created, it records the current limit refusal and response hash instead. The normal service limit remains 100 commands, below the simulator's 1,000-event bound; the new regression exercises the otherwise unreachable boundary without raising either production cap. MIRROR stays opaque, same-socket and non-executing.

5. **Launchers and the selected-file bridge have stricter local boundaries.** Six service launchers use a fixed POSIX shell/path, `/usr/bin/env -i` and `/usr/bin/python3` rather than resolving an interpreter through inherited PATH or invoking inherited Bash first. The configuration worker explicitly closes unrelated descriptors. Before the upstream scanner reads its selected input, the host-added bridge creates a bounded private regular-file snapshot from the authorized descriptor and rejects ordinary concurrent mutation. This is not a filesystem lock or forensic guarantee against a privileged local writer.

6. **Evidence versioning has one source, and ZIP resource errors fail safely.** Build metadata and evidence manifests use `reverse_shell_decoy.__version__`. Existing 0.1.0 packets can still verify consistently, with a different-version warning instead of silently becoming invalid. `LargeZipFile` and `MemoryError` become a fixed invalid-bundle result; external OS quotas remain necessary because catching an exception cannot undo prior resource consumption.

7. **CI inputs are immutable.** Reusable GitHub Actions and the local Gitleaks pre-commit hook are pinned to verified full commit SHAs, with version comments retained. Secret scans still fail their job on findings; no rule or failure check was weakened. A failed job blocks merging only when the repository's separate branch-protection/ruleset settings require it; this release does not assert or silently change those settings.

### What deliberately did not change

- `--consent` is the operator's explicit declaration for that invocation, not proof of ownership, legal authority or OS policy enforcement. Exact-scope, expiry, revocation and single-run checks remain in-process safeguards, not a security boundary against arbitrary code already running in that process.
- The review's PEP 475 cancellation allegation did **not reproduce**: bounded isolated child-process tests interrupted blocked pipe reads and socket receives with SIGINT, revoked the grant and restored handlers. That result is scoped to the tested Linux/Python primitives, not every platform or extension.
- Global lifetime/connection/byte budgets remain finite. There is no automatic cooldown, restart or re-listen. Public exposure needs independent ingress fair-share/rate/connection controls; one source can still consume a deliberately finite global allowance.
- Once output budget is exhausted, a bare close remains correct: a friendly rejection message would itself exceed the cap. Direct startup still refuses known inherited credential names; the clean launchers provide the supported path. Symlinks and shell-like operators, even quoted operators, remain deliberately rejected.
- Realistic console presentation is a small synthetic catalog, not a full OS, shell, robust adversary emulation or promise of sustained deception. Cosmetic string substitutions and a helper's misleading name were not rewritten as security fixes.
- A focused read-only portal review found no confirmed XSS, unsafe HTML/execution sink, cross-tenant access or permissive-origin defect in the reviewed paths. Existing mocked portal tests and exact-origin/ownership/CSRF guards remain; this is not a penetration-test certificate or a live OAuth validation.

### Validation and transparency

The attached review's claims were independently triaged by subsystem; confirmed defects received focused regressions, intentional boundaries were preserved and unconfirmed claims were not presented as proven. See the linked [review and test evidence](docs/review-8-findings.md) for the final executed checks and remaining limitations. Original project code remains Apache-2.0; the preserved auditor remains MIT-licensed.

**Still unproven:** firmware/Secure Boot enforcement and production VM containment — [see the containment note](README.md#limitations-and-transparency-echo-is-not-containment). No new VM deployment, remote loop, provider key custody, policy adoption or automatic remediation was added.

## Core 0.1.0 / portal 1.0.0 — previous release, 2026-10-29–30

The old release remains in Git history rather than as a second executable tree mixed into current code:

- [Complete pre-fix source and README at `4dea59f`](https://github.com/1243353366/cloudsentry/tree/4dea59f2c276d39ac20ed0ec926b6f2548b16389).
- [Download that exact previous source snapshot](https://github.com/1243353366/cloudsentry/archive/4dea59f2c276d39ac20ed0ec926b6f2548b16389.zip).
- Core 0.1.0 contained the bounded local scanners, manual optional collectors, synthetic console/mirror, review-only training, evidence/customer packets, manual backup admission and separate MIT static auditor. Prior release checks recorded 363 core, 95 upstream and 33 portal tests; four CI workflows passed for combined-code commit [`4e687ea`](https://github.com/1243353366/cloudsentry/commit/4e687ea).
- The prior deployed portal checkpoint was `d3101a23fdf64bcb66df9dccd8f8427af3b27043`. Later checkpoint `f167a6d` aligned source license metadata before this patch release; a checkpoint alone is not a separate publication claim.
- Commits `f9e72cd` and `acbf02b` added the containment limitation and its cross-reference. Commit `4dea59f` applied Apache-2.0 to original project code while preserving the auditor's MIT license and prior MIT notice/grants. None established production VM containment.

Old code is preserved for reproducibility, not recommended over the corrected release. Keep incident evidence and manifest pins separate from source archives. Upgrading does not authorize collection, deployment, disclosure or remediation.
