# Sentryvane: defensive triage and bounded decoys

**Current version: 0.1.5, released 2026-11-01.** Sentryvane is the current version of the
CloudSentry line. Earlier CloudSentry releases stay in this repository's history and the
original upstream project remains at [@HuginnsHammer/CloudSentry](https://github.com/HuginnsHammer/CloudSentry).
Where a document still says CloudSentry, read the same tool: the package and CLI keep their
published names `reverse-shell-decoy` so existing installs and logs stay valid.

CloudSentry is a **defensive audit trail and log-triage CLI with a separate synthetic terminal and bounded byte echo**, plus a keyless browser portal for reviewing customer-selected JSON results. It helps inspect authorized evidence, preserve tamper-evident audit trails, and explain observations without executing untrusted commands or granting host access. The core package is strictly passive: it performs zero active network probing, scanning, or callbacks.

**[Launch the live portal](https://csportal-brpeckhv.manus.space)** · **[What changed and the previous release](CHANGELOG.md)** · **[All guides, sources and public links](LINKS.md)**

Current versions: **core 0.1.5 / portal 1.0.1**. The [changelog](CHANGELOG.md) walks through confirmed fixes, unconfirmed review claims and deliberate safety boundaries, with immutable links to the old 0.1.0 source. The public repository and separately managed website do not share customer evidence or credentials.

## Encrypting your own evidence

`vault` seals the evidence this tool collects on your own host with ChaCha20-Poly1305,
so a copied archive, synced folder or stolen backup is ciphertext without your key; a
sealed manifest makes removed or substituted files visible. `synthetic` and `relay`
accept `--tls-cert`/`--tls-key` so your own decoys serve TLS and a plaintext-only
scanner gets no banner at all. What this does **not** do: protect evidence from an
attacker already running code as you, erase the plaintext original, or decrypt traffic
addressed to anyone else's service. The optional `cryptography` backend is a hard
requirement for sealing, and it fails closed rather than using a weaker cipher.
See [docs/encrypted-evidence.md](docs/encrypted-evidence.md).

## Inspecting as little as possible

Every session is recorded metadata-first: the permitted scope is stated before any byte is
parsed, protocol metadata comes next (family, method, path, query keys, sizes), only
allowlisted application fields are kept, secret-looking values are redacted and counted,
and the record is bounded and carries the reason for each field it holds. Bodies and header
values are not in it. Full payload is a separate, labelled tier you ask for with
`--full-payloads`, and `inspect` applies the same minimisation to a capture you already have.
See [docs/data-minimization.md](docs/data-minimization.md).

## What it does

The local tools import selected text/JSONL logs and cloud exports, record limited host OS context, inventory Linux listeners, flag possible shell-linked TCP and persistence indicators, and compare names against an operator-provided typosquatting baseline. Indicators and missing coverage are not compromise or all-clear verdicts.

The optional static configuration auditor checks one selected Terraform, Dockerfile or Compose file without executing it. It is the separately namespaced, pinned **MIT-licensed work of [@HuginnsHammer](https://github.com/HuginnsHammer/CloudSentry)**, with its original source, license and creator notices preserved.

The synthetic console implements a small canned command catalog with cosmetic root/admin output, not a real OS or interpreter. PHP metadata is simulated. MIRROR reflects only the same visitor connection's bytes; the silent sink emits no application response. Neither calls back, loops traffic into a remote listener, executes a command or promises to fool a capable visitor.

The browser uses managed Google/Microsoft/passkey sign-in, customer-isolated reports and metadata-only provider profiles. Customers authenticate with providers and perform scans/exports in their own tools, then deliberately import bounded JSON. No provider keys are requested or stored by the portal; direct GitHub sign-in is not included. Local optional read-only BYOK collection remains separate. Every portal summary requests fresh consent.

## Install and choose an operation

Core runtime: Python 3.10+ and the standard library. Native process/socket/persistence inspection targets Linux; other evidence and synthetic functions are separate from native Windows endpoint scanning. Optional AWS collection needs its documented SDK. The optional configuration auditor has its own Python 3.12 environment.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --no-deps .
reverse-shell-decoy --help
```

Choose your authorized inputs and follow the [local/manual cloud workflow](docs/workflow.md), [collector permissions](docs/collectors.md) or [integration trust guide](docs/integration-trust.md). No scan, provider connection, VM or public listener starts on installation, website login or a detector finding.

For the optional credited configuration auditor:

```sh
python3.12 -m venv .config-auditor-venv
.config-auditor-venv/bin/python -m pip install -e './integrations/config-auditor[dev]'
python3 scripts/scan-configurations.py --target /absolute/path/to/Dockerfile \
  --format json --consent
```

Exit 0 means no qualifying finding, 1 means findings and 2 means incomplete/denied/failed—not clean. The bridge rejects symlinks and oversized files, stages a bounded private snapshot from the authorized descriptor, checks ordinary concurrent mutation and limits worker output/runtime. Explicitly choose a reviewed ordinary file rather than an alternatives-style symlink. Source locations and evidence can contain sensitive data: review them before importing output as `local`. See [setup and preserved upstream limitations](docs/config-auditor-integration.md).

## Local decoy: manual and finite

```sh
# Deliberately start a new bounded loopback console, not a production VM.
sh scripts/start-honeypot.sh

# Analyze one selected preserved audit; no service is started by this command.
python3 scripts/operations-summary.py --audit preserved-service-audit.jsonl --json
```

The clean launcher drops inherited credentials and uses a fixed interpreter. Direct service startup still refuses known inherited credential names. The scanner, console, mirror, customer portal and cloud credentials remain separate. Public source visibility does not create a public honeypot.

Default byte budgets are 1 MiB global admitted input, 1 MiB reserved output and 64 KiB input per session, with a rate of 10 commands/chunks per second. Lifetime, connection, audit and command limits also apply. Budget exhaustion closes work without automatic restart; a bare close after output exhaustion is intentional. A single source can consume the finite connection allowance. External ingress fairness, flood control, egress restrictions, OS resource enforcement and cloud-bill controls remain the operator's responsibility. Application byte accounting is not a physical traffic or billing meter.

Non-loopback binding needs explicit `--allow-public` and independently reviewed infrastructure. The [service guide](docs/service.md), [mirror guide](docs/mirror.md), [manual opt-in instructions](docs/resource-economics.md#customer-opt-in-run-it-manually-on-your-infrastructure) and [emergency-only profile](docs/emergency.md) describe the precise modes and limits. There is no automatic DNS change, traffic interception, hidden persistence, infinite hold, OCR sabotage, remote resource exhaustion or real visitor interpreter.

## Customer control, content patterns and adversarial-activity summaries

```sh
python3 scripts/customer-forensic-report.py --text selected-content.txt \
  --audit selected-audit.jsonl --output-dir new-private-packet --consent
```

The [customer packet](docs/customer-forensic-report.md) preserves selected source hashes, UTC generation time, a packet ID and a separately retained manifest pin. Aggregate UTF-8 writing metrics can describe vocabulary, punctuation, sentence proxies and repetition, with an optional explicit baseline. PDFs require customer-reviewed text extraction first; there is no general PDF/OCR upload feature. The browser accepts bounded JSON, not arbitrary PDF/text uploads.

The customer is the operator, not the profiling target. Content and logs may support a descriptive stylometric footprint or suspected-activity pattern summary; they do not prove identity, authorship, psychology, intelligence, intent, skill or unauthorized access. Changes from a baseline need comparable source material and alternative explanations. Unknowns remain unknown, and copied, quoted, assisted or synthetic text must not be assumed to have one author.

Correlate genuinely independent authentication/network/host records without treating one signal as proof of another. Preserve provenance, available timestamps and clock uncertainty; duplicated exports are not independent corroboration. A synthetic root prompt is not a real compromise, and packet consistency is not source authenticity or legal admissibility. Never convert uploaded instructions or a detector flag into deployment authority. Nothing submits a case to law enforcement automatically.

`--consent` records the operator's explicit declaration for one invocation. It does **not** independently verify ownership, lawful authority or OS permission. Scope, expiry, revocation and single-run grants are in-process safety checks, not isolation from arbitrary code already running in that process. See [engineering contracts](docs/engineering-rules.md), [permission-gated reporting and verification](docs/security-behavior.md), [post-scan review](docs/post-scan-review.md) and [fixed text-indicator limits](docs/trail.md).


## Defensive telemetry vs. active probing

CloudSentry core remains strictly passive. What the decoy listener can actually record, and therefore what this source claims, is narrower than "full packet telemetry": the observed peer endpoint, when the connection was accepted and closed, the peer's opening bytes (a client banner such as `SSH-2.0-...`), the server banner it presented, and, only when the operator opts in with `--capture-payloads`, the complete inbound payload up to a fixed byte budget. Recording what a peer sends to your own listener is ordinary inbound honeypot telemetry.

Core does **not** read IP TTL values or TCP header options: those live below the application layer, and reading them would require raw sockets or packet capture, which this package deliberately does not use. It never redirects a visitor's traffic elsewhere, never re-originates a connection to a third party, and never dials out beyond loopback. Outbound active probing is kept completely separate from core on its own isolated development branch (`feature/active-probe`), disabled by default, and pending legal review.

The one exception is the loopback relay (`reverse-shell-decoy relay`), stated precisely because the difference matters: it accepts a connection on this host and forwards **that same connection** to a decoy backend that must be on loopback, then pumps both directions under byte and time budgets. It opens no outbound connection to a remote host, joins no two visitors' sessions, and intercepts nothing it did not receive. Every record carries `no_third_party_transit: true` and every session record carries `third_party_transit: false`. See [relay rotation](docs/relay-rotation.md).

Every listener the service entry point opens is **paced by default** by one shared token bucket, so a single source cannot multiply its admitted rate by opening more sessions or by hitting a second port. See [the service guide](docs/service.md) for the pacing and capture flags, and [observation completeness](docs/observation-completeness.md) for the measured-coverage listener inventory.

## Policy drift, decoys and the limit of a host observer

Four read-or-serve-only commands answer different questions, and none of them is an all-clear:

- `policy` reads the effective packet filter (`nft -j list ruleset`, then `iptables-save`/`ip6tables-save`, or `netsh advfirewall` and `Get-NetFirewallProfile` on Windows) plus network-namespace coverage, and compares it with CloudSentry's own authorization rules. It reports `MATCH`, `DIVERGENT`, `PARTIAL` or `UNKNOWN`, changes no rule, and sets `all_clear: false` every time. See [policy divergence](docs/policy-divergence.md).
- `scan-loopback` is a bounded TCP connect scan that refuses every non-loopback target by construction, reports explicit completeness, and can cross-check the procfs inventory for disagreement in either direction. See [loopback scan](docs/loopback-scan.md).
- `watchdog` diffs bounded listener snapshots and links a returning binding to its first sighting. It never signals, blocks or restarts anything: every event carries `action: none` and `requires_authorization: true`. See [listener watchdog](docs/listener-watchdog.md).
- `synthetic` serves deliberately obvious fake services whose banners state that nothing is executed, authenticated or stored, and records interaction shape rather than content. Every record is tagged `synthetic: true` / `not_host_activity: true`, so a summary of real activity can exclude the decoy's own invitations. See [synthetic decoy services](docs/synthetic-decoy.md).

**A host-based observer cannot survive a compromised host.** A sufficiently privileged attacker can change both the packet filter and the tools used to read it. `policy` therefore carries a rotation recommendation instead of a reassuring verdict: re-read after any privileged change, on a schedule you control, and from at least one independent vantage point (another host, a network tap, a separate namespace) that a compromised observer cannot rewrite. Rotation, independent observation and preserved evidence are the controls that remain meaningful; a matching result here means two descriptions agree, not that the host is clean.

## Limitations and transparency: echo is not containment

**Partial coverage is sufficient for trusted-fixture testing; it is not sufficient for a production containment claim.** Echo handlers sit at the application layer: they restrict what the application does, not what the operating system permits. A bounded, non-executing echo workload is not itself an OS, hypervisor, device or network isolation boundary.

The echo components and configuration checks have been exercised and pass within their documented test scope. Passing those checks is not the same as validating the VM layers beneath them. Software TPM and disposable-image functional results also do not establish end-to-end containment. The production guest OS, hypervisor, device policy and network isolation have **not been deployed and validated together as a containment stack**; firmware/Secure Boot enforcement and production containment remain unverified.

**Unverified VM/failover deployment paths remain disabled or unavailable by default. More echoes are not compensation for unverified layers.** Manually launching an individual echo service does not validate its host or VM, and static configuration acceptance or a passing application test must never be presented as production deployment approval.

Before making a production containment claim, separately validate the guest OS, hypervisor, device restrictions, network isolation, resource enforcement and failure/stop behavior on the actual target environment, under explicit authorization and with negative tests and independently preserved evidence. Uploaded reports, synthetic scenarios and detector results cannot authorize deployment or change trusted production policy. Until that evidence exists, report the relevant assurance as **unknown**, not secure or contained.

The [manual VM setup](docs/vm-setup.md), [backup admission review](docs/vm-backup-hardening.md), [software-only lab](docs/software-vm-lab.md) and [historical lab assessment](docs/backup-lab-assessment.md) are separate. Static candidate acceptance always leaves deployment unapproved. Missing device/resource-policy enforcement fails closed; application quotas do not eliminate CPU/GPU side channels. Containers and synthetic consoles are not substitutes for an independently validated hypervisor.

## Creators, upstream work and ethical use

| Creator / community | Work and attribution boundary |
|---|---|
| [@HuginnsHammer](https://github.com/HuginnsHammer) | [CloudSentry configuration auditor](https://github.com/HuginnsHammer/CloudSentry): pinned source under `integrations/config-auditor/`; original MIT copyright/license preserved. Only the host-added bridge is maintained here. |
| [@jephersonRD](https://github.com/jephersonRD) | [PC-Free](https://github.com/jephersonRD/PC-Free): backup design reference, not automatically installed or trusted. |
| [@dockur](https://github.com/dockur) | [Windows runtime](https://github.com/dockur/windows): referenced dependency concept, not authenticated by linking. |
| [@TechxArtisanStudio](https://github.com/TechxArtisanStudio) | [Openterface KVM-GO](https://github.com/TechxArtisanStudio/Openterface_KVM-GO_Hardware): administrator-only physical-console reference, not the Linux KVM hypervisor or a visitor interface. |
| [@9elements](https://github.com/9elements) | [VMBoot](https://github.com/9elements/VMBoot): separate firmware research; not flashed or enabled here. |
| [@qemu](https://github.com/qemu) and contributors | [QEMU](https://github.com/qemu/qemu): trusted functional lab tools; TCG tests do not prove hostile-guest isolation. |
| Linux KVM community | [KVM](https://www.linux-kvm.org/): referenced hardware-virtualization backend; no `/dev/kvm` was available in the documented sandbox. |
| [@stefanberger](https://github.com/stefanberger) and contributors | [swtpm](https://github.com/stefanberger/swtpm): finite software-TPM tests, not physical attestation. |
| [@tianocore](https://github.com/tianocore) and contributors | [EDK II / OVMF / AAVMF](https://github.com/tianocore/edk2): functional firmware reference; Secure Boot enforcement remains unproven. |
| [@openbmc](https://github.com/openbmc) and contributors | [OpenBMC](https://github.com/openbmc/openbmc): research reference, not deployed or tested. |
| Prompt Injection Database project | [Public site](https://www.promptinjectiondatabase.com/): no access-gated corpus copied or contribution submitted; [local original-fixture testing](docs/prompt-injection-corpus.md) is separate. |
| GitHub community | [Virtual-machine topic](https://github.com/topics/virtual-machine): discovery index, not an implementation or certification. |

Credits support attribution and professional discovery, not endorsement or guaranteed notifications. [ETHICS.md](ETHICS.md), component notices and [LINKS.md](LINKS.md) preserve the full references. Direct outreach, issues, contributions and public evidence submissions are separate actions. Use only on systems and evidence you are authorized to assess; never punish or exhaust another endpoint.

## Tests, release evidence and licenses

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The current [review findings](docs/review-8-findings.md) distinguish reproduced defects, deliberate boundaries, tested claims and remaining gaps. The [changelog](CHANGELOG.md) keeps previous releases and test scopes separate. A triage tool can miss short-lived, hidden, encrypted or namespace-isolated activity; neither a positive indicator nor an empty report is definitive. See [SECURITY.md](SECURITY.md), [trust model](docs/threat-model.md) and [secret-scanning requirements](docs/secret-scanning.md). Job failure blocks merging only when a separate repository ruleset requires the check; no branch-protection claim is implied.

Original CloudSentry code and documentation are **[Apache-2.0](LICENSE)** except where component notices apply. The bundled auditor remains **MIT-licensed** under its unchanged [upstream license](integrations/config-auditor/LICENSE). Dependencies and assets retain their terms. [NOTICE](NOTICE) preserves attribution; [licenses/MIT-legacy.txt](licenses/MIT-legacy.txt) preserves the previous root notice and does not withdraw existing grants.
