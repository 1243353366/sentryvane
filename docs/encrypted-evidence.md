# Encrypted evidence on your own machine

This page is about one narrow thing: making the evidence this tool collects on **your
own host** unreadable to anyone who does not hold your key, and making your own
decoy listeners speak TLS so an observer on the path sees ciphertext.

It is not about reading traffic addressed to somebody else. A listener that belongs
to another person is not yours to decrypt, and nothing here will do it.

## What encryption actually buys you here

| Situation | Covered by encryption at rest | Not covered |
| --- | --- | --- |
| A copied archive, synced folder, support bundle or backup is taken | Yes: ciphertext without the key | The key itself, if you stored it next to the evidence |
| The disk is imaged after the machine is powered off | Yes, together with full-disk encryption | An unlocked, running machine |
| An attacker is already running code as you while collection happens | No | The key and the plaintext are in process memory by necessity |
| Someone on the network watches the decoy session | Yes, if you serve it over TLS | Anything the client itself recorded |
| Someone scans the port expecting plaintext | Yes, with TLS: the handshake fails and no banner is returned | A scanner that speaks TLS and accepts any certificate |

Two consequences follow, and both are the reason this document exists rather than a
single cheerful paragraph:

1. **Encryption at rest is not a defence against a compromised host in real time.**
   If an attacker has code execution as the account running the collector, they can
   read the key, the plaintext, or simply the next capture. The only honest answer to
   a host you believe is compromised is to stop trusting it: rotate credentials, move
   collection to a machine that is not compromised, and treat everything collected on
   the suspect host as potentially known to the attacker.
2. **Sealing does not erase.** `vault seal` writes a new sealed file and leaves the
   plaintext original in place. `vault status` tells you exactly which plaintext
   siblings it can still see, because a sealed copy sitting next to an open one
   protects nothing. Deleting a file on most modern media is also not a guarantee;
   full-disk encryption is what covers that gap.

## Sealing collected evidence

Nothing is sealed implicitly. You generate a key once, keep it away from the evidence,
and seal what you decide to keep.

```bash
# One key, owner-only permissions (0600). There is no recovery path.
reverse-shell-decoy vault keygen --out ~/.config/sentryvane/evidence.key

# Seal a capture or an exported bundle; the plaintext original stays put.
reverse-shell-decoy vault seal captures/session.jsonl --key-file ~/.config/sentryvane/evidence.key

# Authenticate without writing anything.
reverse-shell-decoy vault verify captures/session.jsonl.svv --key-file ~/.config/sentryvane/evidence.key

# Decrypt only when you actually need to read it, into a private 0600 file.
reverse-shell-decoy vault open captures/session.jsonl.svv --out /tmp/review.jsonl --key-file ~/.config/sentryvane/evidence.key

# What is sealed, what is still plaintext, and which gaps remain.
reverse-shell-decoy vault status captures --key-file ~/.config/sentryvane/evidence.key
```

The key is never written by the tool. It is read from `--key-file` or from
`SENTRYVANE_VAULT_KEY` (raw, hex or base64). A key file that a group or other
accounts can read is refused, and so is a symlinked key: the permissions that are
checked have to be the permissions that are used.

If the optional `cryptography` package is missing, the vault **refuses to run**
(`pip install 'sentryvane[vault]'`). It does not fall back to a weaker cipher,
because evidence labelled encrypted that is not encrypted is worse than evidence
labelled plaintext.

### What a sealed file records

Each sealed file carries an authenticated header: version, creation time, stream and
index, plaintext length and SHA-256, the source label, and a short **key fingerprint**
(`sha256` prefix, not the key). The header is the AEAD associated data, so altering
the metadata breaks authentication just as altering the ciphertext does. Decryption
then re-checks the length and digest.

`vault manifest` seals an inventory of sealed files. Running `verify-manifest` later
reveals files that were removed or substituted; it cannot restore them, and it says so.

## Serving your own decoys over TLS

`--tls-cert` and `--tls-key` make the synthetic decoys and the relay front terminate
TLS with a certificate you hold:

```bash
reverse-shell-decoy synthetic --tls-cert decoy.pem --tls-key decoy.key --runtime 120
reverse-shell-decoy relay --targets 127.0.0.1:22022 --tls-cert decoy.pem --tls-key decoy.key
```

What this changes in practice, measured rather than assumed:

- A TLS client receives the fake banner normally, and the session record says
  `"transport": "tls"` with the certificate fingerprint from `transport.describe`.
- A plaintext client that connects and sends bytes receives **no banner at all**; the
  handshake fails instead of answering. A port scanner that only reads plaintext gets
  nothing useful.
- The decoy still records what the visitor sent, because something has to decrypt it
  to record it. That plaintext lives in this process's memory while the session is
  open, and the transport metadata says so explicitly.

Supplying only one half of the pair is an error, and so is a certificate and key that
do not match. The listener never silently serves plaintext after TLS was requested.

## Legal boundaries, same as everywhere else in this tool

- Decoys, capture and sealing are for **your own systems**, with authority to monitor
  them. Monitoring somebody else's service, or a service another person runs on a
  machine you happen to control, is not covered by "it is my machine".
- Consent and interception law varies. Where recording is restricted, the decoy
  notices and the retention policy are yours to get right; this tool will not decide
  that for you.
- Captured payloads can contain third-party personal data (credentials, tokens,
  other people's text). Sealing protects it at rest; it does not make keeping it
  lawful or wise. Keep retention short and store the key separately from the evidence.
- Nothing here decrypts, intercepts or re-originates traffic that is not addressed to
  a listener this tool started on your own host.

## Practical checklist

1. Full-disk encryption on the machine, before anything else. It is the only control
   that covers the plaintext this tool writes.
2. `vault keygen`, then keep the key off the evidence volume and out of backups of it.
3. Seal what you keep; delete plaintext originals deliberately; re-run `vault status`
   and read the gaps it reports.
4. `vault manifest` after each collection so later removal or substitution is visible.
5. Serve decoys over TLS if you want plaintext-only scanners to get nothing.
6. After any suspected host compromise: rotate everything, move collection elsewhere,
   and do not present sealed evidence from that host as trustworthy.
