# Seven properties, and what actually holds them up

A decoy listener makes promises. This page pairs each promise with the mechanism that
would break first if the promise were false, the observation that demonstrates it, and
the limit that survives both. `reverse-shell-decoy guarantees` prints the same table as
JSON and exits non-zero unless every property is verified.

| # | Property | Enforced by | Observed by | What is still not covered |
| --- | --- | --- | --- | --- |
| 1 | They can establish a connection | an asyncio listener on a declared host and port, admitted only if the throttle allows | `synthetic_connected` with peer, port, transport | reachability depends on the binding |
| 2 | They cannot access useful host resources | peer bytes are classified by pattern only, never used as a path, address or command | a canary filename in the request never appears in a response or record | a memory or dependency bug; OS-level confinement covers that |
| 3 | They cannot use your proxy as an unrestricted relay | targets must be loopback unless a separate override was set; only the connection already held is forwarded | constructing a relay with a remote target raises | the override exists for reviewed lab setups, and records then say `explicit_remote` |
| 4 | They cannot execute commands through your service | no execution primitive in the reachable modules, no interpreter of peer input | AST scan of the listener modules plus shell-syntax probes | the scan covers this package, not its dependencies |
| 5 | They receive synthetic or restricted responses | a fixed banner set with an explicit notice | banner text and `peer_told_it_is_synthetic` | truthfulness, not unfingerprintability |
| 6 | Their session can be throttled, suspended or terminated | token buckets for connects and input units, plus session, idle, line-length and input budgets | `synthetic_throttled` records and a `closed_reason` naming the budget | budgets are in-process; a restart resets them |
| 7 | Their activity generates evidence | every connection, denial and termination appends a bounded, minimised record | record counts by kind for the same probes | the host that wrote it |

## How the check works

```bash
reverse-shell-decoy guarantees            # live loopback probe plus static scan, exit 0 only if all verified
reverse-shell-decoy guarantees --no-probe # static scan only; all seven report unverified
```

The live part does not ask politely. It connects, sends `cat /etc/passwd` with a canary
path, `id`, `$(...)`, backticks and a `CONNECT` request, then floods the listener to force
throttle denials. It then reads the records it produced and reports what it saw.

The static part parses the listener modules as an AST and counts calls that would turn
input into host action: `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `pty.spawn`,
`eval`, `exec`, `compile`, `__import__`. Two outcomes matter:

- A non-zero count is reported, and the execution property fails even if the live probe
  looked harmless.
- A file opened with a **non-literal** argument is listed separately, because that is the
  shape a peer-input-becomes-a-path bug takes.

Network calls are counted separately rather than folded into the execution count. The
relay must open exactly one outbound connection, to its loopback backend; that is the
design, not a leak.

## Reporting rules worth knowing

- `verified` requires a mechanism **and** an observation. `--no-probe` therefore never
  prints `verified`; it prints `unverified`, which is not a softer form of success.
- `failed` means a mechanism is missing or an observation contradicted it, and the process
  exits non-zero.
- The report embeds the capability scan, so a later reader can see what was counted, not
  just the verdict.

## The limit that applies to all seven

A host-based listener cannot vouch for itself after complete host compromise. If an
attacker can rewrite the code, the throttle, or the journal, every property above becomes
a statement about what the attacker chose to leave behind. The honest response is the
same as elsewhere in this tool: rotate credentials, move collection to a host that is not
compromised, and treat reports from the suspect host as evidence of activity rather than
proof of containment.

Two narrower limits are also worth stating plainly. "No execution" is checked against the
modules a visitor can reach, not against the Python interpreter, the standard library or
every dependency. And "synthetic responses" means the decoy never pretends to be real: it
does not mean the decoy is indistinguishable from a real service, because a determined
observer can tell.
