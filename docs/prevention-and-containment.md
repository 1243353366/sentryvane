# Prevention and containment

Two different jobs, deliberately kept apart.

**Prevention** stops unwanted software from establishing or keeping a listener: a written
rule about which executables may bind which ports, a check that compares the rule to what
is actually bound, and the OS-level steps that make an undeclared bind hard.

**Containment** assumes prevention failed. It makes an unwanted listener ineffective with
the smallest change that works, tells you what else that change would break, and leaves an
undo behind.

Neither job involves killing processes, editing another program's files, or touching a host
that is not yours.

## Prevention

### 1. Write the rule

```json
{
  "version": 1,
  "allow": [
    {"executable": "/usr/sbin/sshd", "ports": [22], "exposure": "any", "reason": "operator SSH"},
    {"executable": "/usr/bin/python3", "ports": [22022, 22080], "exposure": "loopback", "reason": "synthetic decoys"}
  ]
}
```

Every entry needs a **reason**. A rule nobody can justify is not a rule, it is a habit; the
loader refuses an entry without one.

### 2. Compare it to reality

```bash
reverse-shell-decoy harden verify --policy /etc/sentryvane/listeners.json
```

Each bound listener gets one verdict:

| Verdict | Meaning |
| --- | --- |
| `approved` | executable is allowed, on a listed port, at the listed exposure |
| `unlisted` | no entry covers this executable |
| `unexpected-port` | the executable is allowed, but not on this port |
| `unexpected-exposure` | policy says loopback; this listener is reachable more widely |
| `unattributed` | no executable could be read, so it is reported as **unknown**, never as allowed |

Exit code is `0` only for `clean`. An empty inventory returns `unknown`, because a scan that
saw nothing is not a host with nothing to find.

### 3. Make an undeclared bind hard

```bash
reverse-shell-decoy harden plan --policy /etc/sentryvane/listeners.json
```

The plan prints five steps, each with what it touches, what it breaks, and how to undo it:

1. **Default-deny inbound** with an explicit accept per policy port. An unwanted listener on
   any other port becomes unreachable even if it starts. Undo: delete the table.
2. **Raise the unprivileged port floor** to 1024, so impersonating a well-known service
   requires privilege.
3. **Log every `bind()`** attempt with the executable, via auditd.
4. **Restrict service sockets** per unit (`RestrictAddressFamilies`, `NoNewPrivileges`).
5. **Schedule the verification** so the rule keeps being compared to reality.

The tool prints these; it does not run them. Prevention that cannot be reversed is a way to
break your own machine, and step 1 in particular will cut off any inbound service whose port
you forgot to list.

## Containment

```bash
reverse-shell-decoy contain plan --port 4444          # what it would take, and what else it affects
reverse-shell-decoy contain plan --pid 4242           # process-scoped tiers, with collateral
reverse-shell-decoy contain apply --port 4444 --confirm
reverse-shell-decoy contain rollback --port 4444
```

### Three tiers, increasing blast radius

| Tier | Scope | Applied by this tool | Collateral it reports |
| --- | --- | --- | --- |
| `port` | inbound tcp on one port | **yes**, with `--confirm` and root | nothing else if no other listener uses that port |
| `cgroup` | one process's socket traffic | no, printed | how many processes share the cgroup, by pid |
| `uid` | every process of one account | no, printed | how many processes share the account |

The plan recommends the **smallest safe tier**. A tier is marked `safe_to_apply: false` when
the tool cannot separate the target from legitimate software, and the `why` says which fact
blocked it. A shared cgroup is never described as process-scoped.

### Hard refusals

- A port that appears in the policy allowlist is refused outright: containing it would cut
  off software you approved.
- `apply` without `--confirm` changes nothing and says so.
- `apply` without root changes nothing; the message tells you to run the printed commands
  yourself.
- `port` and `pid` together are refused, because the tiers differ and mixing them hides
  the collateral.
- A pid that is not in the process table is an error, not an empty plan.

### What apply actually does

It adds one nftables table, `sentryvane_contain`, with a filter chain and a single
`tcp dport <port> drop` rule. Before that, it writes a `0600` state file with the commands
it ran and the exact undo. `rollback` deletes the table and the state file.

Two consequences worth knowing: the table is shared, so rolling back restores the previous
inbound state for every port this tool blocked, and the rule is **inbound only** — an
already-established outbound connection from the target is untouched. Containing a beacon
means blocking what it dials, not what dials it.

### What containment deliberately does not do

- It does not kill, suspend or `SIGSTOP` the process. A hidden process that you killed is a
  process you can no longer observe, and killing the wrong pid is unrecoverable.
- It does not modify, quarantine or delete another program's files.
- It does not act on a host that is not this one, and it does not "contain" a remote peer.
- It does not claim the target is malware. It blocks a port you asked it to block.

## When containment is the wrong tool

If the host is already fully compromised, containing one port is a delaying action, not a
recovery. Rotate credentials, preserve evidence before changing state, and rebuild. A
host-based tool cannot vouch for a host that no longer obeys its own kernel.

Where the listener is allowed but its behaviour is not, the answer is the evidence path, not
blocking: `harden verify` shows the drift, and the decoy and watchdog records show what the
listener actually did.
