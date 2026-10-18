# Amendment HS53 to the W01 host-interface specification

Status: **AWAITING_REVIEW** (independent contract review, together with seccomp allowlists v5). Design label
`HOST-INTERFACE-DRAFT-002-HS53`, roadmap item SECCOMP-OBSERVER-LISTENER, packet 1 of 2 (owner and monitor decisions
2026-10-17, via the lane monitor).

HS53 gives the observer the one listener I01 needs (W01 §5.3 OBSERVER row) and records who produces I01 (W01 §4.3). It is
applied to the effective text of amendment HS43 (`architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md`).
That text stays byte-identical, as do its record, the W02D text beneath it, and every contract file whose clauses HS53
overrides.

This is a specification change only. It installs nothing and proves no enforcement obligation; E01-E12 stay
OPEN_UNPROVEN. The allowlist rule it asks for (O-SECCOMP-V5-OBSERVER-LISTENER) is published beside it, in
`architecture/seccomp-allowlists-v5/`, in the same packet (Q-SOL-1 (a)).

## Why the row changes

- I01 is "Server -> observer", AF_UNIX/SOCK_SEQPACKET at `/run/planeon/live-proxy/policy-observer.sock` (base §3).
  Matrix v5 already makes `planeon_observer_t` that socket's listener and the server its only connector.
- W01 §5.3 gave the observer "As SERVER without listener", and seccomp v1-v4 grant it no `bind`, `listen` or `accept4`.
  §5.3 says a call a row does not derive "means the row is wrong and blocks implementation". So the row is amended
  first, as HS43 preceded seccomp v4.
- I01's producer is R10's HE-004-I01 (fact F-SOL-1, owner decision Q-HE4-1 (a), recorded as obligation I01-1 of
  W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f). The earlier statements that the producer is a pre-existing,
  independently installed operator prerequisite are superseded for I01.

## Files

| File | What it is |
|---|---|
| `amendment.json` | `planeon.internal.host-interface-amendment/v2` (HS43's schema): the pinned HS43 base and record; five decisions; six counted substring replacements (three DECIDED, three EDITORIAL); one disposition per decision; seven obligations; the closed list of four superseded clauses; one residual; the stated non-amendments |
| `HOST_INTERFACE_SPEC.md` | The effective specification: the HS43 effective text with the six items applied |
| `scripts/host_interface_amendment_v3.py` | The standard-library model: HS43's v2 model with HS53's constants and item places. `check(read)` checks the HS43 record digest, the closed HS53 record, every superseded file's digest and quoted clause, and that applying the items to the pinned HS43 bytes gives exactly the published bytes |

The model leaves nothing free-standing in the amended text:
- H1 may change only the §5.3 OBSERVER row;
- H2 is a fixed pair in the model: the stale W02 data pointer becomes the current successor;
- H3 may only append after the §4.3 bullet it names, so the v1 peer duties stay as written;
- the title rename and the head sentence are fixed;
- section 13 is rendered from the record alone;
- the superseded clauses must be exactly the model's closed list, in order;
- the three DECIDED items, the residual and the seven obligations must all be present, in order;
- every decision is cited, each disposition lists every item that cites it, and the amended text names exactly the
  record's obligations.

## Changes

| Item | Where | Change | Decisions |
|---|---|---|---|
| H1 | §5.3 OBSERVER, seccomp and SELinux | Seccomp: "as SERVER without its signed TCP listener", plus, for I01 only, an AF_UNIX SOCK_SEQPACKET listener: `bind` and `listen`, and `accept4` only with flags 0, SOCK_CLOEXEC, or SOCK_CLOEXEC with SOCK_NONBLOCK (low 32 bits). It states that seccomp cannot tell this socket from the observer's TCP sockets, so the TCP-listen boundary is SELinux's, and that the socket's directory, mode and freshness come from the unit. SELinux: the I01 listener on its own `unix_stream_socket`, socket file `planeon_observer_sock_t`, the server its only connector; no `tcp_socket listen`, no `node_bind` | Q-SOL-1, Q-SOL-2, Q-SOL-3, F-SOL-1 |
| H2 | §5.3 text after the table | The W02 data pointer names `architecture/seccomp-allowlists-v5/` instead of v2 | Q-SOL-1 |
| H3 | §4.3 | A new bullet: I01's producer is R10's HE-004-I01; both ends keep the v1 peer duties; HE-004-I01's design decides whether HS43's race-free start-time reference applies to I01 | Q-SOL-4, F-SOL-1 |
| E1 | title | Names the three amendments | — |
| E2 | head | Says HS53 is applied on top of the byte-identical HS43 text | — |
| E3 | §13 (new) | Rendered from the record: items, superseded clauses, residual, data order, obligations | — |

## The listener rule and its limit

- `bind` and `listen` take only a descriptor and integers, so the rule leaves them unconditional (Q-SOL-2 (a)).
- `accept4`'s fourth argument is the flags `int` (v6.12 `net/socket.c:2030-2034`). The kernel itself accepts only
  SOCK_CLOEXEC and SOCK_NONBLOCK bits there (`:1982-1983`). The rule narrows that to 0, SOCK_CLOEXEC and
  SOCK_CLOEXEC|SOCK_NONBLOCK, so SOCK_NONBLOCK without SOCK_CLOEXEC is killed.
- Seccomp cannot see a descriptor's family. The observer keeps its TCP sockets for the I06 read connection, so the grant
  also reaches those (residual R-OBSERVER-TCP-LISTEN). SELinux closes the observer's `name_bind` (matrix v5), but the
  kernel does not check `name_bind` for port 0 or for ports inside `ip_local_port_range`. The boundary is therefore:
  - O-W03-OBSERVER-TCP: no `tcp_socket listen` and no `node_bind` for `planeon_observer_t` in the host policy;
  - O-T04-HS53: T04 checks it;
  - O-MATRIX-OBSERVER-TCP: a matrix revision after the frozen v6 closes them in data.
- An AF_UNIX SOCK_SEQPACKET socket is checked in SELinux's `unix_stream_socket` class. This is the author's reading of
  v6.12 `socket_type_to_security_class` (the pinned research tree holds no `security/` sources), and T04 confirms it.

## Socket file, mode and freshness (Q-SOL-3 (a))

I01 needs a root:root 0600 socket in a root:root 0700 directory with no symlink in its path. The observer's filter gains
no `umask`, `fchmod`, `fchmodat` or `unlinkat`. O-W03-OBSERVER-UNIT puts all of this on the unit:
- RuntimeDirectory= with mode 0700, and UMask=0177 so `bind` creates the socket 0600;
- no socket activation, which native profile v3 forbids;
- a fresh bind at each start.

The directory `/run/planeon/live-proxy/` also holds I02's `capacity-broker.sock` (base §3). So the obligation also states
two outcomes:
- no unit's stop or restart may remove another listener's live socket;
- a stale observer path is cleared before the observer binds, by something that runs outside the observer's filter.

## Superseded clauses

Four adopted clauses, quoted exactly in `amendment.json` and in §13. Their files stay byte-identical:
- the base module table's "Existing fixed native observer, read-only to policy";
- the readiness guide's "The producer is an external operator prerequisite";
- the channel record's `operatorPrerequisite` value `PREEXISTING_INDEPENDENTLY_INSTALLED_OPEN_SOURCE_PRODUCER`;
- seccomp v1's derivation "as SERVER without the listener; the I06 read connection (connect)".

The first three now read, for I01: the producer is R10's HE-004-I01. The protocol, path, modes, framing, limits, peer
checks and the channel record's other fields (including `installationAuthorized` and `producerAvailable`) are unchanged.

## What it does not change

- the I01 wire;
- the v1 peer duties;
- every other §5.3 row, including the WORKER cell's pointer to seccomp v2, where the worker allowlist was defined;
- matrix v5 and the frozen matrix v6;
- seccomp v4;
- every other W01 text and E01-E12 obligation.

The OBSERVER programs and the edge record are republished in packet 2 (O-PROGRAMS-V3-OBSERVER). R10's HE-004-I01 then
re-vendors them and serves I01 (O-R10-HE004-I01).
