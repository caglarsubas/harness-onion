# Amendment HS53 to the W01 host-interface specification

Status: **AWAITING_REVIEW** (independent contract review, round 2, together with seccomp allowlists v5; candidate 2
answers round 1's findings, see the end of this file). Design label `HOST-INTERFACE-DRAFT-002-HS53`, roadmap item
SECCOMP-OBSERVER-LISTENER, packet 1 of 2 (owner and monitor decisions 2026-10-17, via the lane monitor).

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
| `amendment.json` | `planeon.internal.host-interface-amendment/v2` (HS43's schema): the pinned HS43 base and record; seven decisions; six counted substring replacements (three DECIDED, three EDITORIAL); one disposition per decision; eight obligations; the closed list of 14 superseded clauses; one residual; the stated non-amendments |
| `HOST_INTERFACE_SPEC.md` | The effective specification: the HS43 effective text with the six items applied |
| `scripts/host_interface_amendment_v3.py` | The standard-library model: HS43's v2 model with HS53's constants, item places and three tighter checks. `check(read)` checks the HS43 record digest, the closed HS53 record, every superseded file's digest and quoted clause, and that applying the items to the pinned HS43 bytes gives exactly the published bytes |

The model leaves nothing free-standing in the amended text:
- H1 may change only the §5.3 OBSERVER row, and it must keep that row's single line and its cell count, so it cannot add
  a row, a column or a heading;
- H2 is a fixed pair in the model: the stale W02 data pointer becomes the current successor;
- H3 may only append bullet lines (`- ` and indented continuations) after the §4.3 bullet it names, so the v1 peer
  duties stay as written and no heading can be added;
- the title rename and the head sentence are fixed;
- section 13 is rendered from the record alone;
- the superseded clauses must be exactly the model's closed list, in order;
- the three DECIDED items, the residual and the eight obligations must all be present, in order;
- every decision is cited, and each disposition lists every item that cites it;
- the DECIDED items must name exactly the record's obligations, and no item may name another one. Section 13 lists all
  of them, so it cannot be the place that shows one missing.

## Changes

| Item | Where | Change | Decisions |
|---|---|---|---|
| H1 | §5.3 OBSERVER, seccomp and SELinux | Seccomp: "as SERVER without its signed TCP listener", plus, for I01 only, an AF_UNIX SOCK_SEQPACKET listener: `bind` and `listen`, and `accept4` only with flags 0, SOCK_CLOEXEC, or SOCK_CLOEXEC with SOCK_NONBLOCK (low 32 bits). It states what seccomp cannot hold: the grant also reaches any TCP socket the observer holds or creates (including a `listen` without `bind`), so the TCP-listen boundary is SELinux's; among AF_UNIX sockets, too, SELinux holds the listener to I01's path. The socket's directory and mode come from the unit; the observer clears a stale path itself before its filter is installed. SELinux: the I01 listener on its own `unix_stream_socket`, socket file `planeon_observer_sock_t`, the server its only connector; no `tcp_socket listen`, no `node_bind` | Q-SOL-1, Q-SOL-2, Q-SOL-3, F-SOL-1, Q-SOL-5, Q-SOL-6 |
| H2 | §5.3 text after the table | The W02 data pointer names `architecture/seccomp-allowlists-v5/` instead of v2 | Q-SOL-1 |
| H3 | §4.3 | A new bullet: I01's producer is R10's HE-004-I01; both ends keep the v1 peer duties; HE-004-I01's design decides whether HS43's race-free start-time reference applies to I01, and it re-vendors the republished OBSERVER programs | Q-SOL-4, F-SOL-1 |
| E1 | title | Names the three amendments | — |
| E2 | head | Says HS53 is applied on top of the byte-identical HS43 text | — |
| E3 | §13 (new) | Rendered from the record: items, superseded clauses, residual, data order, obligations | — |

## The listener rule and its limits

- `bind` and `listen` take only a descriptor and integers, so the rule leaves them unconditional (Q-SOL-2 (a)).
- `accept4`'s fourth argument is the flags `int` (v6.12 `net/socket.c:2030-2034`). The kernel itself accepts only
  SOCK_CLOEXEC and SOCK_NONBLOCK bits there (`:1982-1983`). The rule narrows that to 0, SOCK_CLOEXEC and
  SOCK_CLOEXEC|SOCK_NONBLOCK, so SOCK_NONBLOCK without SOCK_CLOEXEC is killed.
- Seccomp cannot see a descriptor's family. The observer keeps `socket` for AF_INET and AF_INET6 streams (the I06 read
  connection), so it can create a TCP socket and `bind` or `listen` on it (residual R-OBSERVER-TCP-LISTEN):
  - a `listen` without `bind` meets only SELinux's `tcp_socket listen` check, because v6.12 `__sys_listen_socket`
    (`net/socket.c:1883-1895`) calls `security_socket_listen` and never `security_socket_bind`;
  - by the author's reading of v6.12 SELinux, `name_bind` is not checked for port 0 or for ports inside
    `ip_local_port_range`. Matrix v5 already closes the observer's `name_bind`, and its README states the range part.

  The pinned research tree holds no `security/` or `net/ipv4/` sources, so the last point and the autobind on `listen`
  are stated, not checked here. Denying `tcp_socket listen` closes every path, and denying `node_bind` refuses a bind to
  any TCP port. So the boundary is:
  - O-W03-OBSERVER-TCP: no `tcp_socket listen` and no `node_bind` for `planeon_observer_t` in the host policy;
  - O-T04-HS53: T04 checks it, with `listen` without `bind`, `bind` to port 0 then `listen`, and `bind` inside
    `ip_local_port_range` then `listen`, on AF_INET and AF_INET6;
  - O-MATRIX-OBSERVER-TCP: a matrix revision after the frozen v6 closes them in data.
- Among AF_UNIX sockets, too, the filter cannot hold the listener to I01's path: the observer may create AF_UNIX
  SOCK_SEQPACKET sockets and bind them anywhere its policy allows. SELinux bounds this through the server's `connectto`
  (the only connector into `planeon_observer_t`) and the socket-file rules W03 adds.
- An AF_UNIX SOCK_SEQPACKET socket is checked in SELinux's `unix_stream_socket` class. This is the author's reading of
  v6.12 `socket_type_to_security_class`, and T04 confirms it.

## Socket file, mode and freshness (Q-SOL-3 (a), Q-SOL-5 (a), Q-SOL-6 (c))

I01 needs a root:root 0600 socket in a root:root 0700 directory with no symlink in its path. O-W03-OBSERVER-UNIT
splits this:
- **From the unit:** RuntimeDirectory= with mode 0700, and UMask=0177 so `bind` creates the socket 0600. No socket
  activation, which native profile v3 forbids. A fresh bind at each start.
- **The shared directory:** `/run/planeon/live-proxy/` also holds I02's `capacity-broker.sock` and I05's
  `effect-admission.sock` (base §3), so no unit's stop or restart may remove another listener's live socket. How
  systemd treats a RuntimeDirectory= shared by those units is an open question T04 answers on the enrolled host; this
  amendment does not assume it.
- **A stale path:** under matrix v5 only `planeon_observer_t` and `planeon_server_t` may unlink
  `planeon_observer_sock_t`, and `init_t` may not even stat it. So systemd cannot clear a stale observer socket, and the
  server cannot either (it has no `remove_name` on the directory). The observer clears it itself, before its filter is
  installed. R10 installs the observer's filter in-process, after start-up, so this route applies today. Holding the
  directory's descriptor, it lstats the name (`fstatat` with AT_SYMLINK_NOFOLLOW), refuses anything that is not a
  socket, removes it with `unlinkat` relative to that descriptor, and then binds.
- **The filter:** it adds no `unlink`, `umask`, `fchmod` or `fchmodat` call.
- **The fallback:** if W03 ever installs the observer's filter before exec, the observer can no longer clear the path
  itself. O-MATRIX-OBSERVER-SOCK-CLEAR then has a later matrix revision decide, with the owner's word, whether a named
  clearing agent gets `sock_file getattr` and `unlink` on `planeon_observer_sock_t`. Nothing is granted now.

T04 checks whichever route applies, and that the installed filter still kills `unlink` and `unlinkat`.

## Superseded clauses

The closed list holds 14 adopted clauses, quoted exactly in `amendment.json` and in §13. Their files stay byte-identical:
- the base module table's "Existing fixed native observer, read-only to policy";
- the readiness guide's "Pre-existing protected observation service", its CONF-LIVE-005 row ("Documents the observer as
  a separately installed prerequisite …"), and its two whole sentences beginning "The producer is an external operator
  prerequisite";
- the channel record's `operatorPrerequisite` value and its contract line "An absent independently installed observer
  remains an explicit external prerequisite …";
- the broker handoff guide's "The broker and observer are separately installed, reviewed open-source operator
  prerequisites …", for the observer only;
- the MET-REPAIR-010 summary "The observer is a separately installed open-source operator prerequisite …" in six
  documents;
- seccomp v1's derivation "as SERVER without the listener; the I06 read connection (connect)".

They now read, for I01: the producer is R10's HE-004-I01. The protocol, path, modes, framing, limits, peer checks and the
channel record's other fields (including `installationAuthorized` and `producerAvailable`) are unchanged.

Some statements are left out on purpose, and `notAmended` names them:
- statements that stay true with R10's producer: the observer is a prerequisite whose absence leaves live execution
  NOT_RUN_ENV_UNAVAILABLE, it is a preinstalled native process with its own manifest, and the start-up order;
- records of merged packets' deliverables;
- byte snapshots of earlier states (`docs/history/`, `architecture/*-inputs/meta-before.json`).

## What it does not change

- the I01 wire;
- the v1 peer duties;
- every other §5.3 row, including the WORKER cell's pointer to seccomp v2, where the worker allowlist was defined;
- matrix v5 and the frozen matrix v6;
- seccomp v4;
- every other W01 text and E01-E12 obligation.

A note for W03, not amended here: the gate's I05 and I07 sockets and the broker's I02 socket meet the same stale-path
constraint under matrix v5.

The OBSERVER programs and the edge record are republished in packet 2 (O-PROGRAMS-V3-OBSERVER). The edge record takes the
next free version, probably v6. R10's HE-004-I01 then re-vendors them and serves I01 (O-R10-HE004-I01).

## Round 1 (CHANGES_REQUIRED) and what candidate 2 changed

| Finding | Disposition |
|---|---|
| SOL1-1 MAJOR, no agent can clear a stale I01 path under matrix v5 | Q-SOL-6 (c), monitor: the observer clears it itself before its filter is installed (R10 installs it in-process), in the order fstatat without following a symlink, refuse a non-socket, `unlinkat` on the held directory descriptor, bind. Its filter adds no unlink. New fallback obligation O-MATRIX-OBSERVER-SOCK-CLEAR. T04 checks whichever route applies |
| SOL1-2 MINOR, three listeners share the directory | The obligation and T04 name the observer, the broker (I02) and the gate (I05) |
| SOL1-3 MINOR, TCP surface understated | H1 and the residual cover TCP sockets the observer creates and `listen` without `bind` (`net/socket.c:1883-1895`). The port-0 and range exemptions are stated as the author's reading. T04 lists its cases |
| SOL1-4 MINOR, superseded list incomplete | 14 exact clauses, whole sentences in the guide, plus the stated exclusions above |
| SOL1-5 MINOR, place checks bind only the current text | H1 keeps its line and cell count. H3 may append bullet lines only |
| SOL1-6 NOTE, obligation naming vacuous | The DECIDED items must name every obligation; H3 now names O-PROGRAMS-V3-OBSERVER |
| SOL1-7 NOTE, v5 source check was a prefix | Seccomp v5 pins HS53's OBSERVER row line (`:449`); new mutation M29 |
| SOL1-8 NOTE, "I01 only" among AF_UNIX sockets | One sentence in H1 and in this README |
| SOL1-9 NOTE, W03/R10 identifiers | No change: already public in `docs/MASTER_DEVELOPMENT_PLAN.md`, and F-SOL-1 is quoted verbatim |
| SOL1-10 NOTE, edge version | O-PROGRAMS-V3-OBSERVER takes the next free version and quotes F-SOL-1's note (probably v6) |
