# Amendment HE5 to the W01 host-interface specification

Status: **CANDIDATE c2, AWAITING_REVIEW** (independent contract review, delta round 2, together with operator edge
record v12; `status.json` governs). Design label `HOST-INTERFACE-DRAFT-002-HE5`, slot 270 (MET-ENFORCE-043, EDGE-V12),
owner and monitor decisions 2026-10-26, via the lane monitor.

HE5 lets the capacity broker hand the worker one more descriptor (W01 §5.4 W3-W5): fd 4, the verity-checked O_RDONLY
worker script, beside FD3, so the worker's set is exactly {0..4}; and it records that the broker reads nothing of the
worker's `/proc` after exec. It is applied to the effective text of amendment HS53
(`architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md`). That text stays byte-identical, as do its record,
the texts beneath it, and the two files whose sentences HE5 supersedes.

This is a specification change only. It installs nothing and proves no enforcement obligation; E01-E12 stay
OPEN_UNPROVEN. No R10 file changes in this slot. Operator edge record v12
(`architecture/artifact-edges/operator-harness-engineering-v12.json`) registers the I02/I03 inputs beside it, in the
same slot (Q-EV12-1 (a)).

## Why W3-W5 change

- W5 executed an O_PATH descriptor whose verity digest the broker had checked. FS_IOC_MEASURE_VERITY needs a readable
  descriptor, so the exec descriptor is now the measured O_RDONLY script, fd 4: one open file description from the
  measurement to `execveat`, never re-opened. For a script the kernel hands the interpreter `/dev/fd/4`, so fd 4 stays
  open in the worker, read-only (Q-HE5-9 (a)).
- W3 said the child holds only stdio and the FD3 socketpair end. It now checks, while the child is still uid 0 in the
  broker's domain, that stdio holds no socket and that the two descriptors W4 places are the socketpair end and the
  measured script; W4 closes every other one before exec.
- W4's "close_range above 3" would close fd 4. The child now places both descriptors with `dup3` and closes from 5, in
  raw system calls, with every signal blocked and its disposition reset first and unblocked after.
- After exec the broker reads nothing of the worker's `/proc`: the owner's Q-HE5-12 (b), "Drop post-exec reads". The
  worker's post-exec state holds by construction and T04 traces it (residual R-HE5-POSTEXEC).

## Files

| File | What it is |
|---|---|
| `amendment.json` | `planeon.internal.host-interface-amendment/v2` (HS53's schema, the same key sets): the pinned HS53 base and record; four decisions; six counted substring replacements (three DECIDED, three EDITORIAL); one disposition per decision; two obligations; the closed list of 2 superseded clauses; one residual; six stated non-amendments |
| `HOST_INTERFACE_SPEC.md` | The effective specification: the HS53 effective text with the six items applied |
| `status.json` | The candidate's status for both contract parts of slot 270, this amendment and edge record v12; it governs |
| `source-index.json` | The TOOLS records the candidate is built from, by sha256 (local, not published), and its base inputs |
| `scripts/host_interface_amendment_v4.py` | The standard-library model: HS53's v3 model with HE5's constants and item places. `check(read)` checks the HS53 record digest, the closed HE5 record, every superseded file's digest and quoted clause, and that applying the items to the pinned HS53 bytes gives exactly the published bytes |

The model leaves nothing free-standing in the amended text:
- H1, H2 and H3 may change only §5.4, each inside the lines of its own step (H1 in W3, H2 in W4, H3 in W5), from the
  step's line to the next step line; no item may touch another step, W1, W2 or W6;
- each DECIDED item's proposed text holds no blank line between two of its line feeds (a blank line is empty or only
  spaces and tabs), keeps the step label its current text starts with or adds none, and opens no block on a later
  line, nor on its first line when the current text starts a line without a step label; its current and proposed
  texts agree on a leading line feed and on a trailing line feed (both hold one, or neither does);
- the amended text itself is checked too: §5.4's step lines (the lines that start "Wn. ") are exactly W1, W2, W3, W4,
  W5 and W6, in that order, as in HS53's text; inside W3, W4 and W5, from each step line to the line before the next
  step line, no line is blank, and no line after the step line opens a block unless the identical line occurs in
  HS53's same step; every other line of §5.4, and every line outside §5.4 but the title, the head and section 14, is
  HS53's; so W4's eight calls stay inline as "(1)" to "(8)";
- a line opens a block (CommonMark's block starts and the step label) when, after at most three spaces, it starts with
  a "-", "*" or "+" bullet, an ATX heading of one to six "#" or an ordered marker of one to nine digits and "." or ")",
  each followed by a space, a tab or the line end; or with ">", a step label "Wn.", a fence of three or more backticks
  or tildes, or "<"; or when it is a setext underline (only "=" or only "-", then any spaces or tabs) or a thematic
  break (three or more "*", "-" or "_", with any spaces or tabs between and after);
- the title rename and the head sentence are fixed;
- section 14 is rendered from the record alone;
- the superseded clauses must be exactly the model's closed list of 2, in order;
- the three DECIDED items, the residual and the two obligations must all be present, in order;
- no string in the record holds a line separator other than the line feed;
- every decision is cited, and each disposition lists every item that cites it and the obligations that answer it;
- the DECIDED items must name exactly the record's obligations, and no item may name another one.

## Decisions

Quoted verbatim from the lane's decision record (local, not published), by section id:
- **Q-HE5-9 (a)** (MON-HE005-R1-RULE): "Q-HE5-9 (H5D-3 (iii)): (a)." "Exactly one more inherited descriptor: fd 4, the
  verity-checked O_RDONLY script, read-only. The worker's set is exactly {0..4}, checked both before close_range and
  after exec, under the START freeze. The readiness sentence's errata goes in slot 269, together with Q-HE5-1's
  registration." "Rev 2 must show that fd 4 cannot be written, re-opened writable or used as a second exec route, and
  that the verity measurement and the exec use the same fd." Its post-exec half as re-ruled (MON-HE005-R2-RULE):
  "Q-HE5-9's post-exec half (H5E-1) is re-ruled (a): no capability widening, and HI-7 stays as it is." "fd 4 stays, and
  so does W3's pre-close_range {0..4} check, made while the child is uid 0." "The post-exec {0..4} becomes a structural
  claim, carried by the pinned child path and W3's check, with a T04 trace carried."
- **Q-HE5-12 (b)**, the owner's decision (MON-HE005-Q12-OWNER): "the owner chose Q-HE5-12 (b), "Drop post-exec reads""
  and "R1 is widened and states plainly that runtime detection is given up, with T04 tracing each item."
- **Q-EV12-1 (a)** (MON-EV12-PLAN): "Q-EV12-1 is ruled (a) under the owner's delegation." "slot 269 carries edge record
  v12, with the two BYTE_IDENTICAL, REGISTERED_BEFORE_USE broker-handoff-v1 rows, plus the host-interface amendment
  architecture/host-interface-amendment-he5/ in HS43/HS53 form." "If no rule allows an in-place edit, list it as
  carried." The readiness doc (MON-HE005A-PLAN2): "carried and byte-identical, on your cited rule (FROZEN_PATHS
  :390-397, the sha256 pin at :493, HS53's SUPERSEDED precedent). That is correct for slot 269."
- **MON-HE005-CLOSE**: "DESIGN-HE005 closes at rev 5 (0335ce2d)." "EDGE-V12, the I02/I03 registration plus H5E-10's
  errata list, without the (a) matrix item." The design it closes is the TOOLS record (local, not published), sha256
  `0335ce2df4bd25e5e7ca53c08d9beaa7bea277f69c2c2f8bdebfa1ea3a89f707`.

## Changes

| Item | Where | Change | Decisions |
|---|---|---|---|
| H1 | §5.4 W3 | The descriptor check runs while the child is still uid 0 in the broker's domain: stdio, none of it a socket, and the two descriptors W4 places, the socketpair end (FD3) and the verity-measured O_RDONLY script (fd 4); every other descriptor is closed in W4, before exec | Q-HE5-9, Q-EV12-1, MON-HE005-CLOSE |
| H2 | §5.4 W4 | The child's pre-exec code runs in raw system calls with no allocation or lock: (1) block every signal and reset every disposition except SIGKILL's and SIGSTOP's, (2) `dup3` to 3 and 4, (3) `close_range` from 5, (4) unblock, (5) setresgid/setresuid, (6) drop all capabilities, (7) `no_new_privs=1`, (8) the worker filter | Q-HE5-9, Q-EV12-1, MON-HE005-CLOSE |
| H3 | §5.4 W5 | `execveat(4, …)` on fd 4, the O_RDONLY script descriptor measured before W2 as the same open file description, never O_PATH; `/dev/fd/4` stays open and read-only; no post-exec read of the worker's `/proc`; the post-exec state is by construction, traced by T04 | Q-HE5-9, Q-HE5-12, Q-EV12-1, MON-HE005-CLOSE |
| E1 | title | Names the four amendments | — |
| E2 | head | Says HE5 is applied on top of the byte-identical HS53 text | — |
| E3 | §14 (new) | Rendered from the record: items, superseded clauses, residual, what follows, obligations | — |

The sentences after each changed text stay as they are: W3's `Groups:` sentences, W4's filter sentence and W5's
domain-transition sentence.

## Superseded clauses

The closed list holds 2 adopted clauses, quoted exactly in `amendment.json` and in §14. Their files stay byte-identical,
each by harness-onion's own rule, so both are listed as carried rather than edited (MON-EV12-PLAN):
- the broker handoff guide's "FD3 is the sole inherited non-stdio descriptor" (`docs/alpha-2/BROKER_HANDOFF_READINESS.md`,
  lines 100-101). It now reads: "FD3 and fd 4 (the verity-checked, read-only worker script, Q-HE5-9 (a)) are the only
  inherited non-stdio descriptors" (H1, H3). The guide is frozen by `scripts/validate_seccomp_observer_listener.py`'s
  FROZEN_PATHS (lines 390-391, its entry at 397) and its ERA_SHA256 pin (line 493), as HS53 carried this guide's broker
  sentence (`scripts/host_interface_amendment_v3.py`'s SUPERSEDED, lines 60-77, its entry at 73-75);
- native-profile v4's "on an O_PATH descriptor of the worker executable" (`architecture/native-profile-v4/README.md`,
  line 216). It now reads: "on fd 4, an O_RDONLY descriptor of the verity-checked worker script (W01 §5.4 W5 as amended
  by HE5)" (H3). The README is pinned by sha256 in `scripts/validate_native_profile_v4.py` (lines 402 and 679),
  `scripts/validate_compiled_filter_programs_v3.py` (792), `scripts/validate_i06_backend_profile_v4.py` (918),
  `scripts/validate_native_profile_v5.py` (688), `scripts/validate_selinux_matrix_v4.py` (402) and
  `scripts/validate_w03_plan_amend_3.py` (536).

HE5 governs both texts, and a successor of each file's contract adopts the replacement. A successor of the broker
handoff guide's contract also reattaches the colon clause after the replaced sentence to FD3 alone, and counts fd 4 as
an expected inherited descriptor in the guide's line-118 check ("unexpected inherited FD … refuses before probes").

## Obligations

- **O-R10-HE005** (R10's HE-005C and HE-005D): implement W3-W5 as amended: the descriptor layout; the raw-call child
  path, pinned; the O_RDONLY verity measurement and exec on one description; no post-exec read of the worker's `/proc`.
- **O-T04-HE5** (T04): on the enrolled kernel and policy, confirm FS_IOC_MEASURE_VERITY on an O_RDONLY descriptor of the
  enrolled script; `execveat` of a script through a non-close-on-exec fd 4, with the interpreter reading `/dev/fd/4`; a
  write re-open of fd 4 refused; the worker's post-exec state traced (the descriptor set {0..4}, its uid and gid, an
  empty `Groups:`, its capabilities, NoNewPrivs, `Seccomp_filters: 2`, the label `planeon_worker_t`); `cgroup.kill`
  opened O_WRONLY and written by the sealed broker; a second exec refused.

H3 names both: the worker's post-exec state holds by construction (O-R10-HE005) and is traced by T04 (O-T04-HE5).

## Residual

- **R-HE5-POSTEXEC:** the worker's post-exec state is not observed at runtime: its descriptor set, credentials,
  capabilities, NoNewPrivs, filters and label. It holds by construction (the pinned child path, W3's observed pre-exec
  check, the kernel and the SELinux transition) and is traced by T04. This is the owner's Q-HE5-12 (b) choice: runtime
  detection on the host is given up, and T04 and HE-008's enrollment keep it. It is residual R1 of the closed HE-005
  design (§8). Follow-up: T04 and HE-008.

## What it does not change

- W1, W2 and W6;
- §5.3's rows;
- the BROKER and WORKER seccomp programs (unchanged since MET-ENFORCE-025);
- SELinux matrix v6;
- the I02/I03 wire (registered by edge v12, unchanged);
- the I05 v4 contract.
