# Alpha 2 — exact packet scalar compatibility correction

Status: approved authority publication `MET-REPAIR-007`; product implementation
`CONF-FIX-002` is **NOT_RUN**. This guide supplements, rather than rewrites,
the [six-packet backend plan](LIVE_BACKEND_READINESS.md). Current catalog:
**132 packets, 13 repositories, 16 harnesses, 12 possible live declarations**.

## Diagnosis and evidence

Accepted conformance main is `88de1d9b7272a25678b01129e51d5756dbe608ed`
(PR 5; 103 source files and 120 test IDs). The packet reader JSON-decodes argv
arrays and objects, but returns scalar text without removing double quotes.
All six already-published CONF-LIVE packets legitimately contain JSON-quoted
`id`, `repository` and `warmSourceAccess` values. Their signing and root-owned
activation succeeded; the repository reader subsequently rejected the identity.

CONF-LIVE-001 draft PR 6 at `57ee9668e029b08310c57f502990e419b4a1c797`
failed inside established OS isolation, with exit 2 before **any** acceptance
command or test. Activation sequence 53 and local log SHA-256
`604f1ae0a94ed058d0243fd43e0268c5e524ad6a7259e9aa5f0b0b788aa02d39`
are retained. CI 34115040866 / job 101719758135 was cancelled before runner
assignment: `CANCELLED_NOT_PASS`. No observed product regression-test count or
native result exists for this draft.

The original Linux inventory test also pins the parser's complete old file.
Changing the reader alone would correctly fail that guard. The correction
therefore authorizes exactly one replacement assertion with a fixed new parser
SHA-256, not a mutable exemption or historical fixture rewrite.

## Authority and immutable inputs

The machine authority is
[`packet-scalar-amendment.json`](../../architecture/packet-scalar-amendment.json).
It binds the two new packet specifications and raw hashes, 164 immutable
predecessor packet/architecture/legal/policy/release files, inert before-source
snapshots, the 103-file/120-ID baseline and the two precise transformations.
The old live roadmap remains a byte-identical 130-packet historical authority;
an independently pinned successor admits only these two new IDs.

Do not reserialize any of the 130 existing task YAML files. In particular,
CONF-LIVE-006 contains a published digest lock on CONF-LIVE-001. Editing quotes
to evade the reader would invalidate the signed authority chain. The stored
product source in this meta repository is data only: it must never be imported,
compiled or executed during meta acceptance.

## Execution order and ownership

| Phase | Packet | Work and completion gate |
|---|---|---|
| Alpha 2 authority | MET-REPAIR-007 | Publish only this meta authority; local signed offline, required localhost PR CI, merge, separate local exact-main |
| Alpha 2 correction | CONF-FIX-002 | Start from accepted conformance main; implement the two exact transformations and three new files; all five source gates independently pass |
| Alpha 2 backend | CONF-LIVE-001 | Resume PR 6 only after corrective closure; preserve original inventory and add exact corrective predecessor proof |
| Alpha 2 backend | CONF-LIVE-002 through 006 | Existing sequential source-only plan; no installation or live target authority |
| Alpha 2 native gate | CONF-LINUX-001 / CONF-LIVE-006 | Independent signed native AMD64 qualification before runtime coding; ARM64 separate |

The additive dispatch gate does not rewrite any original predecessor list or
broaden CONF-LIVE-001's allowed paths. Missing corrective SOURCE, LOCAL_OFFLINE,
REQUIRED_PR_CI, MERGE or LOCAL_EXACT_MAIN evidence means **do not dispatch**.

## CONF-FIX-002 implementation contract

Branch: `codex/conf-fix-002-packet-scalars`. Predecessors are MET-REPAIR-007
and the accepted CONF-LINUX-001 source kit, not the blocked session draft.

| Exact product path | Permitted change |
|---|---|
| `ci/run_packet.py` | Replace only the scalar branch in `extract`; every other byte remains unchanged |
| `tests/platform/linux_baseline/test_linux_inventory.py` | Replace only the identified old blob assertion with a single fixed parser SHA assertion and unchanged blob checks for every other file |
| `tests/platform/linux_baseline/test_packet_scalars.py` | New independent parser/identity/refusal and exact-change regressions, discovered by the existing flat Linux suite root |
| `fixtures/platform/linux-baseline/scalar-repair.json` | New exact original/corrected source hashes, all 103 baseline paths, all 120 old IDs and six published packet scalar/argv views |
| `docs/reports/packet-scalar-repair.md` | New source-only diagnosis, implementation, acceptance and rollback evidence report |

Use the exact before/after blocks and prefix/suffix hashes in the amendment.
The corrected parser whole-file SHA is
`397219b875c040d496edaecaca28bf68725c5338313f047a799235b451ca6de1`.
The corrected old inventory test whole-file SHA is
`9111de6b6e167c2eca41801bffc5430b1af8c85f7da696c11a20cce577a1bb29`.
No other change to either existing file is authorized.

Supported scalars are existing bare identifiers or strictly JSON-double-quoted
strings. Decode the latter, then require `[A-Za-z][A-Za-z0-9_-]{0,127}`.
Do not introduce a general YAML parser into the dependency-free product reader.
Reject malformed/trailing strings, indirection, controls, whitespace, non-ASCII,
numeric/object/array/null values and overlong identifiers. Preserve duplicate
field refusal and the exact repository/packet/source-access validation. Bare
tokens such as `true` remain textual identifiers at extraction and must still
fail the real identity validator; do not confuse extraction with authorization.

New product tests must exercise the real extraction and identity validation
against all six pinned published packet scalar/argv views and the previous bare
form. Add negative vectors for the rejected forms above, duplicate fields,
wrong repository/ID/access mode, command reordering and altered source bytes.
Retain all 120 predecessor test identities and the original 103-file inventory.
Run all seven declared commands: the five unchanged existing suite roots plus
campaign and evidence checks. No Make dispatcher/target/argv/dependency change,
new test-root indirection or test suppression is allowed.

## Resuming the session draft after corrective closure

Integrate the exact accepted corrective predecessor into the existing draft,
using its current ten owned files only for inventory/report reconciliation.
Keep all original 103 baseline file hashes and 120 test IDs as immutable history.
Add the corrective main SHA, two corrected source hashes, its three added paths
and independently enumerated new test IDs as a separately checked successor.
Do not replace historical hashes with current discovery output or trust a count
alone. Prove that only the exact two old paths changed and all older IDs remain.
The session draft still requires its full six roots/eight commands, independent
local head, PR CI, merge and local exact-main evidence. This supplement grants
no new product paths, changes to command inventories or automatic acceptance.

## Verification, rollback and remaining gates

Meta verification runs all thirteen packet-declared commands through the
existing signed root-owned offline launcher, including predecessor validators,
strict amendment mutation tests, the full old suite and zero-bill scan. The
new tests compare inert bytes; they do not substitute for product parser tests.
Record local source, required PR CI, merge and exact-main separately. The ten
existing nested-isolation skips, if present, are not native Linux evidence.

Routine activation uses the existing approved nonroot signed runner mechanism.
No root helper, policy, key, sudoers, permission, installation, network egress,
toolchain, API key or billing boundary changes are needed. No warm source is
read or copied. No live launcher or campaign may run in this work.

Before consumption, revert the additive authority as one reviewed unit. After
consumption, publish a reviewed successor instead of rewriting signed history.
Retain failed logs, old inventory and operator replay history. Product rollback
is a reviewed corrective/revert packet, never an unrecorded test weakening.
Linux/native, artifact, deployment, runtime, assurance and tenant acceptance
remain independent and unproven. Alpha 2 is ongoing; no phase-end effort change
is due.
