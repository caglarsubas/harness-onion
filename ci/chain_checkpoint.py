"""MET-PERF-047 (CHAIN-COMPACTION-002, G1): the chain checkpoint's shadow reader.

Loaded by path from the root conftest.py inside a guard: a missing, unloadable or raising reader never changes a
session's outcome. Active only in an outermost pytest session (PLANEON_PARALLEL_SUITE_SERIAL absent at import; every
worker and nested pytest inherits it) and only when architecture/chain-checkpoint/record.json exists. Shadow mode
observes and records only; nothing here raises out of a hook or changes an exit status.

Public interface: Reader(root, clock, cap, tree, in_dry_run).start(); .report(nodeid, when, outcome, duration);
.finish(head_sha=None) -> (summary line, record dict); rebuild(path, live, newer, normalised, budget); sample(tree,
slots, fraction); naming_authority(root, live_sha, budget, auths); newer_authorities(root, baseline, budget, auths);
check_ledger(record); head_slot(record, auths); entry_fault(entry); attach_classes(apath, rec, sides);
unauthored(reverted, unexplained);
check_pairs(entries); pin_normalised(raw, default); and the CLI
`chain_checkpoint.py dry-run-compare LOG OUT` (the dry-run runner's comparison, parameters.shadowIn == "dryRunOnly").

The ledger (record.json, schema harness.planeon.ai/chain-checkpoint/v1): schemaVersion, checkpointSlot,
checkpointBaseline, writingCommit, writingTree, parameters {cadenceSlots, sampleFraction, fullRunOn, nShadow,
shadowCapSeconds, workers, shadowIn}, normalisedRecordClass, layers [{slot, module, validatorPath, validatorSha256,
testFilePath?, testFileSha256?, authorityPath, authoritySha256, inputs {path: sha256}, nodes [{nodeSha256, setup, call,
teardown}], seconds}], checkPairs [{layerSlot, pairsPath, ids [a, b], type}], fullRunProof, writingRun, sizeBytes,
sizeBound, exclusion {files, pinLine} (MON-282-W2-RULED: the step's own products, never an input; the
pinLine file is attested with its AUTHORITY_SHA256 line normalised, pin_normalised). Every digest is at the
checkpoint tree.

The rebuild (D9 (a)): for each attested file, undo newest first the reverseHunks of every authority newer than the
checkpoint (baseline catalog larger than checkpointBaseline), byte-exact, afterSha256 and beforeSha256 checked; each
authority keeps v2.1's eight-member form and three-key hunks; a classed authority's classes live in its
closed hunk-class record (HUNK_CLASSES_DIR/<slot>.json, MON-282-W1-A2: exactly authorityPath, hunkClassVocabulary,
hunkClassRuleSha256, hunkClassContext {newPacket == authorityPacket, prevValidator, prevTest, steps == [1, 1 + K]}
and classes {path: one class per reverse hunk, in the authority's order}), an ordinary new file of its step that
the authority's newFiles names by sha256, checked after the entry's shape (entry_fault) and before any class is
trusted; a missing, unnamed, digest-mismatched, malformed, miscounted or duplicated record, or an authority that
carries classes itself, is class A; each recorded class is re-checked by the rule its record names
(RULES_BY_SHA: chainmech v2.2's or v2.3's; one copy below, v2.2's being v2.3's with register off), and only classes
in normalised() are undone (cascade, bridge and register, plus record when normalisedRecordClass).

The shadow record (one JSON line in the session's log, prefixed "chain-checkpoint shadow record:"): headSha,
readerSeconds, capSeconds, overCap, workers and workersSource, shadowIn, mode, naming, attested (every ledger slot),
sampled, layers {slot: {recorded, live, agree, writingSeconds, liveSeconds}}, reverted {slot: [[path, [[authority,
{class: count}]]]]}, unauthored [paths], disagreements [{slot, where, class, kind, countEffect, detail}].

The kinds, their classes and their countEffects are architecture/chain-checkpoint/README.md's countEffect table, the
single source; COUNT_EFFECT below mirrors it, and the module tests pin the two equal. A kind is set by cause, never by
an exception's type: corrupt is exactly what check_ledger, _authorities, entry_fault and newer_authorities refuse
(the README's corrupt row), naming the file and the member; any other exception of the reader is fault, and so is a failing clock (one record
per reading, "the clock failed"; P047-ORACLE-B1). A class-C record's slot is the head's chain slot (head_slot: checkpointSlot plus the authorities newer than
the checkpoint by baseline, one authority per slot: their baselines and authorityPackets are distinct; null when the
ledger was not read or its slots are malformed). A fault's or a corrupt record's detail names its exception class;
every class-C detail names the head slot and the checkpoint slot. An attested file whose only miss is at its newest recorded
step is unauthored: class A, kind input, listed in unauthored. Stop rule (condition (v); MON-282-C23, MON-282-QC31):
every kind restarts the clean count of N_shadow except skipped, which is neutral and still writes its record; an
agree counts; a dry-run-only reading by the dry-run runner counts. Any three skips, or any three faults, within the
period are a finding to the lane monitor, not only consecutive ones (MON-282-CR4-KEEP), counted across verify records by the monitor and by MET-PERF-048 (no reader sees
more than one session); a reader that keeps faulting is a ci/ defect, not a reason to re-run the period.

MET-PERF-049 (slot 286, CONTRACT_286 r3) adds:
- **Class rule v2.4** (RULE_V24_SHA256, the block after v2.3's): R1 member forms F1 (K 0), F2 (K >= 1) and F3 (ids in the
  authority's productPackets key order); R2 declared digit pairs only (the catalog pair (n, n + steps[1]) and the
  context's countPairs); W, the weights append form. A v2.4 record's context has exactly five keys (countPairs added).
- **The class cache:** L1, per session, the classes of one authority's hunks on one path, keyed by (the authority's
  sha256, path), filled only by a completed ordered pass (a hit still runs the afterSha256 gate and the byte checks);
  L2, per Reader invocation with its newer set fixed at start, one rebuild per (path, live sha256), filled only after
  the afterSha256 gate. Neither outlives the invocation (PERF-028/029, Q-PERF40-2).
- **The demotion (OQ-048-1 (b)):** when a path's only unexplained entry is "n of m hunks of a class not normalised",
  the replay continues with every hunk of every newer authority on the path, gates kept, to the attested digest; on an
  exact landing every layer attesting the path is demoted (neutral) and runs live; otherwise class A. A demoted layer's
  changed outcome is "demoted-outcome-explained", countEffect "pending isolation", only with a matching
  outcomeStatements entry of the authoring v2.4 record; otherwise class A.
- **MET-PERF-048's inert provisions:** P-048-1, the G1 module ci/chain_checkpoint_g1.py is loaded only when present;
  P-048-3, the mode of record is the verifier's declaration (the T1 signal file under HOME, checked by signal_check)
  plus the module's presence. MODE is the default mode; at 286 the module is absent, so the run is shadow.
"""
import base64
import difflib
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/chain-checkpoint/record.json"
SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
CAP_SECONDS = 15.0
SERIAL_ENV = "PLANEON_PARALLEL_SUITE_SERIAL"
OUTERMOST = SERIAL_ENV not in os.environ
MODE = "shadow"                                       # the default mode (047); the writer refuses any other (condition (i))
G1_MODULE = "ci/chain_checkpoint_g1.py"               # P-048-1: MET-PERF-048's module, loaded only when present
SIGNAL_RELATIVE = ".planeon/chain-checkpoint-g1-signal.json"   # P-048-3 (T1): under the verifier account's HOME
SIGNAL_FIELDS = frozenset(("ledgerSha256", "g1ModuleSha256", "bundleId", "head"))
SIGNAL_MAX = 4096
RULE_SHA256 = "007112479ff663fea703347aed5e8f8ee9ff39a540118002dfd7b42ac592748f"   # the pinned hunk_class_v23.py (MON-282-W2-RULED)
RULE_V22_SHA256 = "c4a77f027b244d6f1c22178fadfa7c0d4b6f7b607ada89b2eebdebc01417427b"   # the pinned hunk_class_v22.py
RULE_V24_SHA256 = "9287d40a173d3bf63f6ea833f82876194c9a2ebf1e1d7263c453d621797cddc9"   # the pinned hunk_class_v24.py (CONTRACT_286 r3 3.1)
PREFIX = "chain-checkpoint shadow:"
RECORD_LINE = "chain-checkpoint shadow record:"
COUNT_EFFECT = {"input": ("A", "restart"), "stale": ("A", "restart"), "outcome": ("B", "restart"),
                "corrupt": ("C", "restart"), "over-budget": ("C", "restart"), "over-cap": ("C", "restart"),
                "fault": ("C", "restart"), "skipped": ("C", "neutral"),
                "demoted": ("—", "neutral"), "demoted-outcome-explained": ("—", "pending isolation")}   # the README's countEffect table; an agree counts
ISOLATION_EFFECT = {"PASS": ("—", "count"), "FAIL": ("A", "restart")}   # E1 (286 3.11): what the lane's isolation record implies
UNAUTHORED_MISS = "afterSha256 differs before the replay"
HUNK_CLASSES_DIR = "architecture/chain-checkpoint/hunk-classes"     # MON-282-W1-A2: one closed record per classed authority
SIDE_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext", "classes"})
SIDE_MEMBERS_V24 = SIDE_MEMBERS | {"outcomeStatements"}     # 286 C1-5: picked by the record's own rule digest
CONTEXT_KEYS = frozenset({"newPacket", "prevValidator", "prevTest", "steps"})
CONTEXT_KEYS_V24 = CONTEXT_KEYS | {"countPairs"}
CLASS_MEMBERS = ("hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext")
PIN_LINE_PATTERN = rb'^AUTHORITY_SHA256 = "[^"]*"\n'     # MON-282-W2-RULED: the head validator's one pin line
PIN_PLACEHOLDER = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"\n'
EXCLUSION_MEMBERS = frozenset({"files", "pinLine"})

# ---- chainmech v2.3's class rule (hunk_class_v23.py), copied byte for byte by patch_f_src.py; v2.2's rule is this
# ---- one with register=False (RULES_BY_SHA below) ----
CLASSES = ("bridge", "cascade", "other", "record", "register")   # v2.3's closed vocabulary, sorted
NORMALISED = frozenset(("bridge", "cascade", "record", "register"))   # "record" when normalisedRecordClass is true
RECORDS = frozenset(("architecture/review-record/briefs.json", "task-packets/README.md",
                     "docs/repositories/00-harness-engineering.md", "docs/MASTER_DEVELOPMENT_PLAN.md"))
TOKEN = re.compile(rb"\d+|[A-Za-z_][A-Za-z_0-9]*|\s+|.", re.S)  # strings split too: a count inside a message is a digit token
CHAIN = re.compile(rb"(?:[A-Za-z_][A-Za-z_0-9]*\.)?\*?(?:successor\.)+(?:NEW_PACKET|PRODUCT_PACKETS)")


def _tokens(raw):
    return TOKEN.findall(raw)


def _member_run(run, new_id):
    """An inserted run that adds exactly one element: a successor chain, or the new id's string."""
    core = b"".join(run).strip()
    core = core[1:].strip() if core.startswith(b",") else core
    core = core[:-1].strip() if core.endswith(b",") else core
    return bool(CHAIN.fullmatch(core)) or core in (b'"%s"' % new_id.encode(), b"'%s'" % new_id.encode())


MEMBER = re.compile(rb"(?:[A-Za-z_][A-Za-z_0-9]*\.)?\*?(?:successor\.)+(?:NEW_PACKET|PRODUCT_PACKETS)")
WS = re.compile(rb"\s+")


def _lines(after, at, remove, insert):
    """The whole lines a hunk touches, after and before it (byte-minimal hunks may cut a token)."""
    start = after.rfind(b"\n", 0, at) + 1
    stop = after.find(b"\n", at + len(remove))
    stop = len(after) if stop < 0 else stop
    return after[start:stop], after[start:at] + insert + after[at + len(remove):stop]


def _shape(tok):
    return b"#" if tok.isdigit() else tok


def _rest_ok(before, after, step):  # step: the allowed moves
    """before -> after differs only by digit tokens moving +step (or equal) and inserted runs of "successor." tokens.
    The common prefix and suffix are matched by shape (digits masked) in linear time, their digit pairs checked, and only
    the differing middle window goes through a sequence match."""
    b = [x for x in _tokens(before) if not x.isspace()]
    a = [x for x in _tokens(after) if not x.isspace()]
    i = 0
    while i < len(b) and i < len(a) and _shape(b[i]) == _shape(a[i]):
        i += 1
    j = 0
    while j < len(b) - i and j < len(a) - i and _shape(b[len(b) - 1 - j]) == _shape(a[len(a) - 1 - j]):
        j += 1
    pairs = list(zip(b[:i], a[:i])) + list(zip(b[len(b) - j:], a[len(a) - j:]))
    for o, n in pairs:
        if o != n and not (o.isdigit() and n.isdigit() and int(n) - int(o) in step):
            return False
    bm, am = b[i:len(b) - j], a[i:len(a) - j]
    if not bm and not am:
        return True
    for tag, a0, a1, b0, b1 in difflib.SequenceMatcher(None, bm, am, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        old, new = bm[a0:a1], am[b0:b1]
        if tag == "replace" and len(old) == len(new) and all(o.isdigit() and n.isdigit() and int(n) - int(o) in step
                                                             for o, n in zip(old, new)):
            continue
        if tag == "insert" and re.fullmatch(rb"(successor\.)+|\.successor|(\.successor)+", b"".join(new)):
            continue
        return False
    return True


# Q-V22-1 (a), MON-V22-Q: "record" is a closed form, one entry for the slot per append position of the file, in that
# position, re-checked by rule; anything else in the four files is "other". The positions, per file:
#   briefs.json: the rider, the last element of "briefs", whose series is "<NEW_ID>/packet";
#   task-packets/README.md: the top section (newest first) and the index row (the file's last line);
#   docs/repositories/00-harness-engineering.md: the top section and the plan item (numbered one past the item above it);
#   docs/MASTER_DEVELOPMENT_PLAN.md: the top section.
FORMS = {"architecture/review-record/briefs.json": ("rider",), "task-packets/README.md": ("top", "row"),
         "docs/repositories/00-harness-engineering.md": ("top", "item"), "docs/MASTER_DEVELOPMENT_PLAN.md": ("top",)}


def record_class(path, after, at, remove, insert, new_id, seen=None):
    """The class of a hunk in one of the four index records: "record" when the forward edit only adds one whole entry
    of one of the file's forms, in its position, naming the slot's packet, and that form has not been seen yet in this
    file; else "other". seen (a set, per file) is updated by the caller's loop, so a second entry of a form is "other"."""
    if insert or not remove:
        return "other"
    before = after[:at] + after[at + len(remove):]
    nid = new_id.encode()
    form = None
    if path.endswith("briefs.json"):
        try:
            a, b = json.loads(after)["briefs"], json.loads(before)["briefs"]
        except (ValueError, KeyError, TypeError):
            return "other"
        if len(a) == len(b) + 1 and a[:-1] == b and isinstance(a[-1], dict) and a[-1].get("series") == new_id + "/packet":
            form = "rider"
    else:
        al, bl = after.splitlines(True), before.splitlines(True)
        ops = [o for o in difflib.SequenceMatcher(None, bl, al, autojunk=False).get_opcodes() if o[0] != "equal"]
        if len(ops) == 1 and ops[0][0] == "insert":
            _, _, _, i, j = ops[0]
            block = al[i:j]
            first = block[0].rstrip(b"\n")
            if len(block) == 1 and re.match(rb"\| \d+ \| `%s` \|" % re.escape(nid), first) and j == len(al):
                form = "row"
            elif len(block) == 1 and re.match(rb"(\d+)\. `%s`" % re.escape(nid), first) and i > 0:
                m, prev = re.match(rb"(\d+)\. ", first), re.match(rb"(\d+)\. `", al[i - 1])
                if prev and int(m.group(1)) == int(prev.group(1)) + 1:
                    form = "item"
        elif len(ops) == 1 and ops[0][0] == "replace" and ops[0][2] - ops[0][1] == 1 and ops[0][4] - ops[0][3] >= 3:
            # the top section: "<#> Current <T> - <PREV ...>" becomes "<#> Current <T> - <NEW_ID ...>", the new body,
            # a blank line, and "<#> Historical <words> - <PREV ...>" with the old heading's tail unchanged
            _, a0, _, i, j = ops[0]
            old, block = bl[a0].rstrip(b"\n"), [l.rstrip(b"\n") for l in al[i:j]]
            dash = b" \xe2\x80\x94 "
            m = re.match(rb"(#+ )Current (.+?)" + dash + rb"(.+)\Z", old)
            if m:
                level, tail = m.group(1), m.group(3)
                head_new = re.match(rb"%sCurrent .+?%s%s\b" % (re.escape(level), dash, re.escape(nid)), block[0])
                head_old = re.match(rb"%sHistorical .+%s%s\Z" % (re.escape(level), dash, re.escape(tail)), block[-1])
                inner = block[1:-1]
                if head_new and head_old and inner and inner[-1] == b"" \
                        and not any(l.startswith(level) for l in inner) \
                        and not any(l.startswith(level + b"Current ") for l in al[:i]):
                    form = "top"
    if form is None or form not in FORMS.get(path, ()):
        return "other"
    if seen is not None:
        if form in seen:
            return "other"
        seen.add(form)
    return "record"


READINESS, PLAN = "scripts/validate_readiness.py", "docs/MASTER_DEVELOPMENT_PLAN.md"
REGISTER_FORMS = {READINESS: "block", PLAN: "status"}
BLOCK = ('    authority_owner.update({path: "%s"\n'
         '                            for path in packets["%s"]["allowedPaths"]\n'
         '                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})\n'
         '    authority_owner["task-packets/%s.yaml"] = "%s"\n')
OWNED = re.compile(rb'    authority_owner\["task-packets/([A-Z0-9-]+)\.yaml"\] = "([A-Z0-9-]+)"\n\Z')


def register_class(path, after, at, remove, insert, new_id, seen=None):
    """v2.3: "register" when the forward edit is exactly this step's registration in one of the two files, in its
    position and once per file; else "other". readiness "block": an insertion of BLOCK for new_id plus zero or more
    product lines owned by new_id, right after a packet's own task-packets line. plan "status": one "- [ ] " line
    becomes itself ticked plus one new "- [ ] " line naming new_id."""
    form = REGISTER_FORMS.get(path)
    if form is None or not remove:
        return "other"
    before = after[:at] + insert + after[at + len(remove):]
    al, bl = after.splitlines(True), before.splitlines(True)
    ops = [o for o in difflib.SequenceMatcher(None, bl, al, autojunk=False).get_opcodes() if o[0] != "equal"]
    if len(ops) != 1:
        return "other"
    tag, a0, a1, i, j = ops[0]
    nid = new_id.encode()
    ok = False
    if form == "block" and tag == "insert" and i > 0:
        block = BLOCK.encode() % (nid, nid, nid, nid)
        lines = al[i:j]
        head = b"".join(lines[:4])
        prev = OWNED.match(al[i - 1])
        ok = (head == block and all((m := OWNED.match(l)) and m.group(2) == nid for l in lines[4:])
              and bool(prev) and prev.group(1) == prev.group(2))
    elif form == "status" and tag == "replace" and a1 - a0 == 1 and j - i == 2:
        old, new0, new1 = bl[a0], al[i], al[i + 1]
        ok = (old.startswith(b"- [ ] ") and new0 == b"- [x] " + old[len(b"- [ ] "):]
              and new1.startswith(b"- [ ] ") and (b" / " + nid + b" \xc2\xb7 ") in new1)
    if not ok:
        return "other"
    if seen is not None:
        if form in seen:
            return "other"
        seen.add(form)
    return "register"


def classify(path, after, at, remove, insert, prev_validator, prev_test, new_id, steps=(1,), seen=None, register=True):
    """The closed class of one reverse hunk (remove: its bytes in AFTER; insert: the BEFORE bytes), judged on the whole
    lines it touches. cascade: before -> after differs only by (a) at most one appended element - a successor chain
    (optionally behind one attribute, starred for PRODUCT_PACKETS) or the new id's string, with its comma - (b) digit
    tokens moving +step and (c) inserted "successor." runs, or it is the (v) tuple form. bridge: any hunk in the previous
    head's validator or test. register (v2.3, register=True): where this would be other, register_class's two forms.
    other: anything else (a real edit)."""
    if path in (prev_validator, prev_test):
        return "bridge"
    if path in RECORDS:
        c = record_class(path, after, at, remove, insert, new_id, seen)
        return register_class(path, after, at, remove, insert, new_id, seen) if c == "other" and register else c
    a_lines, b_lines = _lines(after, at, remove, insert)
    if re.search(rb"==\s*(successor\.)+NEW_PACKET", b_lines) and \
            re.search(rb"in\s*\(\s*(successor\.)+NEW_PACKET,\s*(successor\.)+NEW_PACKET\s*\)", a_lines):
        return "cascade"
    step = frozenset(steps)
    if _rest_ok(b_lines, a_lines, step):
        return "cascade"
    lo = 0
    while lo < min(len(a_lines), len(b_lines)) and a_lines[lo] == b_lines[lo]:
        lo += 1
    hi = 0
    while hi < min(len(a_lines), len(b_lines)) - lo and a_lines[len(a_lines) - 1 - hi] == b_lines[len(b_lines) - 1 - hi]:
        hi += 1
    window = (max(0, lo - 300), len(a_lines) - hi + 300)   # only elements near the differing bytes are candidates
    ids = (b'"%s"' % new_id.encode(), b"'%s'" % new_id.encode())
    spans = [m.span() for m in MEMBER.finditer(a_lines) if m.end() >= window[0] and m.start() <= window[1]] + \
            [(i, i + len(q)) for q in ids for i in _finds(a_lines, q) if window[0] - len(q) <= i <= window[1]]
    for s, e in spans:
        left = re.search(rb",\s*\Z", a_lines[:s])
        right = re.match(rb"\s*,", a_lines[e:])
        for cut in ((left.start(), e) if left else None, (s, e + right.end()) if right else None):
            if cut and _rest_ok(b_lines, a_lines[:cut[0]] + a_lines[cut[1]:], step):
                return "cascade"
    return register_class(path, after, at, remove, insert, new_id, seen) if register else "other"


def _finds(raw, needle):
    i = raw.find(needle)
    while i >= 0:
        yield i
        i = raw.find(needle, i + 1)


# ---- end of the copied rule; its NORMALISED constant is not used here: normalised() decides ----
# ---- chainmech v2.4's class rule (hunk_class_v24.py; CONTRACT_286 r3 section 3.1), copied byte for byte into the
# ---- reader after v2.3's rule; it reuses v2.3's _tokens, _lines, _shape, MEMBER, _finds, record_class and register_class.
# R1 (283-D4; MP049-C1-2): a member insertion is cascade only in form F1 (one successor...NEW_PACKET chain, K = 0 only),
#   F2 (the NEW_PACKET chain then the *...PRODUCT_PACKETS chain, K >= 1 only) or F3 (an id line gains the new id, then
#   at K >= 1 the authority's product ids in the key order of its productPackets).
# R2 (VIS-285-RULE (a)): a digit move is cascade only when every (before, after) pair is declared: the catalog pair
#   (n, n + steps[1]), n the authority's baselinePackets size, or a pair of the context's countPairs.
# W (Q-286-3 (a)): a hunk in ci/parallel_suite_weights.json is class record when it only inserts entries, each key a
#   test file the authority's newFiles adds and not already a key, every existing entry byte-equal; a re-measure or a
#   duplicate key is other.
V24_WEIGHTS = "ci/parallel_suite_weights.json"
V24_CHAIN_NEW = rb"(?:[A-Za-z_][A-Za-z_0-9]*\.)?(?:successor\.)+NEW_PACKET"
V24_CHAIN_PROD = rb"(?:[A-Za-z_][A-Za-z_0-9]*\.)?\*(?:successor\.)+PRODUCT_PACKETS"
V24_F2 = re.compile(V24_CHAIN_NEW + rb"\s*,\s*" + V24_CHAIN_PROD)
V24_F1 = re.compile(V24_CHAIN_NEW)
V24_ENTRY = re.compile(rb'^\s*"([^"]+)"\s*:\s*-?[0-9][0-9.eE+-]*\s*,?\s*$')


def _rest_ok_v24(before, after, pairs):
    """before -> after differs only by digit tokens moving along a declared (before, after) pair (or equal) and by
    inserted "successor." runs. The prefix and suffix are matched by shape (digits masked), as v2.3's _rest_ok does."""
    b = [x for x in _tokens(before) if not x.isspace()]
    a = [x for x in _tokens(after) if not x.isspace()]
    i = 0
    while i < len(b) and i < len(a) and _shape(b[i]) == _shape(a[i]):
        i += 1
    j = 0
    while j < len(b) - i and j < len(a) - i and _shape(b[len(b) - 1 - j]) == _shape(a[len(a) - 1 - j]):
        j += 1
    moved = list(zip(b[:i], a[:i])) + list(zip(b[len(b) - j:], a[len(a) - j:]))
    for o, n in moved:
        if o != n and not (o.isdigit() and n.isdigit() and (int(o), int(n)) in pairs):
            return False
    bm, am = b[i:len(b) - j], a[i:len(a) - j]
    if not bm and not am:
        return True
    for tag, a0, a1, b0, b1 in difflib.SequenceMatcher(None, bm, am, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        old, new = bm[a0:a1], am[b0:b1]
        if tag == "replace" and len(old) == len(new) and all(o.isdigit() and n.isdigit() and (int(o), int(n)) in pairs
                                                             for o, n in zip(old, new)):
            continue
        if tag == "insert" and re.fullmatch(rb"(successor\.)+|\.successor|(\.successor)+", b"".join(new)):
            continue
        return False
    return True


def _v24_id_run(ids):
    """F3's run: the given ids in order, each quoted (one quote kind for the run), comma-separated."""
    for q in (b'"', b"'"):
        yield re.compile(rb"\s*,\s*".join(re.escape(q + i.encode() + q) for i in ids))


def weights_class_v24(after, at, remove, insert, new_tests):
    """W: record when the forward edit only inserts whole entry lines whose keys are new test files of this step (each
    key once in the file) and leaves every existing entry byte-equal but for a trailing comma on the line before;
    other otherwise (a re-measure, a duplicate key, anything else)."""
    a_lines, b_lines = _lines(after, at, remove, insert)
    al, bl = a_lines.split(b"\n"), b_lines.split(b"\n")
    for tag, i0, i1, j0, j1 in difflib.SequenceMatcher(None, bl, al, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and i1 - i0 == 1 and j1 - j0 >= 1:
            old, first = bl[i0], al[j0]
            if first.rstrip() != old.rstrip() + b"," or not V24_ENTRY.match(old):   # the line before gains one comma
                return "other"
            added = al[j0 + 1:j1]
        elif tag == "insert":
            added = al[j0:j1]
        else:
            return "other"
        for line in added:
            m = V24_ENTRY.match(line)
            if not m or m.group(1).decode("utf-8", "replace") not in new_tests:
                return "other"
            if len(list(_finds(after, b'"%s"' % m.group(1)))) != 1:    # a duplicate key would override an entry
                return "other"
    return "record"


def classify_v24(path, after, at, remove, insert, ctx, seen=None):
    """The closed v2.4 class of one reverse hunk. ctx: prevValidator, prevTest, newPacket, products (the authority's
    productPackets keys in order), steps, pairs (the declared (before, after) digit pairs, the catalog pair included)
    and newTests (the step's new test files)."""
    if path in (ctx["prevValidator"], ctx["prevTest"]):
        return "bridge"
    new_id, products, k = ctx["newPacket"], list(ctx["products"]), len(ctx["products"])
    if path == V24_WEIGHTS:
        return weights_class_v24(after, at, remove, insert, frozenset(ctx["newTests"]))
    if path in RECORDS:
        c = record_class(path, after, at, remove, insert, new_id, seen)
        return register_class(path, after, at, remove, insert, new_id, seen) if c == "other" else c
    a_lines, b_lines = _lines(after, at, remove, insert)
    if re.search(rb"==\s*(successor\.)+NEW_PACKET", b_lines) and \
            re.search(rb"in\s*\(\s*(successor\.)+NEW_PACKET,\s*(successor\.)+NEW_PACKET\s*\)", a_lines):
        return "cascade"
    pairs = frozenset(tuple(p) for p in ctx["pairs"])
    if _rest_ok_v24(b_lines, a_lines, pairs):
        return "cascade"
    lo = 0
    while lo < min(len(a_lines), len(b_lines)) and a_lines[lo] == b_lines[lo]:
        lo += 1
    hi = 0
    while hi < min(len(a_lines), len(b_lines)) - lo and a_lines[len(a_lines) - 1 - hi] == b_lines[len(b_lines) - 1 - hi]:
        hi += 1
    window = (max(0, lo - 300), len(a_lines) - hi + 300)
    if k == 0:
        forms = [V24_F1] + list(_v24_id_run([new_id]))
    else:
        forms = [V24_F2] + list(_v24_id_run([new_id] + products))
    for form in forms:
        for m in form.finditer(a_lines):
            s, e = m.span()
            if e < window[0] or s > window[1]:
                continue
            if form is V24_F1 and a_lines[max(0, s - 1):s] == b"*":
                continue
            left = re.search(rb",\s*\Z", a_lines[:s])
            right = re.match(rb"\s*,", a_lines[e:])
            for cut in ((left.start(), e) if left else None, (s, e + right.end()) if right else None):
                if cut and _rest_ok_v24(b_lines, a_lines[:cut[0]] + a_lines[cut[1]:], pairs):
                    return "cascade"
    return register_class(path, after, at, remove, insert, new_id, seen)
# ---- end of chainmech v2.4's class rule ----
VOCABULARY_V22 = ("bridge", "cascade", "other", "record")   # chainmech v2.2's closed vocabulary
RULES_BY_SHA = {RULE_V22_SHA256: (VOCABULARY_V22, False), RULE_SHA256: (CLASSES, True),
                RULE_V24_SHA256: (CLASSES, True)}   # (vocabulary, register); v2.4 classifies by classify_v24


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fault(Exception):
    """A class-C fault: the reader's own or the records'."""


class Corrupt(Fault):
    """C3-1: the ledger or the authority set is malformed: class C, kind corrupt, set by cause."""


class OverBudget(Exception):
    """The in-run budget is spent: the rest of the replay is skipped and recorded as class C, kind over-budget."""


def _read(root, path):
    p = root / path
    try:
        return p.read_bytes() if p.is_file() and not p.is_symlink() else None
    except OSError:
        return None


def _authorities(root, budget=None):
    """Every architecture/*-authority.json, parsed once: [(baseline catalog size, path, record)]. An authority that
    does not parse, is not an object, or whose baselinePackets, changedFiles or newFiles is not an object is Corrupt,
    naming the file and the member (P047-C4-1): never skipped."""
    out = []
    for p in sorted((root / "architecture").glob("*-authority.json")):
        if budget:
            budget()
        rel = p.relative_to(root).as_posix()
        try:
            rec = json.loads(p.read_bytes())
        except (OSError, ValueError):
            raise Corrupt("authority %s does not parse" % rel) from None
        if not isinstance(rec, dict):
            raise Corrupt("authority %s is not an object" % rel)
        for key in ("baselinePackets", "changedFiles", "newFiles"):
            if not isinstance(rec.get(key, {}), dict):
                raise Corrupt("authority %s %s is not an object" % (rel, key))
        out.append((len(rec.get("baselinePackets", {})), rel, rec))
    return out


def naming_authority(root, live_sha, budget=None, auths=None):
    """(authority path, verdict): the newest authority, by baseline, that names the record in newFiles or changedFiles,
    and whether it names the live digest ("named", "stale") or none names it ("unnamed")."""
    naming = []
    for n, path, rec in (auths if auths is not None else _authorities(root, budget)):
        entry = rec.get("changedFiles", {}).get(RECORD_PATH, {})
        if not isinstance(entry, dict):
            raise Corrupt("authority %s changedFiles[%s] is not an object" % (path, RECORD_PATH))
        named = rec.get("newFiles", {}).get(RECORD_PATH) or entry.get("afterSha256")
        if named:
            naming.append((n, path, named))
    if not naming:
        return None, "unnamed"
    n, path, named = max(naming)
    return path, ("named" if named == live_sha else "stale")


def _hunk_class_records(root, budget=None):
    """MON-282-W1-A2: every hunk-class record, {path: (sha256 of its bytes, its parsed object or None)}. Never a
    refusal here: a record that does not parse, and an entry that is a link, not a file or unreadable ((None, None),
    read as _read reads, P047-C6-5), are judged only when an authority names them (class A)."""
    out = {}
    for p in sorted((root / HUNK_CLASSES_DIR).glob("*.json")):
        if budget:
            budget()
        rel = p.relative_to(root).as_posix()
        raw = _read(root, rel)
        if raw is None:
            out[rel] = (None, None)
            continue
        try:
            side = json.loads(raw)
        except ValueError:
            side = None
        out[rel] = (_sha(raw), side)
    return out


def attach_classes(apath, rec, sides):
    """MON-282-W1-A2: the authority with its hunk-class record attached, in memory: its vocabulary, rule sha256 and
    context, and each hunk's class in the authority's reverseHunks order. The authority's newFiles names exactly one
    record, whose bytes hash to the named digest and whose authorityPath is the authority's (condition 2'). A binding
    fault is kept as hunkClassBinding, which bind_context reports first (class A); nothing on disk is changed."""
    def bad(reason):
        return dict(rec, hunkClassBinding=reason)
    changed = rec.get("changedFiles", {})
    if any(k in rec for k in CLASS_MEMBERS) or any(isinstance(e, dict) and isinstance(e.get("reverseHunks"), list)
                                                  and any(isinstance(h, dict) and "class" in h for h in e["reverseHunks"])
                                                  for e in changed.values()):
        return bad("the authority carries hunk classes itself (MON-282-W1-A2: only its hunk-class record does)")
    named = sorted(p for p in rec.get("newFiles", {}) if p.startswith(HUNK_CLASSES_DIR + "/"))
    if not named:
        return bad("the authority's newFiles names no hunk-class record")
    if len(named) != 1:
        return bad("the authority's newFiles names %d hunk-class records" % len(named))
    if named[0] not in sides:
        return bad("the hunk-class record the authority names is missing")
    side_sha, side = sides[named[0]]
    if side_sha is None:
        return bad("the hunk-class record the authority names is a link, not a file, or unreadable")
    if rec["newFiles"][named[0]] != side_sha:
        return bad("the hunk-class record's bytes do not hash to the authority's digest")
    if not isinstance(side, dict):
        return bad("the hunk-class record does not parse as an object")
    members = SIDE_MEMBERS_V24 if side.get("hunkClassRuleSha256") == RULE_V24_SHA256 else SIDE_MEMBERS
    if set(side) != members:
        return bad("the hunk-class record's members are not the closed set")
    if members is SIDE_MEMBERS_V24:
        broken = statements_fault(side["outcomeStatements"], changed)
        if broken:
            return bad("outcomeStatements: " + broken)
    if side["authorityPath"] != apath:
        return bad("the hunk-class record names another authority")
    if sum(1 for _, s in sides.values() if isinstance(s, dict) and s.get("authorityPath") == apath) != 1:
        return bad("more than one hunk-class record names this authority")
    classes = side["classes"]
    if not (isinstance(classes, dict) and set(classes) == set(changed)):
        return bad("the hunk-class record does not cover exactly the authority's changed files")
    merged = {}
    for path, entry in changed.items():
        listed = classes[path]
        if not (isinstance(listed, list) and all(isinstance(c, str) for c in listed)):
            return bad("the hunk-class record's classes for %s are not a list of strings" % path)
        hunks = entry.get("reverseHunks") if isinstance(entry, dict) else None
        if not isinstance(hunks, list):
            merged[path] = entry          # entry_fault refuses it in rebuild (corrupt)
            continue
        if len(listed) != len(hunks):
            return bad("the hunk-class record's count for %s is not the authority's hunk count" % path)
        merged[path] = dict(entry, reverseHunks=[dict(h, **{"class": c}) if isinstance(h, dict) else h
                                                 for h, c in zip(hunks, listed)])
    out = dict(rec, changedFiles=merged)
    for key in CLASS_MEMBERS:
        out[key] = side[key]
    if members is SIDE_MEMBERS_V24:
        out["outcomeStatements"] = side["outcomeStatements"]
    return out


HEX64 = re.compile(r"[0-9a-f]{64}")


def statements_fault(statements, changed):
    """286 C1-5: a v2.4 record's outcomeStatements, a list (may be empty) of exactly {layerSlot, path, nodeSha256s}:
    layerSlot an int, path a key of the authority's changedFiles, nodeSha256s a non-empty list of distinct 64-hex, no
    two entries sharing (layerSlot, path). Returns the fault, or None."""
    if not isinstance(statements, list):
        return "not a list"
    seen = set()
    for i, s in enumerate(statements):
        if not (isinstance(s, dict) and set(s) == {"layerSlot", "path", "nodeSha256s"}):
            return "entry %d is not exactly {layerSlot, path, nodeSha256s}" % i
        nodes = s["nodeSha256s"]
        if type(s["layerSlot"]) is not int or not isinstance(s["path"], str) or s["path"] not in changed:
            return "entry %d layerSlot or path" % i
        if not (isinstance(nodes, list) and nodes and all(isinstance(x, str) and HEX64.fullmatch(x) for x in nodes)
                and len(set(nodes)) == len(nodes)):
            return "entry %d nodeSha256s" % i
        if (s["layerSlot"], s["path"]) in seen:
            return "entry %d repeats (layerSlot, path)" % i
        seen.add((s["layerSlot"], s["path"]))
    return None


def newer_authorities(root, baseline, budget=None, auths=None, sides=None):
    out = [(n, path, rec) for n, path, rec in (auths if auths is not None else _authorities(root, budget)) if n > baseline]
    out.sort(key=lambda t: -t[0])
    by_size, by_packet = {}, {}
    for n, path, _ in out:     # P047-ORACLE-B3: a conflict names both authorities
        if n in by_size:
            raise Corrupt("two newer authorities share a baseline size: %s and %s" % (by_size[n], path))
        by_size[n] = path
    for _, path, rec in out:
        packet = rec.get("authorityPacket")
        if not (isinstance(packet, str) and packet):
            raise Corrupt("authority %s authorityPacket" % path)
        if packet in by_packet:
            raise Corrupt("two newer authorities name one authorityPacket (one authority per slot, P047-C4-2): %s and %s"
                          % (by_packet[packet], path))
        by_packet[packet] = path
    if not out:
        return out
    sides = sides if sides is not None else _hunk_class_records(root, budget)     # MON-282-W1-A
    return [(n, path, attach_classes(path, rec, sides)) for n, path, rec in out]


def bind_context(apath, rec):
    """C1-6: the authority's class vocabulary, rule digest and step context (from its hunk-class record, attached by
    attach_classes), before any of its classes is trusted."""
    if rec.get("hunkClassBinding"):     # MON-282-W1-A2, condition 2': a binding fault is class A
        return rec["hunkClassBinding"]
    ctx = rec.get("hunkClassContext")
    v24 = rec.get("hunkClassRuleSha256") == RULE_V24_SHA256
    if not (isinstance(ctx, dict) and set(ctx) == (CONTEXT_KEYS_V24 if v24 else CONTEXT_KEYS)):
        return "hunkClassContext missing or malformed"
    if ctx["newPacket"] != rec.get("authorityPacket"):
        return "hunkClassContext.newPacket is not the authority's packet"
    if not isinstance(rec.get("productPackets", {}), dict):     # a bad class context stays class A (P047-C5-2)
        return "productPackets is not an object"
    if ctx["steps"] != [1, 1 + len(rec.get("productPackets", {}))]:
        return "hunkClassContext.steps is not [1, 1 + K]"
    rule_sha = rec.get("hunkClassRuleSha256")
    rule = RULES_BY_SHA.get(rule_sha) if isinstance(rule_sha, str) else None
    if rule is None:     # MON-282-W2-RULED: the record's rule picks its vocabulary and whether register is decided
        return "hunkClassRuleSha256 is not a rule the reader holds (v2.2, v2.3 or v2.4)"
    if rec.get("hunkClassVocabulary") != list(rule[0]):
        return "hunkClassVocabulary is not the closed vocabulary of its rule"
    if v24:     # 286 3.1: countPairs, distinct integer pairs each moving by steps[1], never the catalog pair
        pairs, step = ctx["countPairs"], ctx["steps"][1]
        catalog = [len(rec.get("baselinePackets", {})), len(rec.get("baselinePackets", {})) + step]
        if not (isinstance(pairs, list) and all(isinstance(p, list) and len(p) == 2 and all(type(x) is int for x in p)
                                                and p[1] - p[0] == step for p in pairs)
                and len({tuple(p) for p in pairs}) == len(pairs) and catalog not in pairs):
            return "hunkClassContext.countPairs is malformed"
    return None


def context_v24(rec, ctx):
    """classify_v24's inputs from an attached v2.4 authority: the catalog pair from its own baselinePackets size."""
    n = len(rec.get("baselinePackets", {}))
    return {"prevValidator": ctx["prevValidator"], "prevTest": ctx["prevTest"], "newPacket": ctx["newPacket"],
            "products": list(rec.get("productPackets", {})), "steps": ctx["steps"],
            "pairs": [[n, n + ctx["steps"][1]]] + [list(p) for p in ctx["countPairs"]],
            "newTests": [p for p in rec.get("newFiles", {}) if p.startswith("tests/") and p.endswith(".py")]}


def normalised(record):
    extra = ("record",) if record.get("normalisedRecordClass") is True else ()
    return frozenset(("bridge", "cascade", "register") + extra)


def check_ledger(record):
    """C3-1: the ledger's shape, member by member. A malformed ledger is Corrupt (kind corrupt), naming the member."""
    def need(ok, member):
        if not ok:
            raise Corrupt("ledger %s" % member)
    need(isinstance(record, dict), "is not an object")
    need(record.get("schemaVersion") == SCHEMA, "schemaVersion")
    for key in ("checkpointSlot", "checkpointBaseline"):
        need(type(record.get(key)) is int, key)
    params = record.get("parameters")
    need(isinstance(params, dict), "parameters is not an object")
    need(params.get("shadowIn", "verify") in ("verify", "dryRunOnly"), "parameters.shadowIn")
    need(type(params.get("sampleFraction")) in (int, float) and 0 <= params["sampleFraction"] <= 1, "parameters.sampleFraction")
    need(isinstance(record.get("layers"), list), "layers is not a list")
    for i, layer in enumerate(record["layers"]):
        need(isinstance(layer, dict) and type(layer.get("slot")) is int, "layers[%d].slot" % i)
        for key in ("validatorPath", "validatorSha256", "authorityPath", "authoritySha256") + (
                ("testFilePath", "testFileSha256") if "testFilePath" in layer else ()):
            need(isinstance(layer.get(key), str), "layers[%d].%s" % (i, key))
        need(isinstance(layer.get("inputs"), dict)
             and all(isinstance(k, str) and isinstance(v, str) for k, v in layer["inputs"].items()), "layers[%d].inputs" % i)
        need(isinstance(layer.get("nodes"), list)
             and all(isinstance(n, dict) and isinstance(n.get("nodeSha256"), str) for n in layer["nodes"]), "layers[%d].nodes" % i)
    pairs = record.get("checkPairs", [])
    need(isinstance(pairs, list), "checkPairs is not a list")
    for i, e in enumerate(pairs):
        need(isinstance(e, dict) and type(e.get("layerSlot")) is int and isinstance(e.get("type"), str)
             and isinstance(e.get("ids"), list) and all(isinstance(x, str) for x in e["ids"]), "checkPairs[%d]" % i)
    if "exclusion" in record:     # MON-282-W2-RULED: the step's own products, never an attested input
        ex = record["exclusion"]
        need(isinstance(ex, dict) and set(ex) == EXCLUSION_MEMBERS, "exclusion is not {files, pinLine}")
        need(isinstance(ex["files"], list) and all(isinstance(p, str) for p in ex["files"])
             and ex["files"] == sorted(set(ex["files"])), "exclusion.files")
        need(isinstance(ex["pinLine"], str), "exclusion.pinLine")
        for i, layer in enumerate(record["layers"]):
            need(not set(ex["files"]) & set(layer["inputs"]), "layers[%d].inputs names an excluded file" % i)


def head_slot(record, auths):
    """C3-2: the head's chain slot: checkpointSlot plus the authorities newer than the checkpoint by baseline (one per
    slot; the newest is the head's)."""
    return record["checkpointSlot"] + sum(1 for n, _, _ in auths if n > record["checkpointBaseline"])


def entry_fault(entry):
    """P047-C4-1: the member a changedFiles entry breaks, or None."""
    if not isinstance(entry, dict):
        return "the entry is not an object"
    for key in ("afterSha256", "beforeSha256"):
        if not isinstance(entry.get(key), str):
            return key
    hunks = entry.get("reverseHunks")
    if not isinstance(hunks, list):
        return "reverseHunks is not a list"
    for i, h in enumerate(hunks):
        if not (isinstance(h, dict) and type(h.get("at")) is int and h["at"] >= 0
                and isinstance(h.get("removeBase64"), str) and isinstance(h.get("insertBase64"), str)):
            return "reverseHunks[%d]" % i
        try:
            base64.b64decode(h["removeBase64"], validate=True)
            base64.b64decode(h["insertBase64"], validate=True)
        except ValueError:
            return "reverseHunks[%d] base64" % i
        if "class" in h and not isinstance(h["class"], str):
            return "reverseHunks[%d].class" % i
    return None


def _recheck(path, cur, apath, rec, entry, classes):
    """The recorded classes of one authority's hunks on path, each re-checked by the record's rule, in order; the
    L1 cache (classes = (authority sha256 by path, cache)) holds a completed pass only. Returns (keep, detail): keep
    the [(at, remove, insert, class)] list, or None with the detail that stops the replay."""
    ctx = rec["hunkClassContext"]
    key = None
    if classes is not None and apath in classes[0]:
        key = (classes[0][apath], path)
    hit = classes[1].get(key) if key else None
    keep, seen, prior = [], set(), -1
    v24 = rec["hunkClassRuleSha256"] == RULE_V24_SHA256
    c24 = context_v24(rec, ctx) if v24 else None
    register = RULES_BY_SHA[rec["hunkClassRuleSha256"]][1]
    for i, h in enumerate(entry["reverseHunks"]):
        if h["at"] <= prior:
            return None, "reverse hunks out of order"
        prior = h["at"]
        rm, ins = base64.b64decode(h["removeBase64"]), base64.b64decode(h["insertBase64"])
        if cur[h["at"]:h["at"] + len(rm)] != rm:
            return None, "a hunk does not apply byte-exactly"
        cls = h.get("class")
        if hit is not None:
            again = hit[i]
        elif v24:
            again = classify_v24(path, cur, h["at"], rm, ins, c24, seen=seen)
        else:
            again = classify(path, cur, h["at"], rm, ins, ctx["prevValidator"], ctx["prevTest"], ctx["newPacket"],
                             tuple(ctx["steps"]), seen=seen, register=register)
        if cls != again:
            return None, "recorded class %s fails the re-check (%s)" % (cls, again)
        keep.append((h["at"], rm, ins, cls))
    if key and hit is None:
        classes[1][key] = tuple(k[3] for k in keep)
    return keep, None


def rebuild(path, live, newer, norm, budget=None, classes=None):
    """The bytes of path at the checkpoint tree, undoing newest first each newer authority's normalised hunks.
    Returns (bytes, reverted [(authority, {class: count})], unexplained [(authority, detail)]). budget() raises
    OverBudget when the in-run budget is spent. classes: the Reader's L1 cache, or None."""
    cur, reverted, unexplained = live, [], []
    for _, apath, rec in newer:
        if budget:
            budget()
        entry = rec.get("changedFiles", {}).get(path)
        if entry is None:
            if path in rec.get("newFiles", {}):
                unexplained.append((apath, "added after the checkpoint"))
            continue
        broken = entry_fault(entry)
        if broken:
            raise Corrupt("authority %s, %s: %s" % (apath, path, broken))
        bad = bind_context(apath, rec)
        if bad:
            unexplained.append((apath, bad))
            return cur, reverted, unexplained
        pending = len(entry["reverseHunks"])
        if _sha(cur) != entry["afterSha256"]:
            share = sum(1 for h in entry["reverseHunks"] if h.get("class") in norm)
            unexplained.append((apath, "afterSha256 differs before the replay; recorded cascade share %d of %d hunks" % (share, pending)))
            return cur, reverted, unexplained
        keep, detail = _recheck(path, cur, apath, rec, entry, classes)
        if keep is None:
            unexplained.append((apath, detail))
            return cur, reverted, unexplained
        undo = [k for k in keep if k[3] in norm]
        for at, rm, ins, _ in sorted(undo, key=lambda k: -k[0]):
            cur = cur[:at] + ins + cur[at + len(rm):]
        counts = {}
        for k in keep:
            counts[k[3]] = counts.get(k[3], 0) + 1
        reverted.append((apath, counts))
        if len(undo) != len(keep):
            unexplained.append((apath, "%d of %d hunks of a class not normalised" % (len(keep) - len(undo), len(keep))))
            return cur, reverted, unexplained
        if _sha(cur) != entry["beforeSha256"]:
            unexplained.append((apath, "beforeSha256 differs after the replay"))
            return cur, reverted, unexplained
    return cur, reverted, unexplained


AUTHORED = re.compile(r"^\d+ of \d+ hunks of a class not normalised$")


def landing(path, live, newer, digest, pin, budget=None, classes=None):
    """286 3.11 (C1-4): the continued replay. Every newer authority naming path, newest first, gates kept (afterSha256 at
    the replay point, order, byte-exact apply, the class re-check, beforeSha256 after its full undo), with ALL its hunks
    undone, the class-other ones included; the final bytes (pin-normalised for the pin file) must equal the attested
    digest. Returns (True, the newest authority with a class-other hunk) on an exact landing, else (False, detail)."""
    cur, demoting = live, None
    for _, apath, rec in newer:
        if budget:
            budget()
        entry = rec.get("changedFiles", {}).get(path)
        if entry is None:
            if path in rec.get("newFiles", {}):
                return False, "%s: added after the checkpoint" % apath
            continue
        if entry_fault(entry) or bind_context(apath, rec):
            return False, "%s: the entry or its binding fails" % apath
        if _sha(cur) != entry["afterSha256"]:
            return False, "%s: afterSha256 differs at the replay point" % apath
        keep, detail = _recheck(path, cur, apath, rec, entry, classes)
        if keep is None:
            return False, "%s: %s" % (apath, detail)
        if demoting is None and any(k[3] == "other" for k in keep):
            demoting = apath
        for at, rm, ins, _ in sorted(keep, key=lambda k: -k[0]):
            cur = cur[:at] + ins + cur[at + len(rm):]
        if _sha(cur) != entry["beforeSha256"]:
            return False, "%s: beforeSha256 differs after the full undo" % apath
    if path == pin:
        cur = pin_normalised(cur, cur)
    if _sha(cur) != digest or demoting is None:
        return False, "the continued replay does not land on the checkpoint digest"
    return True, demoting


def signal_check(root, home, head_of):
    """P-048-3 (T1, MP049-C1-14): the verifier's signal file under HOME. Returns (None, None) when absent (or HOME unset),
    (fields, None) when every rule holds, or (None, the failed check). Rules: opened with O_NOFOLLOW, fstat on that
    descriptor (a regular file, uid 0, no group or world write bit, nlink 1, at most SIGNAL_MAX bytes), at most
    SIGNAL_MAX + 1 bytes read, I-JSON (duplicate keys refused) with exactly SIGNAL_FIELDS in their forms, head equal to
    the checkout's HEAD, the ledger's and the G1 module's digests equal to the live files'."""
    import stat as _stat
    if not home:
        return None, None
    path = os.path.join(home, SIGNAL_RELATIVE)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "the signal file cannot be opened without following a link"
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            return None, "the signal file is not a regular file"
        if st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1 or st.st_size > SIGNAL_MAX:
            return None, "the signal file fails the owner, mode, link or size rule"
        raw = os.read(fd, SIGNAL_MAX + 1)
    finally:
        os.close(fd)
    if len(raw) > SIGNAL_MAX:
        return None, "the signal file is over %d bytes" % SIGNAL_MAX

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError):
        return None, "the signal file is not I-JSON"
    if not (isinstance(doc, dict) and set(doc) == SIGNAL_FIELDS and all(isinstance(doc[k], str) for k in doc)
            and HEX64.fullmatch(doc["ledgerSha256"]) and HEX64.fullmatch(doc["g1ModuleSha256"])
            and re.fullmatch(r"[0-9a-f]{40}", doc["head"]) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", doc["bundleId"])):
        return None, "the signal file's fields or their forms"
    try:
        head = head_of()
    except Exception:
        return None, "the head is unavailable"
    if doc["head"] != head:
        return None, "the signal file names another head"
    if doc["ledgerSha256"] != _sha(_read(root, RECORD_PATH) or b"") or doc["g1ModuleSha256"] != _sha(_read(root, G1_MODULE) or b""):
        return None, "the signal file names another ledger or G1 module"
    return doc, None


def unauthored(reverted, unexplained):
    """C3-4 (a): the file's only miss is at its newest recorded step: no newer step replayed, and either no newer
    authority names it, or the first that does fails its afterSha256 before any hunk is applied."""
    return not reverted and (not unexplained or (len(unexplained) == 1 and unexplained[0][1].startswith(UNAUTHORED_MISS)))


def pin_normalised(raw, default=None):
    """MON-282-W2-RULED: the head validator's bytes with its one AUTHORITY_SHA256 pin line set to PIN_PLACEHOLDER, as
    the writer attests it (the pin is filled after the ledger is written); default when the line is not exactly one."""
    if len(re.findall(PIN_LINE_PATTERN, raw, re.M)) != 1:
        return default
    return re.sub(PIN_LINE_PATTERN, lambda m: PIN_PLACEHOLDER, raw, count=1, flags=re.M)


RULED_PAIR_TYPES = frozenset(("supersession",))


def check_pairs(entries):
    """V006-P2-2: each entry two distinct ids and a ruled pair type; no entry repeated. Returns the faults, each naming
    the ledger and the entry (P047-ORACLE-B2)."""
    seen, faults = set(), []
    for i, e in enumerate(entries):
        ids = e.get("ids")
        if not (isinstance(ids, list) and len(ids) == 2 and ids[0] != ids[1]) or e.get("type") not in RULED_PAIR_TYPES:
            faults.append("ledger checkPairs[%d]: self-paired, not a pair, or unruled (slot %s)" % (i, e.get("layerSlot")))
            continue
        key = (e.get("layerSlot"), tuple(sorted(ids)))
        if key in seen:
            faults.append("ledger checkPairs[%d]: repeated (slot %s)" % (i, e.get("layerSlot")))
        seen.add(key)
    return faults


def sample(tree_id, slots, fraction):
    return sorted(s for s in slots if int(_sha(tree_id.encode() + b"\0" + str(s).encode()), 16) < fraction * 2 ** 256)


def _git(root, *args):
    out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=5)
    value = out.stdout.strip()
    if out.returncode or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise Fault("git %s unavailable" % args[-1])
    return value


def node_hash(nodeid):
    return _sha(nodeid.encode("utf-8"))


def _workers(root):
    raw = _read(root, "ci/parallel_suite.py") or b""
    m = re.search(rb"^WORKERS = (\d+)$", raw, re.M)
    return (int(m.group(1)), "ci/parallel_suite.py WORKERS") if m else (None, "unavailable")


class Reader:
    """One shadow run for one outermost session. Every public method records faults instead of raising them."""

    def __init__(self, root=ROOT, clock=time.monotonic, cap=CAP_SECONDS, tree=None, in_dry_run=False, cache=True):
        self.root, self.clock, self.cap, self.tree, self.in_dry_run = Path(root), clock, cap, tree, in_dry_run
        self.cache = cache     # 286 3.4: a test-only flag; False runs the same reading with no L1 and no L2
        self._l1, self._l2, self._land, self._auth_sha, self._newer = {}, {}, {}, {}, []
        self.demoted, self._demoted_slots, self.isolation = [], {}, []
        self.g1, self.mode_of_record = None, "shadow"
        self.active, self.spent, self.record, self.mode = False, 0.0, None, "inactive"
        self.disagreements, self.reverted, self.layers, self.unauthored = [], {}, {}, set()
        self.live, self.durations, self.sampled, self.naming, self.over_cap = {}, {}, [], None, False
        self._t0 = 0.0
        self._clock_fault, self._last_clock = False, 0.0
        self.head_slot, self.ckpt_slot, self.ledger_state = None, None, None

    def _budget(self):
        if self.spent + (self._now() - self._t0) > self.cap:
            raise OverBudget()

    def _now(self):
        """P047-ORACLE-B1: the clock, never raising. A clock that raises, or reads as no finite number, is one class-C
        fault per reading ("the clock failed"); its last good reading stands in from then on."""
        if not self._clock_fault:
            try:
                value = float(self.clock())
                if math.isfinite(value):
                    self._last_clock = value
                    return value
                raise ValueError("not a finite number")
            except Exception as exc:
                self._clock_fault = True
                self.disagreements.append((self.head_slot, "reader", "C", "%s: the clock failed: %s; %s"
                                           % (type(exc).__name__, str(exc)[:120], self._slots()), "fault"))
        return self._last_clock

    def _slots(self):
        if self.head_slot is None:
            return "head slot unknown (%s)" % (self.ledger_state or "the ledger was not read")     # P047-C4-2, P047-C5-5
        return "head slot %s, checkpoint slot %s" % (self.head_slot, self.ckpt_slot)

    def _timed(self, fn, *args):
        self._t0 = start = self._now()
        try:
            return fn(*args)
        except OverBudget:
            self.over_cap = True
            self.disagreements.append((self.head_slot, "reader", "C", "over budget: the replay stopped at %.0f s; the dry-run path; %s"
                                       % (self.cap, self._slots()), "over-budget"))
        except Exception as exc:
            kind = "corrupt" if isinstance(exc, Corrupt) else "fault"     # C3-1: by cause
            self.disagreements.append((self.head_slot, "reader", "C", "%s: %s; %s" % (type(exc).__name__, str(exc)[:200], self._slots()), kind))
        finally:
            self.spent += self._now() - start

    def start(self):
        self._timed(self._start)

    def _start(self):
        raw = _read(self.root, RECORD_PATH)
        if raw is None:
            return
        self.active = True
        self._budget()
        auths = _authorities(self.root, self._budget)      # parsed once, inside the budget
        self._auth_sha = {rel: _sha(_read(self.root, rel) or b"") for _, rel, _ in auths}     # L1's keys
        self.naming, verdict = naming_authority(self.root, _sha(raw), auths=auths)
        if verdict != "named":
            self.disagreements.append((None, RECORD_PATH, "A", "the record is %s (vector 2)" % verdict, "stale"))
            return
        try:
            record = json.loads(raw)
        except ValueError:
            self.ledger_state = "the ledger is not JSON"
            raise Corrupt("ledger is not JSON") from None
        if not isinstance(record, dict):
            self.ledger_state = "the ledger is not an object"
        elif type(record.get("checkpointSlot")) is int and type(record.get("checkpointBaseline")) is int:
            self.ckpt_slot, self.head_slot = record["checkpointSlot"], head_slot(record, auths)
        else:
            self.ledger_state = "the ledger's checkpointSlot or checkpointBaseline is malformed"
        check_ledger(record)
        self.record = record
        newer = newer_authorities(self.root, record["checkpointBaseline"], self._budget, auths=auths)     # before the skip (P047-C5-1)
        self._newer = newer          # L2's invariant: one newer set per invocation, fixed here
        self._provisions()
        if record["parameters"].get("shadowIn") == "dryRunOnly" and not self.in_dry_run:
            self.mode = "dry-run-only: skipped"
            self.disagreements.append((self.head_slot, "reader", "C", "dry-run-only: skipped in this session (%s); the dry-run "
                                       "runner compares" % self._slots(), "skipped"))
            return
        self.mode = "compare"
        norm = normalised(record)
        pin = record.get("exclusion", {}).get("pinLine")     # MON-282-W2-RULED: compared with its pin line normalised
        for layer in sorted(record["layers"], key=lambda l: -l["slot"]):
            files = {layer["validatorPath"]: layer["validatorSha256"], layer["authorityPath"]: layer["authoritySha256"]}
            if layer.get("testFilePath"):
                files[layer["testFilePath"]] = layer["testFileSha256"]
            files.update(layer["inputs"])
            for path, digest in sorted(files.items()):
                self._budget()
                try:
                    live = _read(self.root, path)
                    if live is None:
                        self.disagreements.append((layer["slot"], path, "A", "missing", "input"))
                        continue
                    rebuilt_sha, reverted, unexplained = self._rebuilt(path, live, newer, norm, pin)
                    if reverted:
                        self.reverted.setdefault(layer["slot"], []).append([path, [[a, c] for a, c in reverted]])
                    if rebuilt_sha != digest:
                        demoting = self._demotion(path, live, newer, digest, pin, unexplained)
                        if demoting:     # 286 3.11: authored edits landing exactly on the checkpoint digest
                            self.demoted.append({"slot": layer["slot"], "path": path, "authority": demoting})
                            self._demoted_slots.setdefault(layer["slot"], []).append((path, demoting, digest))
                            continue
                        detail = "; ".join("%s: %s" % u for u in unexplained) or "differs from its checkpoint digest"
                        if unauthored(reverted, unexplained):     # C3-4: edited since its newest recorded state
                            self.unauthored.add(path)
                            detail = "unauthored: " + detail
                        self.disagreements.append((layer["slot"], path, "A", detail, "input"))
                except (OverBudget, KeyboardInterrupt):
                    raise
                except Exception as exc:     # C1-16: one file's fault never ends the rest; the slot is the head's (C3-2)
                    kind = "corrupt" if isinstance(exc, Corrupt) else "fault"     # by cause (P047-C4-1)
                    self.disagreements.append((self.head_slot, path, "C", "%s: %s; layer %s; %s"
                                               % (type(exc).__name__, str(exc)[:160], layer["slot"], self._slots()), kind))
        for fault in check_pairs(record.get("checkPairs", [])):
            self.disagreements.append((self.head_slot, "checkPairs", "C", "Corrupt: %s; %s" % (fault, self._slots()), "corrupt"))
        self.sampled = sample(self.tree or _git(self.root, "rev-parse", "HEAD^{tree}"), [l["slot"] for l in record["layers"]],
                              record["parameters"]["sampleFraction"])

    def _rebuilt(self, path, live, newer, norm, pin):
        """L2 (286 3.3): one rebuild per (path, live sha256) inside this invocation, whose newer set is fixed at start;
        filled only after the afterSha256 gate (a result whose replay missed the gate is not cached)."""
        key = (path, _sha(live))
        if self.cache and key in self._l2:
            return self._l2[key]
        rebuilt, reverted, unexplained = rebuild(path, live, newer, norm, self._budget,
                                                 classes=(self._auth_sha, self._l1) if self.cache else None)
        if path == pin:
            rebuilt = pin_normalised(rebuilt, rebuilt)
        value = (_sha(rebuilt), reverted, unexplained)
        if self.cache and not any(d.startswith(UNAUTHORED_MISS) for _, d in unexplained):
            self._l2[key] = value
        return value

    def _demotion(self, path, live, newer, digest, pin, unexplained):
        """286 3.11 (C1-4): only a path whose one unexplained entry is the authored form is a candidate; the continued
        replay decides. Returns the demoting authority, or None."""
        if not (len(unexplained) == 1 and AUTHORED.match(unexplained[0][1])):
            return None
        key = (path, _sha(live), digest)
        if self.cache and key in self._land:
            ok, who = self._land[key]
        else:
            ok, who = landing(path, live, newer, digest, pin, self._budget,
                              classes=(self._auth_sha, self._l1) if self.cache else None)
            if self.cache:
                self._land[key] = (ok, who)
        return who if ok else None

    def _provisions(self):
        """P-048-1 and P-048-3 (inert at 286): the G1 module is loaded only when present; only then is the signal
        file read, and the mode of record is the verifier's declaration plus the module's presence."""
        if not (self.root / G1_MODULE).is_file():
            return
        import importlib.util
        try:
            spec = importlib.util.spec_from_file_location("_planeon_met_perf_048_g1", self.root / G1_MODULE)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.g1 = module
        except Exception as exc:
            self.disagreements.append((self.head_slot, G1_MODULE, "C", "%s: the G1 module did not load; shadow; %s"
                                       % (type(exc).__name__, self._slots()), "fault"))
            return
        fields, failed = signal_check(self.root, os.environ.get("HOME"), lambda: _git(self.root, "rev-parse", "HEAD"))
        if failed:
            self.disagreements.append((self.head_slot, "signal", "C", "P-048-3: %s; shadow; %s" % (failed, self._slots()), "fault"))
        elif fields:
            self.mode_of_record = "sampled"

    def _statement(self, slot, nodes):
        """C2's statement check for a demoted layer whose outcome differs: the authoring v2.4 record states that
        layer, the path and every differing node, and the path's hunks include a class-other hunk. Returns the
        explained event (countEffect "pending isolation"), or None."""
        by_path = {apath: rec for _, apath, rec in self._newer}
        for path, apath, digest in self._demoted_slots[slot]:
            rec = by_path.get(apath, {})
            hunks = rec.get("changedFiles", {}).get(path, {}).get("reverseHunks", [])
            for s in rec.get("outcomeStatements", []):
                if s["layerSlot"] == slot and s["path"] == path and set(nodes) <= set(s["nodeSha256s"]) \
                        and any(h.get("class") == "other" for h in hunks):
                    return {"slot": slot, "path": path, "authority": apath, "nodes": sorted(nodes),
                            "statement": {"layerSlot": slot, "path": path, "nodeSha256s": list(s["nodeSha256s"])},
                            "restoredPaths": [{"path": p, "baseSha256": d} for p, _, d in self._demoted_slots[slot]],
                            "isolation": [], "kind": "demoted-outcome-explained",
                            "countEffect": COUNT_EFFECT["demoted-outcome-explained"][1]}
        return None

    def report(self, nodeid, when, outcome, duration=0.0):
        if self.active and self.mode == "compare":
            start = self._now()
            try:
                key = node_hash(nodeid)
                self.live.setdefault(key, {})[when] = outcome
                self.durations[key] = self.durations.get(key, 0.0) + float(duration or 0.0)
            finally:
                self.spent += self._now() - start

    def finish(self, head_sha=None):
        if not self.active:
            return None, None
        self._timed(self._finish)
        start = self._now()
        try:
            head = head_sha or _git(self.root, "rev-parse", "HEAD")
        except Exception as exc:
            head = "unknown"
            self.disagreements.append((self.head_slot, "reader", "C", "%s: head sha: %s; %s" % (type(exc).__name__, str(exc)[:120],
                                                                                                self._slots()), "fault"))
        self.spent += self._now() - start
        if self.spent > self.cap and not self.over_cap:
            self.over_cap = True
            self.disagreements.append((self.head_slot, "reader", "C", "over cap: %.3f s over %.0f s; the dry-run path; %s"
                                       % (self.spent, self.cap, self._slots()), "over-cap"))
        try:
            return self._record(head)
        except Exception as exc:     # C2-8: a record is still written, with one class C
            self.disagreements.append((self.head_slot, "reader", "C", "%s: the record could not be built: %s; %s"
                                       % (type(exc).__name__, str(exc)[:120], self._slots()), "fault"))
            return ("%s head %s; record fault" % (PREFIX, head[:12]),
                    {"headSha": head, "mode": self.mode, "disagreements": [{"slot": s, "where": w, "class": c, "kind": k,
                     "countEffect": COUNT_EFFECT.get(k, ("C", "restart"))[1], "detail": d} for s, w, c, d, k in self.disagreements],
                     "unauthored": sorted(self.unauthored)})

    def _finish(self):
        if self.record is None or self.mode != "compare":
            return
        input_slots = {d[0] for d in self.disagreements if d[2] == "A"}
        for layer in sorted(self.record["layers"], key=lambda l: -l["slot"]):
            recorded, live, agree, live_s = {}, {}, True, 0.0
            demoted, differing = layer["slot"] in self._demoted_slots, []
            for node in layer["nodes"]:
                key = node["nodeSha256"]
                want = {k: node[k] for k in ("setup", "call", "teardown") if node.get(k) is not None}
                got = self.live.get(key)
                recorded[key[:12]], live[key[:12]] = want, got
                live_s += self.durations.get(key, 0.0)
                if got is None or any(got.get(k) != v for k, v in want.items()):
                    agree = False
                    if demoted:
                        differing.append(key)
                        continue
                    cls = "A" if layer["slot"] in input_slots else "B"
                    detail = "not run in this session" if got is None else "outcome differs"
                    self.disagreements.append((layer["slot"], key[:12], cls, detail, "input" if cls == "A" else "outcome"))
            if differing:     # 286 3.11, C2: never neutral; explained (pending isolation) or class A
                event = self._statement(layer["slot"], differing)
                if event:
                    event["seconds"] = round(live_s, 4)
                    self.isolation.append(event)
                else:
                    self.disagreements.append((layer["slot"], differing[0][:12], "A",
                                               "a demoted layer's outcome differs with no matching statement", "input"))
            self.layers[str(layer["slot"])] = {"recorded": recorded, "live": live, "agree": agree,
                                               "writingSeconds": layer.get("seconds"), "liveSeconds": round(live_s, 4)}

    def _record(self, head):
        workers, source = _workers(self.root)
        attested = [l["slot"] for l in (self.record or {}).get("layers", [])]
        record = {"headSha": head, "readerSeconds": round(self.spent, 3), "capSeconds": self.cap, "overCap": self.over_cap,
                  "workers": workers, "workersSource": source, "mode": self.mode,
                  "shadowIn": (self.record or {}).get("parameters", {}).get("shadowIn"), "naming": self.naming,
                  "attested": sorted(l["slot"] for l in (self.record or {}).get("layers", [])), "sampled": self.sampled,
                  "layers": self.layers, "reverted": {str(k): v for k, v in self.reverted.items()},
                  "unauthored": sorted(self.unauthored),
                  "disagreements": [{"slot": s, "where": w, "class": c, "kind": k, "countEffect": COUNT_EFFECT[k][1],
                                     "detail": d} for s, w, c, d, k in self.disagreements],
                  "demoted": [dict(e, liveSeconds=self.layers.get(str(e["slot"]), {}).get("liveSeconds"),
                                   kind="demoted", countEffect=COUNT_EFFECT["demoted"][1]) for e in self.demoted],
                  "attestedFraction": (round((len(attested) - len(self._demoted_slots)) / len(attested), 6)
                                       if attested else None),
                  "isolation": self.isolation, "modeOfRecord": self.mode_of_record}
        counts = {c: sum(1 for d in self.disagreements if d[2] == c) for c in "ABC"}
        line = "%s head %s; %.3f s (cap %.0f s%s); mode %s; A %d B %d C %d; sampled %d; unauthored %d; demoted %d; pending isolation %d" % (
            PREFIX, head[:12], self.spent, self.cap, ", OVER CAP" if self.over_cap else "", self.mode,
            counts["A"], counts["B"], counts["C"], len(self.sampled), len(self.unauthored), len(self.demoted), len(self.isolation))
        return line, record


def dry_run_compare(log_path, out_path, root=ROOT):
    """The dry-run runner's comparison (parameters.shadowIn == "dryRunOnly"): argv 63's END events from the dry run's
    log feed the same Reader, which writes its record to out_path. An event is read wherever it sits in its line
    (MON-282-DRYRUN-FIND: the log has teardown events after other output on the same line)."""
    reader = Reader(root=root, in_dry_run=True)
    reader.start()
    for line in Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines():
        at = line.find("PYTEST_DIAGNOSTIC=")
        if at >= 0:
            try:
                event = json.loads(line[at + len("PYTEST_DIAGNOSTIC="):])
            except ValueError:
                continue
            if event.get("event") == "END" and reader.active and reader.mode == "compare":
                reader.live.setdefault(event["node"], {})[event["phase"]] = event["outcome"]
                reader.durations[event["node"]] = reader.durations.get(event["node"], 0.0) + event.get("durationUs", 0) / 1e6
    line, record = reader.finish()
    Path(out_path).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    return line


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "dry-run-compare":
        print(dry_run_compare(sys.argv[2], sys.argv[3]))
    else:
        raise SystemExit("usage: chain_checkpoint.py dry-run-compare LOG OUT")
