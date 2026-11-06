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
check_pairs(entries); and the CLI
`chain_checkpoint.py dry-run-compare LOG OUT` (the dry-run runner's comparison, parameters.shadowIn == "dryRunOnly").

The ledger (record.json, schema harness.planeon.ai/chain-checkpoint/v1): schemaVersion, checkpointSlot,
checkpointBaseline, writingCommit, writingTree, parameters {cadenceSlots, sampleFraction, fullRunOn, nShadow,
shadowCapSeconds, workers, shadowIn}, normalisedRecordClass, layers [{slot, module, validatorPath, validatorSha256,
testFilePath?, testFileSha256?, authorityPath, authoritySha256, inputs {path: sha256}, nodes [{nodeSha256, setup, call,
teardown}], seconds}], checkPairs [{layerSlot, pairsPath, ids [a, b], type}], fullRunProof, writingRun, sizeBytes,
sizeBound. Every digest is at the checkpoint tree.

The rebuild (D9 (a)): for each attested file, undo newest first the reverseHunks of every authority newer than the
checkpoint (baseline catalog larger than checkpointBaseline), byte-exact, afterSha256 and beforeSha256 checked; each
each authority keeps v2.1's eight-member form and three-key hunks; a classed authority's classes live in its
closed hunk-class record (HUNK_CLASSES_DIR/<slot>.json, MON-282-W1-A2: exactly authorityPath, hunkClassVocabulary,
hunkClassRuleSha256, hunkClassContext {newPacket == authorityPacket, prevValidator, prevTest, steps == [1, 1 + K]}
and classes {path: one class per reverse hunk, in the authority's order}), an ordinary new file of its step that
the authority's newFiles names by sha256, checked after the entry's shape (entry_fault) and before any class is
trusted; a missing, unnamed, digest-mismatched, malformed, miscounted or duplicated record, or an authority that
carries classes itself, is class A; each recorded class is re-checked by the rule copied
below, and only classes in normalised() are undone (cascade and bridge, plus record when normalisedRecordClass).

The shadow record (one JSON line in the session's log, prefixed "chain-checkpoint shadow record:"): headSha,
readerSeconds, capSeconds, overCap, workers and workersSource, shadowIn, mode, naming, attested (every ledger slot),
sampled, layers {slot: {recorded, live, agree, writingSeconds, liveSeconds}}, reverted {slot: [[path, [[authority,
{class: count}]]]]}, unauthored [paths], disagreements [{slot, where, class, kind, countEffect, detail}].

The kinds, their classes and their countEffects are architecture/chain-checkpoint/README.md's countEffect table, the
single source; COUNT_EFFECT below mirrors it, and the module tests pin the two equal. A kind is set by cause, never by
an exception's type: corrupt is exactly what check_ledger, _authorities, entry_fault and newer_authorities refuse
(the README's corrupt row), naming the file and the member; any other exception of the reader is fault. A class-C record's slot is the head's chain slot (head_slot: checkpointSlot plus the authorities newer than
the checkpoint by baseline, one authority per slot: their baselines and authorityPackets are distinct; null when the
ledger was not read or its slots are malformed). A fault's or a corrupt record's detail names its exception class;
every class-C detail names the head slot and the checkpoint slot. An attested file whose only miss is at its newest recorded
step is unauthored: class A, kind input, listed in unauthored. Stop rule (condition (v); MON-282-C23, MON-282-QC31):
every kind restarts the clean count of N_shadow except skipped, which is neutral and still writes its record; an
agree counts; a dry-run-only reading by the dry-run runner counts. Any three skips, or any three faults, within the
period are a finding to the lane monitor, not only consecutive ones (MON-282-CR4-KEEP), counted across verify records by the monitor and by MET-PERF-048 (no reader sees
more than one session); a reader that keeps faulting is a ci/ defect, not a reason to re-run the period.
"""
import base64
import difflib
import hashlib
import json
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
MODE = "shadow"                                       # 047; the writer refuses any other (condition (i))
RULE_SHA256 = "c4a77f027b244d6f1c22178fadfa7c0d4b6f7b607ada89b2eebdebc01417427b"   # the pinned hunk_class_v22.py
PREFIX = "chain-checkpoint shadow:"
RECORD_LINE = "chain-checkpoint shadow record:"
COUNT_EFFECT = {"input": ("A", "restart"), "stale": ("A", "restart"), "outcome": ("B", "restart"),
                "corrupt": ("C", "restart"), "over-budget": ("C", "restart"), "over-cap": ("C", "restart"),
                "fault": ("C", "restart"), "skipped": ("C", "neutral")}   # the README's countEffect table; an agree counts
UNAUTHORED_MISS = "afterSha256 differs before the replay"
HUNK_CLASSES_DIR = "architecture/chain-checkpoint/hunk-classes"     # MON-282-W1-A2: one closed record per classed authority
SIDE_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext", "classes"})
CLASS_MEMBERS = ("hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext")

# ---- chainmech v2.2's class rule (hunk_class_v22.py), copied byte for byte by make_c2_282.py ----
CLASSES = ("bridge", "cascade", "other", "record")   # the closed vocabulary, sorted; pinned in each authority from 282 on
NORMALISED = frozenset(("bridge", "cascade", "record"))   # "record" pending Q-V22-1
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


def classify(path, after, at, remove, insert, prev_validator, prev_test, new_id, steps=(1,), seen=None):
    """The closed class of one reverse hunk (remove: its bytes in AFTER; insert: the BEFORE bytes), judged on the whole
    lines it touches. cascade: before -> after differs only by (a) at most one appended element - a successor chain
    (optionally behind one attribute, starred for PRODUCT_PACKETS) or the new id's string, with its comma - (b) digit
    tokens moving +step and (c) inserted "successor." runs, or it is the (v) tuple form. bridge: any hunk in the previous
    head's validator or test. other: anything else (a real edit)."""
    if path in (prev_validator, prev_test):
        return "bridge"
    if path in RECORDS:
        return record_class(path, after, at, remove, insert, new_id, seen)
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
    return "other"


def _finds(raw, needle):
    i = raw.find(needle)
    while i >= 0:
        yield i
        i = raw.find(needle, i + 1)


# ---- end of the copied rule; its NORMALISED constant is not used here: normalised() decides ----


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
    refusal here: a record that does not parse is judged when an authority names it (class A)."""
    out = {}
    for p in sorted((root / HUNK_CLASSES_DIR).glob("*.json")):
        if budget:
            budget()
        raw = p.read_bytes()
        try:
            side = json.loads(raw)
        except ValueError:
            side = None
        out[p.relative_to(root).as_posix()] = (_sha(raw), side)
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
    if rec["newFiles"][named[0]] != side_sha:
        return bad("the hunk-class record's bytes do not hash to the authority's digest")
    if not isinstance(side, dict):
        return bad("the hunk-class record does not parse as an object")
    if set(side) != SIDE_MEMBERS:
        return bad("the hunk-class record's members are not the closed set")
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
    return out


def newer_authorities(root, baseline, budget=None, auths=None, sides=None):
    out = [(n, path, rec) for n, path, rec in (auths if auths is not None else _authorities(root, budget)) if n > baseline]
    out.sort(key=lambda t: -t[0])
    if len({n for n, _, _ in out}) != len(out):
        raise Corrupt("two newer authorities share a baseline size")
    packets = [rec.get("authorityPacket") for _, _, rec in out]
    for (_, path, _), packet in zip(out, packets):
        if not (isinstance(packet, str) and packet):
            raise Corrupt("authority %s authorityPacket" % path)
    if len(set(packets)) != len(packets):
        raise Corrupt("two newer authorities name one authorityPacket (one authority per slot, P047-C4-2)")
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
    if not (isinstance(ctx, dict) and set(ctx) == {"newPacket", "prevValidator", "prevTest", "steps"}):
        return "hunkClassContext missing or malformed"
    if ctx["newPacket"] != rec.get("authorityPacket"):
        return "hunkClassContext.newPacket is not the authority's packet"
    if not isinstance(rec.get("productPackets", {}), dict):     # a bad class context stays class A (P047-C5-2)
        return "productPackets is not an object"
    if ctx["steps"] != [1, 1 + len(rec.get("productPackets", {}))]:
        return "hunkClassContext.steps is not [1, 1 + K]"
    if rec.get("hunkClassVocabulary") != list(CLASSES):
        return "hunkClassVocabulary is not the closed vocabulary"
    if rec.get("hunkClassRuleSha256") != RULE_SHA256:
        return "hunkClassRuleSha256 is not the copied rule's"
    return None


def normalised(record):
    return frozenset(("bridge", "cascade") + (("record",) if record.get("normalisedRecordClass") is True else ()))


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


def rebuild(path, live, newer, norm, budget=None):
    """The bytes of path at the checkpoint tree, undoing newest first each newer authority's normalised hunks.
    Returns (bytes, reverted [(authority, {class: count})], unexplained [(authority, detail)]). budget() raises
    OverBudget when the in-run budget is spent."""
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
        ctx, keep, seen, prior = rec["hunkClassContext"], [], set(), -1
        pending = len(entry["reverseHunks"])
        if _sha(cur) != entry["afterSha256"]:
            share = sum(1 for h in entry["reverseHunks"] if h.get("class") in norm)
            unexplained.append((apath, "afterSha256 differs before the replay; recorded cascade share %d of %d hunks" % (share, pending)))
            return cur, reverted, unexplained
        for h in entry["reverseHunks"]:
            if h["at"] <= prior:
                unexplained.append((apath, "reverse hunks out of order"))
                return cur, reverted, unexplained
            prior = h["at"]
            rm, ins = base64.b64decode(h["removeBase64"]), base64.b64decode(h["insertBase64"])
            if cur[h["at"]:h["at"] + len(rm)] != rm:
                unexplained.append((apath, "a hunk does not apply byte-exactly"))
                return cur, reverted, unexplained
            cls = h.get("class")
            again = classify(path, cur, h["at"], rm, ins, ctx["prevValidator"], ctx["prevTest"], ctx["newPacket"],
                             tuple(ctx["steps"]), seen=seen)
            if cls != again:
                unexplained.append((apath, "recorded class %s fails the re-check (%s)" % (cls, again)))
                return cur, reverted, unexplained
            keep.append((h["at"], rm, ins, cls))
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


def unauthored(reverted, unexplained):
    """C3-4 (a): the file's only miss is at its newest recorded step: no newer step replayed, and either no newer
    authority names it, or the first that does fails its afterSha256 before any hunk is applied."""
    return not reverted and (not unexplained or (len(unexplained) == 1 and unexplained[0][1].startswith(UNAUTHORED_MISS)))


RULED_PAIR_TYPES = frozenset(("supersession",))


def check_pairs(entries):
    """V006-P2-2: each entry two distinct ids and a ruled pair type; no entry repeated. Returns the faults."""
    seen, faults = set(), []
    for e in entries:
        ids = e.get("ids")
        if not (isinstance(ids, list) and len(ids) == 2 and ids[0] != ids[1]) or e.get("type") not in RULED_PAIR_TYPES:
            faults.append("check_pairs entry self-paired, not a pair, or unruled (slot %s)" % e.get("layerSlot"))
            continue
        key = (e.get("layerSlot"), tuple(sorted(ids)))
        if key in seen:
            faults.append("check_pairs entry repeated (slot %s)" % e.get("layerSlot"))
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

    def __init__(self, root=ROOT, clock=time.monotonic, cap=CAP_SECONDS, tree=None, in_dry_run=False):
        self.root, self.clock, self.cap, self.tree, self.in_dry_run = Path(root), clock, cap, tree, in_dry_run
        self.active, self.spent, self.record, self.mode = False, 0.0, None, "inactive"
        self.disagreements, self.reverted, self.layers, self.unauthored = [], {}, {}, set()
        self.live, self.durations, self.sampled, self.naming, self.over_cap = {}, {}, [], None, False
        self._t0 = 0.0
        self.head_slot, self.ckpt_slot, self.ledger_state = None, None, None

    def _budget(self):
        if self.spent + (self.clock() - self._t0) > self.cap:
            raise OverBudget()

    def _slots(self):
        if self.head_slot is None:
            return "head slot unknown (%s)" % (self.ledger_state or "the ledger was not read")     # P047-C4-2, P047-C5-5
        return "head slot %s, checkpoint slot %s" % (self.head_slot, self.ckpt_slot)

    def _timed(self, fn, *args):
        self._t0 = start = self.clock()
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
            self.spent += self.clock() - start

    def start(self):
        self._timed(self._start)

    def _start(self):
        raw = _read(self.root, RECORD_PATH)
        if raw is None:
            return
        self.active = True
        self._budget()
        auths = _authorities(self.root, self._budget)      # parsed once, inside the budget
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
        if record["parameters"].get("shadowIn") == "dryRunOnly" and not self.in_dry_run:
            self.mode = "dry-run-only: skipped"
            self.disagreements.append((self.head_slot, "reader", "C", "dry-run-only: skipped in this session (%s); the dry-run "
                                       "runner compares" % self._slots(), "skipped"))
            return
        self.mode = "compare"
        norm = normalised(record)
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
                    rebuilt, reverted, unexplained = rebuild(path, live, newer, norm, self._budget)
                    if reverted:
                        self.reverted.setdefault(layer["slot"], []).append([path, [[a, c] for a, c in reverted]])
                    if _sha(rebuilt) != digest:
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

    def report(self, nodeid, when, outcome, duration=0.0):
        if self.active and self.mode == "compare":
            start = self.clock()
            try:
                key = node_hash(nodeid)
                self.live.setdefault(key, {})[when] = outcome
                self.durations[key] = self.durations.get(key, 0.0) + float(duration or 0.0)
            finally:
                self.spent += self.clock() - start

    def finish(self, head_sha=None):
        if not self.active:
            return None, None
        self._timed(self._finish)
        start = self.clock()
        try:
            head = head_sha or _git(self.root, "rev-parse", "HEAD")
        except Exception as exc:
            head = "unknown"
            self.disagreements.append((self.head_slot, "reader", "C", "%s: head sha: %s; %s" % (type(exc).__name__, str(exc)[:120],
                                                                                                self._slots()), "fault"))
        self.spent += self.clock() - start
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
            for node in layer["nodes"]:
                key = node["nodeSha256"]
                want = {k: node[k] for k in ("setup", "call", "teardown") if node.get(k) is not None}
                got = self.live.get(key)
                recorded[key[:12]], live[key[:12]] = want, got
                live_s += self.durations.get(key, 0.0)
                if got is None or any(got.get(k) != v for k, v in want.items()):
                    agree = False
                    cls = "A" if layer["slot"] in input_slots else "B"
                    detail = "not run in this session" if got is None else "outcome differs"
                    self.disagreements.append((layer["slot"], key[:12], cls, detail, "input" if cls == "A" else "outcome"))
            self.layers[str(layer["slot"])] = {"recorded": recorded, "live": live, "agree": agree,
                                               "writingSeconds": layer.get("seconds"), "liveSeconds": round(live_s, 4)}

    def _record(self, head):
        workers, source = _workers(self.root)
        record = {"headSha": head, "readerSeconds": round(self.spent, 3), "capSeconds": self.cap, "overCap": self.over_cap,
                  "workers": workers, "workersSource": source, "mode": self.mode,
                  "shadowIn": (self.record or {}).get("parameters", {}).get("shadowIn"), "naming": self.naming,
                  "attested": sorted(l["slot"] for l in (self.record or {}).get("layers", [])), "sampled": self.sampled,
                  "layers": self.layers, "reverted": {str(k): v for k, v in self.reverted.items()},
                  "unauthored": sorted(self.unauthored),
                  "disagreements": [{"slot": s, "where": w, "class": c, "kind": k, "countEffect": COUNT_EFFECT[k][1],
                                     "detail": d} for s, w, c, d, k in self.disagreements]}
        counts = {c: sum(1 for d in self.disagreements if d[2] == c) for c in "ABC"}
        line = "%s head %s; %.3f s (cap %.0f s%s); mode %s; A %d B %d C %d; sampled %d; unauthored %d" % (
            PREFIX, head[:12], self.spent, self.cap, ", OVER CAP" if self.over_cap else "", self.mode,
            counts["A"], counts["B"], counts["C"], len(self.sampled), len(self.unauthored))
        return line, record


def dry_run_compare(log_path, out_path, root=ROOT):
    """The dry-run runner's comparison (parameters.shadowIn == "dryRunOnly"): argv 63's END events from the dry run's
    log feed the same Reader, which writes its record to out_path."""
    reader = Reader(root=root, in_dry_run=True)
    reader.start()
    for line in Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("PYTEST_DIAGNOSTIC="):
            try:
                event = json.loads(line[len("PYTEST_DIAGNOSTIC="):])
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
