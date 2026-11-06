"""MET-PERF-047 (CHAIN-COMPACTION-002, G1): the chain checkpoint's shadow reader.

Loaded by path from the root conftest.py inside a guard, so a missing, unloadable or raising reader never changes a
session's outcome. It is active only in the outermost pytest session (PLANEON_PARALLEL_SUITE_SERIAL absent when this
module is imported: every worker and every nested pytest inherits it) and only when
architecture/chain-checkpoint/record.json exists and an authority names it with its sha256.

Shadow mode observes and records only. At session start it rebuilds every attested layer's files (its validator, its
test file and its captured inputs) at the checkpoint tree from the live files, undoing, newest first, the published
reverseHunks of every authority newer than the checkpoint whose recorded class is in NORMALISED, byte-exact, with each
file's afterSha256 and beforeSha256 checked; each recorded class is re-checked by this module's copy of chainmech
v2.2's rule (hunk_class_v22), using the authority's hunkClassContext. Rebuilt bytes are compared, never executed. It
draws the sample, sha256(head tree id + NUL + slot) / 2**256 < f. At session finish it compares the ledger's recorded
node outcomes with this session's, layer by layer. Every disagreement is recorded with its slot and class: A (an
input differs after normalisation), B (an outcome differs with no input change), C (a fault of the reader or of the
records). It writes one shadow record file and prints one summary line; it never raises and never changes the exit
status. Its whole run is timed once; over CAP_SECONDS it records the over-cap state and the dry-run path.
Standard library only; no sys.path edit; no repository module is imported.
"""
import base64
import difflib
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/chain-checkpoint/record.json"
SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
CAP_SECONDS = 15.0
SERIAL_ENV = "PLANEON_PARALLEL_SUITE_SERIAL"
OUTERMOST = SERIAL_ENV not in os.environ
NORMALISED_BASE = frozenset(("bridge", "cascade"))   # plus "record" when W's capture decides it ([Q-V22-1])
PREFIX = "chain-checkpoint shadow:"

# ---- chainmech v2.2's class rule (hunk_class_v22.py), copied byte for byte by make_c1_282.py ----
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


# ---- end of the copied rule ----


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fault(Exception):
    """A class-C fault: the reader's own or the records'."""


def _read(root, path):
    p = root / path
    try:
        return p.read_bytes() if p.is_file() and not p.is_symlink() else None
    except OSError:
        return None


def naming_authority(root, raw):
    """The authority that names the record with its exact sha256 (in newFiles or as a changed file's afterSha256)."""
    digest, hits = _sha(raw), []
    for p in sorted((root / "architecture").glob("*-authority.json")):
        body = p.read_bytes()
        if RECORD_PATH.encode() not in body:
            continue
        rec = json.loads(body)
        if rec.get("newFiles", {}).get(RECORD_PATH) == digest or \
                rec.get("changedFiles", {}).get(RECORD_PATH, {}).get("afterSha256") == digest:
            hits.append(p.relative_to(root).as_posix())
    return hits


def newer_authorities(root, baseline):
    """Every authority whose baseline catalog is larger than the checkpoint authority's, newest first."""
    out = []
    for p in sorted((root / "architecture").glob("*-authority.json")):
        rec = json.loads(p.read_bytes())
        n = len(rec.get("baselinePackets", {}))
        if n > baseline:
            out.append((n, p.relative_to(root).as_posix(), rec))
    out.sort(key=lambda t: -t[0])
    if len({n for n, _, _ in out}) != len(out):
        raise Fault("two newer authorities share a baseline size")
    return out


def _normalised(record):
    extra = record.get("normalisedRecordClass") is True   # set at W when the capture names an index record ([Q-V22-1])
    return NORMALISED_BASE | ({"record"} if extra else frozenset())


def rebuild(path, live, newer, normalised):
    """The bytes of path at the checkpoint tree, from its live bytes, undoing newest first each newer authority's
    normalised hunks. Returns (bytes, reverted [(authority, class, count)], unexplained [(authority, detail)])."""
    cur, reverted, unexplained = live, [], []
    for _, apath, rec in newer:
        entry = rec.get("changedFiles", {}).get(path)
        if entry is None:
            if path in rec.get("newFiles", {}):
                unexplained.append((apath, "added after the checkpoint"))
            continue
        if _sha(cur) != entry["afterSha256"]:
            unexplained.append((apath, "afterSha256 differs before the replay"))
            return cur, reverted, unexplained
        ctx = rec.get("hunkClassContext")
        hunks, keep, seen = entry["reverseHunks"], [], set()
        prior = -1
        for h in hunks:
            if h["at"] <= prior:
                unexplained.append((apath, "reverse hunks out of order"))
                return cur, reverted, unexplained
            prior = h["at"]
            rm, ins = base64.b64decode(h["removeBase64"]), base64.b64decode(h["insertBase64"])
            if cur[h["at"]:h["at"] + len(rm)] != rm:
                unexplained.append((apath, "a hunk does not apply byte-exactly"))
                return cur, reverted, unexplained
            cls = h.get("class")
            if cls is None or ctx is None:
                unexplained.append((apath, "a hunk without its class or context"))
                return cur, reverted, unexplained
            again = classify(path, cur, h["at"], rm, ins, ctx["prevValidator"], ctx["prevTest"], ctx["newPacket"],
                             tuple(ctx["steps"]), seen=seen)
            if again != cls:
                unexplained.append((apath, "recorded class %s fails the re-check (%s)" % (cls, again)))
                return cur, reverted, unexplained
            keep.append((h["at"], rm, ins, cls))
        undo = [k for k in keep if k[3] in normalised]
        for at, rm, ins, cls in sorted(undo, key=lambda k: -k[0]):
            cur = cur[:at] + ins + cur[at + len(rm):]
        counts = {}
        for k in keep:
            counts[k[3]] = counts.get(k[3], 0) + 1
        reverted.append((apath, counts))
        if len(undo) != len(keep):
            unexplained.append((apath, "%d hunk(s) of a class not normalised" % (len(keep) - len(undo))))
            return cur, reverted, unexplained
        if _sha(cur) != entry["beforeSha256"]:
            unexplained.append((apath, "beforeSha256 differs after the replay"))
            return cur, reverted, unexplained
    return cur, reverted, unexplained


RULED_PAIR_TYPES = frozenset(("supersession",))


def check_pairs(entries):
    """V006-P2-2: each entry two distinct ids and a ruled pair type; no entry repeated."""
    seen = set()
    for e in entries:
        ids = e.get("ids")
        if not (isinstance(ids, list) and len(ids) == 2 and ids[0] != ids[1]) or e.get("type") not in RULED_PAIR_TYPES:
            raise Fault("a check_pairs entry is self-paired, not a pair, or of an unruled type (slot %s)" % e.get("layerSlot"))
        key = (e.get("layerSlot"), tuple(sorted(ids)))
        if key in seen:
            raise Fault("a repeated check_pairs entry (slot %s)" % e.get("layerSlot"))
        seen.add(key)


def sample(tree_id, slots, fraction):
    """The head-seeded sample: a slot is sampled when sha256(tree id + NUL + slot) / 2**256 < fraction."""
    return sorted(s for s in slots if int(_sha(tree_id.encode() + b"\0" + str(s).encode()), 16) < fraction * 2 ** 256)


def head_tree(root):
    out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True, timeout=5)
    if out.returncode or not re.fullmatch(r"[0-9a-f]{40}", out.stdout.strip()):
        raise Fault("the head tree id is unavailable")
    return out.stdout.strip()


def node_hash(nodeid):
    return _sha(nodeid.encode("utf-8"))


class Reader:
    """One shadow run for one outermost session. Every method records faults instead of raising them."""

    def __init__(self, root=ROOT, clock=time.monotonic, out_dir=None, cap=CAP_SECONDS, tree=None):
        self.root, self.clock, self.cap = Path(root), clock, cap
        self.out_dir = Path(out_dir) if out_dir else Path(tempfile.gettempdir())
        self.tree = tree
        self.active, self.spent, self.record = False, 0.0, None
        self.disagreements, self.faults, self.live, self.reverted = [], [], {}, {}
        self.sampled, self.naming, self.over_cap = [], [], False

    def _timed(self, fn, *args):
        start = self.clock()
        try:
            fn(*args)
        except Exception as exc:    # a fault never escapes: class C
            self.faults.append("C %s: %s" % (type(exc).__name__, str(exc)[:200]))
        finally:
            self.spent += self.clock() - start

    def start(self):
        self._timed(self._start)

    def _start(self):
        raw = _read(self.root, RECORD_PATH)
        if raw is None:
            return                                 # no record: inactive (c1 and W)
        self.active = True
        self.naming = naming_authority(self.root, raw)
        if not self.naming:
            self.disagreements.append((None, RECORD_PATH, "A", "the record is present but no authority names it"))
            return
        record = json.loads(raw)
        if record.get("schemaVersion") != SCHEMA:
            raise Fault("record schema")
        self.record = record
        check_pairs(record.get("checkPairs", []))
        checkpoint_baseline = record["checkpointBaseline"]
        newer = newer_authorities(self.root, checkpoint_baseline)
        normalised = _normalised(record)
        for layer in sorted(record["layers"], key=lambda l: -l["slot"]):    # newest first (RL-07 ordering)
            files = {layer["validatorPath"]: layer["validatorSha256"]}
            if layer.get("testFilePath"):
                files[layer["testFilePath"]] = layer["testFileSha256"]
            files.update(layer["inputs"])
            for path, digest in sorted(files.items()):
                live = _read(self.root, path)
                if live is None:
                    self.disagreements.append((layer["slot"], path, "A", "missing"))
                    continue
                rebuilt, reverted, unexplained = rebuild(path, live, newer, normalised)
                if reverted:
                    self.reverted.setdefault(layer["slot"], []).append((path, reverted))
                if _sha(rebuilt) != digest:
                    detail = "; ".join("%s: %s" % u for u in unexplained) or "differs from its checkpoint digest"
                    self.disagreements.append((layer["slot"], path, "A", detail))
        tree = self.tree or head_tree(self.root)
        self.sampled = sample(tree, [l["slot"] for l in record["layers"]], record["parameters"]["sampleFraction"])

    def report(self, nodeid, when, outcome):
        if self.active and self.record is not None:
            start = self.clock()
            try:
                self.live.setdefault(node_hash(nodeid), {})[when] = outcome
            finally:
                self.spent += self.clock() - start

    def finish(self, head_sha="unknown"):
        self._timed(self._finish)
        if not self.active:
            return None
        if self.spent > self.cap:
            self.over_cap = True
        return self._write(head_sha)

    def _finish(self):
        if self.record is None:
            return
        input_slots = {d[0] for d in self.disagreements if d[2] == "A"}
        for layer in sorted(self.record["layers"], key=lambda l: -l["slot"]):
            for node in layer["nodes"]:
                live = self.live.get(node["nodeSha256"])
                want = {k: node[k] for k in ("setup", "call", "teardown") if node.get(k) is not None}
                if live is None:
                    self.disagreements.append((layer["slot"], node["nodeSha256"][:12], "B", "not run in this session"))
                elif any(live.get(k) != v for k, v in want.items()):
                    cls = "A" if layer["slot"] in input_slots else "B"
                    self.disagreements.append((layer["slot"], node["nodeSha256"][:12], cls, "outcome differs"))

    def _write(self, head_sha):
        body = {"headSha": head_sha, "readerSeconds": round(self.spent, 3), "workers": 8,
                "capSeconds": self.cap, "overCap": self.over_cap,
                "dryRunPath": "the lane's dry run (DESIGN_CC2 vector 9)" if self.over_cap else None,
                "naming": self.naming, "sampled": self.sampled,
                "disagreements": [{"slot": s, "where": w, "class": c, "detail": d} for s, w, c, d in self.disagreements],
                "faults": self.faults,
                "reverted": {str(k): [[p, [[a, c] for a, c in r]] for p, r in v] for k, v in self.reverted.items()}}
        name = "chain-checkpoint-shadow-%s.json" % (head_sha[:12] if re.fullmatch(r"[0-9a-f]{7,40}", head_sha) else "head")
        try:
            (self.out_dir / name).write_text(json.dumps(body, sort_keys=True) + "\n", encoding="utf-8")
        except OSError as exc:
            self.faults.append("C record file: %s" % type(exc).__name__)
        counts = {c: sum(1 for d in self.disagreements if d[2] == c) for c in "AB"}
        return "%s head %s; %.3f s (cap %.0f s%s); disagreements A %d B %d; faults C %d; sampled %d; record %s" % (
            PREFIX, head_sha[:12], self.spent, self.cap, ", OVER CAP: dry-run path" if self.over_cap else "",
            counts["A"], counts["B"], len(self.faults), len(self.sampled), name)
