"""D5a oracle tests for slot 270, MET-ENFORCE-043 (EDGE-V12): host-interface amendment HE5 and operator edge record v12.

Owner decision D5a: a contract packet carries black-box tests written outside the candidate, by someone who is not its
builder. These tests were written by the D5a oracle author from the two contract READMEs of the adopted candidate c2:

- `architecture/host-interface-amendment-he5/README.md`: header, "Why W3-W5 change", "Files" (with the model's rules),
  "Decisions", "Changes", "Superseded clauses", "Obligations", "Residual", "What it does not change";
- `architecture/artifact-edges/README-v12.md`: header, the v12 record section and its table, "Commits", "Schema".

Where every expected value comes from:
- README text: item ids, places and decisions (the Changes table, parsed here), decision ids and quoted words, the
  superseded quotes, cited lines and replacements, obligations, the residual, the non-amendments, the edge table's
  paths, byte counts, digest prefixes and commit prefix, and the status statements; each test's docstring names the
  README and section;
- derived here from the files' bytes (independent of the model): every sha256 and byte count; the effective text,
  derived by counted substring replacement over HS53's bytes; the line diff HS53 -> HE5; the split of section 5.4 into
  its steps; the block-start test, written here from the README's prose; each disposition's items, computed from the
  items;
- regression pins, taken once from the adopted record and spec (c2) and not independent derivations: the normalised
  `proposed` words of H1-H3 and the sha256 of the published section 14;
- model-derived (named so in each test): the model's public constants, `check`, `check_steps` and `render_section14`
  of `scripts/host_interface_amendment_v4.py`. The README states no refusal texts; a refusal is the ValueError the
  model's public `require` raises.

The model is imported from ROOT/scripts and used only through its public functions, with hand-made arguments. Mutations
enter only through this file's own `read(path)`. No directory is walked: every file is read by its exact path.
"""

import copy
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import host_interface_amendment_v4 as model  # noqa: E402

HE5_README = "architecture/host-interface-amendment-he5/README.md"
EDGE_README = "architecture/artifact-edges/README-v12.md"
RECORD = "architecture/host-interface-amendment-he5/amendment.json"
STATUS = "architecture/host-interface-amendment-he5/status.json"
SPEC = "architecture/host-interface-amendment-he5/HOST_INTERFACE_SPEC.md"
HS53_SPEC = "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md"
HS53_RECORD = "architecture/host-interface-amendment-hs53/amendment.json"
EDGE_V11 = "architecture/artifact-edges/operator-harness-engineering-v11.json"
EDGE_V12 = "architecture/artifact-edges/operator-harness-engineering-v12.json"
PROVIDER_SCHEMA = "architecture/broker-handoff-inputs/channel.schema.json"
PROVIDER_VECTORS = "architecture/broker-handoff-inputs/vectors.json"
GUIDE = "docs/alpha-2/BROKER_HANDOFF_READINESS.md"
NPV4 = "architecture/native-profile-v4/README.md"

OBLIGATION_IDS = ["O-R10-HE005", "O-T04-HE5"]
SECTION14_HEADING = "## 14. Amendment HE5 (2026-10-26)"

# Regression pin (Q-CB2-7): sha256 and size of the published section 14, from its heading to the end of the file,
# taken once from the adopted spec (c2).
SECTION14_SHA256 = "43a71961a4cef4afda99c2347cd1418faa5763c460a6c05109130af42432b19e"
SECTION14_BYTES = 2178

# Regression pin (C1-6): the words of H1-H3's `proposed`, line feeds and runs of spaces normalised to one space, taken
# once from the adopted record (c2). A pin, not an independent derivation.
H_PINS = {
    "H1": " ".join([
        "It also checks the descriptor table while the child is still uid 0 in the",
        "broker's domain: stdio, none of it a socket, and the two descriptors W4 places. These are the broker-created",
        "socketpair end, which becomes FD3, and the verity-measured O_RDONLY worker script, which becomes fd 4. Every"
        " other",
        "descriptor the child holds is closed in W4, before exec.",
    ]),
    "H2": " ".join([
        "The child runs broker-owned pre-exec code only, in raw system calls with no",
        "allocation or lock: (1) block every signal, and reset every disposition except SIGKILL's and SIGSTOP's;"
        " (2) `dup3`",
        "the socketpair end to 3 and the measured script descriptor to 4; (3) `close_range` from 5; (4) unblock;",
        "(5) setresgid/setresuid to the signed UID; (6) drop all capabilities; (7) `no_new_privs=1`; (8) install the"
        " worker",
        "seccomp filter (W02d).",
    ]),
    "H3": " ".join([
        'W5. The child calls `execveat(4, "", ..., AT_EMPTY_PATH)` on fd 4, an O_RDONLY descriptor of the fs-verity'
        " worker",
        "script, never O_PATH, because FS_IOC_MEASURE_VERITY needs a readable descriptor. The broker measured the"
        " verity",
        "digest of that same open file description before W2, and never re-opens it. For a script, the kernel hands"
        " the",
        "interpreter `/dev/fd/4`, which stays open in the worker and read-only: the verity file refuses every write"
        " open, and",
        "the worker filter's openat admits read flags only (Q-HE5-9 (a)). After exec, the broker reads nothing of the",
        "worker's `/proc` (owner decision Q-HE5-12 (b), \"Drop post-exec reads\"; SELinux matrix v6, XV1-7). The"
        " worker's",
        "post-exec state holds by construction (O-R10-HE005) and is traced by",
        "T04 (O-T04-HE5).",
    ]),
}

# HE5 README, Changes: each table claim (README words) and the words of the pinned text that carry it.
CHANGE_CLAIMS = [
    ("H1", "while the child is still uid 0 in the broker's domain",
     ["while the child is still uid 0 in the broker's domain"]),
    ("H1", "stdio, none of it a socket", ["stdio, none of it a socket"]),
    ("H1", "the two descriptors W4 places", ["the two descriptors W4 places"]),
    ("H1", "the socketpair end (FD3)", ["socketpair end, which becomes FD3"]),
    ("H1", "the verity-measured O_RDONLY script (fd 4)",
     ["the verity-measured O_RDONLY worker script, which becomes fd 4"]),
    ("H1", "every other descriptor is closed in W4, before exec",
     ["Every other descriptor the child holds is closed in W4, before exec"]),
    ("H2", "in raw system calls with no allocation or lock", ["in raw system calls with no allocation or lock"]),
    ("H2", "(1) block every signal and reset every disposition except SIGKILL's and SIGSTOP's",
     ["(1) block every signal, and reset every disposition except SIGKILL's and SIGSTOP's"]),
    ("H2", "(2) `dup3` to 3 and 4", ["(2) `dup3` the socketpair end to 3 and the measured script descriptor to 4"]),
    ("H2", "(3) `close_range` from 5", ["(3) `close_range` from 5"]),
    ("H2", "(4) unblock", ["(4) unblock"]),
    ("H2", "(5) setresgid/setresuid", ["(5) setresgid/setresuid"]),
    ("H2", "(6) drop all capabilities", ["(6) drop all capabilities"]),
    ("H2", "(7) `no_new_privs=1`", ["(7) `no_new_privs=1`"]),
    ("H2", "(8) the worker filter", ["(8) install the worker seccomp filter"]),
    ("H3", "`execveat(4, …)` on fd 4", ['`execveat(4, "", ..., AT_EMPTY_PATH)` on fd 4']),
    ("H3", "the O_RDONLY script descriptor measured before W2 as the same open file description",
     ["an O_RDONLY descriptor of the fs-verity worker script",
      "measured the verity digest of that same open file description before W2"]),
    ("H3", "never O_PATH", ["never O_PATH"]),
    ("H3", "`/dev/fd/4` stays open and read-only", ["`/dev/fd/4`, which stays open in the worker and read-only"]),
    ("H3", "no post-exec read of the worker's `/proc`", ["the broker reads nothing of the worker's `/proc`"]),
    ("H3", "the post-exec state is by construction, traced by T04",
     ["post-exec state holds by construction", "traced by T04"]),
]

# HE5 README, Decisions: the words it quotes from the decision record, per decision, with the section ids it names.
DECISION_QUOTES = {
    "Q-HE5-9": [
        "Q-HE5-9 (H5D-3 (iii)): (a).",
        "Exactly one more inherited descriptor: fd 4, the verity-checked O_RDONLY script, read-only. The worker's set"
        " is exactly {0..4}, checked both before close_range and after exec, under the START freeze. The readiness"
        " sentence's errata goes in slot 269, together with Q-HE5-1's registration.",
        "Rev 2 must show that fd 4 cannot be written, re-opened writable or used as a second exec route, and that the"
        " verity measurement and the exec use the same fd.",
        "Q-HE5-9's post-exec half (H5E-1) is re-ruled (a): no capability widening, and HI-7 stays as it is.",
        "fd 4 stays, and so does W3's pre-close_range {0..4} check, made while the child is uid 0.",
        "The post-exec {0..4} becomes a structural claim, carried by the pinned child path and W3's check, with a T04"
        " trace carried.",
        "MON-HE005-R1-RULE",
        "MON-HE005-R2-RULE",
    ],
    "Q-HE5-12": [
        'the owner chose Q-HE5-12 (b), "Drop post-exec reads"',
        "R1 is widened and states plainly that runtime detection is given up, with T04 tracing each item.",
        "MON-HE005-Q12-OWNER",
    ],
    "Q-EV12-1": [
        "Q-EV12-1 is ruled (a) under the owner's delegation.",
        "slot 269 carries edge record v12, with the two BYTE_IDENTICAL, REGISTERED_BEFORE_USE broker-handoff-v1 rows,"
        " plus the host-interface amendment architecture/host-interface-amendment-he5/ in HS43/HS53 form.",
        "If no rule allows an in-place edit, list it as carried.",
        "carried and byte-identical, on your cited rule (FROZEN_PATHS :390-397, the sha256 pin at :493, HS53's"
        " SUPERSEDED precedent). That is correct for slot 269.",
        "MON-EV12-PLAN",
        "MON-HE005A-PLAN2",
    ],
    "MON-HE005-CLOSE": [
        "DESIGN-HE005 closes at rev 5 (0335ce2d).",
        "EDGE-V12, the I02/I03 registration plus H5E-10's errata list, without the (a) matrix item.",
    ],
}
DESIGN_SHA256 = "0335ce2df4bd25e5e7ca53c08d9beaa7bea277f69c2c2f8bdebfa1ea3a89f707"

# HE5 README, Superseded clauses: path, quote, cited lines, "It now reads" text, items.
SUPERSEDED_README = [
    (GUIDE, "FD3 is the sole inherited non-stdio descriptor", (100, 101),
     "FD3 and fd 4 (the verity-checked, read-only worker script, Q-HE5-9 (a)) are the only inherited non-stdio"
     " descriptors", ["H1", "H3"]),
    (NPV4, "on an O_PATH descriptor of the worker executable", (216, 216),
     "on fd 4, an O_RDONLY descriptor of the verity-checked worker script (W01 §5.4 W5 as amended by HE5)",
     ["H3"]),
]

# HS53's own sentences that the HE5 README says stay after each change (taken from HS53's bytes).
KEPT_SENTENCES = {
    "W3": "The child holds no supplementary groups: the `Groups:` line\nof `/proc/<pid>/status` lists none (the kernel"
          " writes `Groups:`, a tab and one space). W4's setresgid and setresuid\nleave supplementary groups unchanged,"
          " so the broker must run with none (obligation O-W03-GROUPS), and neither filter\nallows `setgroups`.",
    "W4": "That filter admits W5's `execveat`\nform and no other exec, and it stacks on the inherited broker filter.",
    "W5": "The domain transition to `planeon_worker_t` happens on this\nexec.",
}
HS53_W4_STEP_LINE = "W4. The broker thaws the leaf. The child runs broker-owned pre-exec code only:"
W3_END = "neither filter\nallows `setgroups`.\n"
W5_END = "happens on this\nexec.\n"
BLOCK_LINE = "- a hand-made list item\n"
HEADING_0 = b"## 0. Disposition vocabulary"
SEPARATORS = "\r\x0b\x0c\x1c\x1d\x1e\x85  "  # str.splitlines boundaries other than the line feed
STEP_LINE = re.compile(r"W[0-9]+\. ")
OBLIGATION_REF = re.compile(r"\bO-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")


# ---------------------------------------------------------------------------------------------------- helpers

def raw(path):
    return (ROOT / path).read_bytes()


def text(path):
    return raw(path).decode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def norm(value):
    return " ".join(value.split())


def pin_norm(value):
    return re.sub(" +", " ", value.replace("\n", " "))


def loose(value):
    """Whitespace collapsed, colons dropped, first letter lower-cased: for README restatements of record text."""
    value = norm(value.replace(":", ""))
    return value[:1].lower() + value[1:]


def record():
    return json.loads(raw(RECORD))


def by_id(rec):
    return {item["id"]: item for item in rec["items"]}


def once(value, old, new):
    assert value.count(old) == 1, old
    return value.replace(old, new)


def readme_section(readme, heading):
    lines = readme.split("\n")
    start = lines.index(heading)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start + 1:end]


def bullets(lines):
    out = []
    for line in lines:
        if line.startswith("- "):
            out.append(line[2:])
        elif out and line.startswith("  ") and line.strip():
            out[-1] += " " + line.strip()
    return out


def table_rows(lines):
    rows = [[cell.strip() for cell in line.strip().strip("|").split("|")]
            for line in lines if line.startswith("| ") and not line.startswith("|---")]
    return rows[1:]


def changes_table():
    rows = table_rows(readme_section(text(HE5_README), "## Changes"))
    return [(r[0], r[1], r[2], [] if r[3] == "—" else r[3].split(", ")) for r in rows]


def opens_block(line):
    """The HE5 README's definition (Files), written here from its prose."""
    body = line.lstrip(" ")
    if len(line) - len(body) > 3:
        return False
    return bool(re.match(r"(?:[-*+]|#{1,6}|[0-9]{1,9}[.)])(?:[ \t]|$)", body)
                or re.match(r"(?:>|W[0-9]+\.|`{3,}|~{3,}|<)", body)
                or re.fullmatch(r"(?:=+|-+)[ \t]*", body)
                or re.fullmatch(r"(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,}", body))


def steps(lines):
    """Section 5.4's span, its step labels in order, and each step's line span (step line to the next step line)."""
    start = next(i for i, line in enumerate(lines) if line.startswith("### 5.4 "))
    end = next(i for i, line in enumerate(lines) if i > start and line.startswith("### 5.5 "))
    starts = [i for i in range(start, end) if STEP_LINE.match(lines[i])]
    spans = {}
    for k, i in enumerate(starts):
        j = starts[k + 1] if k + 1 < len(starts) else next(x for x in range(i, end) if not lines[x].strip())
        spans[lines[i].split(".", 1)[0]] = (i, j)
    return (start, end), [lines[i].split(".", 1)[0] for i in starts], spans


def step_text(lines, spans, label):
    i, j = spans[label]
    return "\n".join(lines[i:j])


def base_lines(base, current):
    start = base[: base.index(current)].count("\n") + 1
    end = start + current.count("\n") - (1 if current.endswith("\n") else 0)
    return str(start) if end == start else f"{start}-{end}"


def apply_items(rec, base, ids=None):
    """Counted substring replacement over HS53's text, as the HE5 README (Files) states."""
    out = base
    for item in rec["items"]:
        if ids is not None and item["id"] not in ids:
            continue
        assert base.count(item["current"]) == item["occurrences"], item["id"]
        assert out.count(item["current"]) == item["occurrences"], item["id"]
        out = out.replace(item["current"], item["proposed"])
    return out


def section14(spec_text):
    return spec_text[spec_text.index(SECTION14_HEADING):]


def reader(overrides=None):
    """This file's own read(path): the published bytes, or the changed bytes given for a path."""
    overrides = dict(overrides or {})

    def read(path):
        if path in overrides:
            return overrides[path]
        return (ROOT / path).read_bytes()
    return read


def serialise(rec):
    return (json.dumps(rec, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def consistent(rec):
    """A consistent world for a changed record: its effective text derived here, its effective digest updated."""
    effective = apply_items(rec, text(HS53_SPEC)).encode("utf-8")
    rec["effective"]["sha256"] = sha(effective)
    return {RECORD: serialise(rec), SPEC: effective}


def decided_pins_hold(rec):
    items = by_id(rec)
    return all(k in items and pin_norm(items[k]["proposed"]) == v for k, v in H_PINS.items())


def refs(value):
    return set(OBLIGATION_REF.findall(value))


# ---------------------------------------------------------------------------------------------------- 1. the base

def test_base_pinned_by_model_and_record():
    """HE5 README, header and Files: HS53's effective text and record have the sha256 values the model's public
    constants name (model-derived constants, digests computed here), and the record's `base` names the same path and
    digest."""
    rec = record()
    readme = text(HE5_README)
    assert f"(`{HS53_SPEC}`)" in readme
    assert model.BASE_PATH == HS53_SPEC and model.BASE_RECORD_PATH == HS53_RECORD
    assert sha(raw(HS53_SPEC)) == model.BASE_SHA256
    assert sha(raw(HS53_RECORD)) == model.BASE_RECORD_SHA256
    assert rec["base"]["path"] == HS53_SPEC and rec["base"]["sha256"] == sha(raw(HS53_SPEC))
    assert rec["base"]["record"] == {"path": HS53_RECORD, "sha256": sha(raw(HS53_RECORD))}
    assert rec["base"]["designLabel"] == model.BASE_LABEL == "HOST-INTERFACE-DRAFT-002-HS53"
    assert "`HOST-INTERFACE-DRAFT-002-HS53`" in text(HS53_SPEC)
    assert "`HOST-INTERFACE-DRAFT-002-HE5`" in readme
    assert rec["designLabel"] == model.DESIGN_LABEL == "HOST-INTERFACE-DRAFT-002-HE5"
    assert "`planeon.internal.host-interface-amendment/v2`" in readme
    assert rec["schemaVersion"] == model.SCHEMA == "planeon.internal.host-interface-amendment/v2"
    assert rec["effective"] == {"path": SPEC, "sha256": sha(raw(SPEC))}


def test_record_counts_match_files_table():
    """HE5 README, Files (`amendment.json` row): four decisions; six counted substring replacements, three DECIDED
    and three EDITORIAL; one disposition per decision; two obligations; 2 superseded clauses; one residual; six
    non-amendments."""
    rec = record()
    assert len(rec["ownerDecisions"]) == 4
    assert len(rec["items"]) == 6
    assert sorted(item["kind"] for item in rec["items"]) == ["DECIDED"] * 3 + ["EDITORIAL"] * 3
    decisions = [d["id"] for d in rec["ownerDecisions"]]
    assert sorted(d["decision"] for d in rec["dispositions"]) == sorted(decisions)
    assert len(rec["dispositions"]) == len(set(decisions)) == 4
    assert len(rec["obligations"]) == 2
    assert len(rec["supersedes"]) == 2
    assert len(rec["residuals"]) == 1
    assert len(rec["notAmended"]) == 6


# ---------------------------------------------------------------------------------------------------- 2. the items

def test_items_follow_changes_table():
    """HE5 README, Changes (and Files): six items; H1-H3 DECIDED in 5.4 W3, W4 and W5, E1-E3 EDITORIAL (title, head,
    section 14), each citing exactly the decisions the table lists; DECIDED items in the table's order H1, H2, H3 and
    EDITORIAL items in its order E1, E2, E3 (the README does not state the record's interleaving; see the report)."""
    table = changes_table()
    assert [row[0] for row in table] == ["H1", "H2", "H3", "E1", "E2", "E3"]
    rec = record()
    items = by_id(rec)
    assert set(items) == {row[0] for row in table}
    assert [i["id"] for i in rec["items"] if i["kind"] == "DECIDED"] == [r[0] for r in table if r[0][0] == "H"]
    assert [i["id"] for i in rec["items"] if i["kind"] == "EDITORIAL"] == [r[0] for r in table if r[0][0] == "E"]
    expected_where = {"H1": "§5.4 W3", "H2": "§5.4 W4", "H3": "§5.4 W5",
                      "E1": "title", "E2": "head", "E3": "§14 (new)"}
    for item_id, where, _change, decisions in table:
        item = items[item_id]
        assert where == expected_where[item_id]
        assert item["kind"] == ("DECIDED" if item_id.startswith("H") else "EDITORIAL")
        assert item["section"].split(",")[0] == where.lstrip("§")
        assert item["decisions"] == decisions
    assert [r[3] for r in table[:3]] == [["Q-HE5-9", "Q-EV12-1", "MON-HE005-CLOSE"],
                                         ["Q-HE5-9", "Q-EV12-1", "MON-HE005-CLOSE"],
                                         ["Q-HE5-9", "Q-HE5-12", "Q-EV12-1", "MON-HE005-CLOSE"]]
    assert all(r[3] == [] for r in table[3:])


def test_decided_items_occur_inside_their_own_steps():
    """HE5 README, Changes and Files (the model's limits): each DECIDED item's `current` occurs in HS53's text as many
    times as its `occurrences` says, and lies inside the lines of its own step (from the step line to the next one)."""
    base = text(HS53_SPEC)
    lines = base.split("\n")
    _span, _labels, spans = steps(lines)
    for item_id, label in (("H1", "W3"), ("H2", "W4"), ("H3", "W5")):
        item = by_id(record())[item_id]
        assert base.count(item["current"]) == item["occurrences"] >= 1
        pos = base.index(item["current"])
        first = base[:pos].count("\n")
        last = first + item["current"].rstrip("\n").count("\n")
        start, end = spans[label]
        assert start <= first and last < end, item_id


def test_editorial_items():
    """HE5 README, Changes (E1-E3) and Files: E1 names the four amendments in the title; E2 keeps HS53's head line and
    says HE5 is applied on top of the byte-identical HS53 text; E3 adds section 14 after HS53's last line."""
    base = text(HS53_SPEC)
    items = by_id(record())
    e1, e2, e3 = items["E1"], items["E2"], items["E3"]
    assert e1["current"] == base.split("\n")[0] + "\n"
    assert "W02D, HS43, HS53 and HE5" in e1["proposed"] and e1["proposed"].startswith("# ")
    assert base.count(e2["current"]) == 1 and e2["proposed"].startswith(e2["current"])
    added = norm(e2["proposed"][len(e2["current"]):])
    assert "Amendment HE5 (`HOST-INTERFACE-DRAFT-002-HE5`, section 14)" in added
    assert "applied on top of the HS53 effective text" in added and "byte-identical" in added
    assert f"`{HS53_SPEC}`" in added
    assert base.endswith(e3["current"]) and base.count(e3["current"]) == 1
    assert e3["proposed"] == e3["current"] + "\n" + section14(text(SPEC))


# ---------------------------------------------------------------------------------------------------- 3. the text

def test_effective_text_derived_independently():
    """HE5 README, Files (`HOST_INTERFACE_SPEC.md` row and the model row): applying H1-H3, E1 and E2 to HS53's bytes by
    counted substring replacement gives the published spec up to section 14; with E3 it gives the whole spec."""
    base = text(HS53_SPEC)
    published = text(SPEC)
    rec = record()
    derived = apply_items(rec, base, ids={"E1", "E2", "H1", "H2", "H3"})
    assert published.startswith(derived)
    assert published == derived + "\n" + section14(published)
    assert apply_items(rec, base) == published
    assert sha(published.encode("utf-8")) == rec["effective"]["sha256"]


def test_line_diff_touches_only_named_regions():
    """HE5 README, Files (the model's limits): a line diff HS53 -> HE5 changes only the title, the head, W3, W4, W5
    and adds section 14; every other line of the text is HS53's."""
    a = text(HS53_SPEC).split("\n")
    b = text(SPEC).split("\n")

    def regions(lines, with14):
        out = {0: "title"}
        design = next(i for i, line in enumerate(lines) if line.startswith("Design label `HOST-INTERFACE-DRAFT-002`;"))
        out.update({i: "head" for i in range(1, design)})
        _span, _labels, spans = steps(lines)
        for label in ("W3", "W4", "W5"):
            i, j = spans[label]
            out.update({x: label for x in range(i, j)})
        if with14:
            k = lines.index(SECTION14_HEADING)
            out.update({x: "section14" for x in range(k - 1, len(lines))})
        return out

    ra, rb = regions(a, False), regions(b, True)
    touched = set()
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        for i in range(i1, i2):
            assert i in ra, (tag, i + 1, a[i])
            touched.add(ra[i])
        for j in range(j1, j2):
            assert j in rb, (tag, j + 1, b[j])
            touched.add(rb[j])
    assert touched == {"title", "head", "W3", "W4", "W5", "section14"}
    # outside section 5.4, the title, the head and section 14, every line is HS53's
    (sa, ea), _l, _s = steps(a)
    (sb, eb), _l, _s = steps(b)
    da = next(i for i, line in enumerate(a) if line.startswith("Design label"))
    db = next(i for i, line in enumerate(b) if line.startswith("Design label"))
    assert a[da:sa] == b[db:sb]
    assert a[ea:] == b[eb:b.index(SECTION14_HEADING)]


def test_unchanged_steps_and_kept_sentences():
    """HE5 README, What it does not change and Changes: W1, W2, W6 and section 5.3 are byte-identical to HS53's; the
    sentences that stay after each change (W3's `Groups:` sentences, W4's filter sentence, W5's domain-transition
    sentence) are unchanged, each once in its own step of both texts."""
    a = text(HS53_SPEC).split("\n")
    b = text(SPEC).split("\n")
    (sa, ea), _la, spa = steps(a)
    (sb, eb), _lb, spb = steps(b)
    for label in ("W1", "W2", "W6"):
        assert step_text(a, spa, label) == step_text(b, spb, label), label
    assert a[sa:spa["W1"][0]] == b[sb:spb["W1"][0]]
    assert a[spa["W6"][1]:ea] == b[spb["W6"][1]:eb]

    def five_three(lines):
        i = next(x for x, line in enumerate(lines) if line.startswith("### 5.3 "))
        return lines[i:next(x for x, line in enumerate(lines) if line.startswith("### 5.4 "))]
    assert five_three(a) == five_three(b)
    for label, sentence in KEPT_SENTENCES.items():
        assert step_text(a, spa, label).count(sentence) == 1, label
        assert step_text(b, spb, label).count(sentence) == 1, label


# ---------------------------------------------------------------------------------------------------- 4. step rules

def test_step_rules_hold_in_published_text():
    """HE5 README, Files (the model's limits) and Why W3-W5 change: section 5.4's step lines are exactly W1-W6 in
    order in both texts; inside W3-W5 no line is blank and no line after the step line opens a block unless HS53's
    same step holds it; W4's eight calls stay inline as "(1)" to "(8)"; the W3-W5 claims are in the text."""
    a = text(HS53_SPEC).split("\n")
    b = text(SPEC).split("\n")
    _sa, labels_a, spa = steps(a)
    _sb, labels_b, spb = steps(b)
    assert labels_a == labels_b == ["W1", "W2", "W3", "W4", "W5", "W6"]
    for label in ("W3", "W4", "W5"):
        i, j = spb[label]
        base_step = set(a[spa[label][0]:spa[label][1]])
        for line in b[i:j]:
            assert line.strip(" \t"), label
        for line in b[i + 1:j]:
            assert not opens_block(line) or line in base_step, (label, line)
    w4 = step_text(b, spb, "W4")
    positions = [w4.find(f"({n}) ") for n in range(1, 9)]
    assert all(w4.count(f"({n}) ") == 1 for n in range(1, 9))
    assert positions == sorted(positions) and positions[0] > 0
    assert not any(f"({n})" in step_text(a, spa, "W4") for n in range(1, 9))
    w3 = norm(step_text(b, spb, "W3"))
    w4n = norm(w4)
    w5 = norm(step_text(b, spb, "W5"))
    assert "which becomes fd 4" in w3 and "O_RDONLY" in w3 and "still uid 0" in w3 and "none of it a socket" in w3
    assert "`dup3` the socketpair end to 3 and the measured script descriptor to 4" in w4n
    assert "`close_range` from 5" in w4n and "close_range above 3" not in w4n
    assert '`execveat(4, "", ..., AT_EMPTY_PATH)` on fd 4, an O_RDONLY descriptor' in w5
    assert "never O_PATH" in w5 and "on an O_PATH descriptor" not in w5
    assert "the broker reads nothing of the worker's `/proc`" in w5


def test_decided_items_add_no_block():
    """HE5 README, Files (the model's limits): each DECIDED item's proposed text holds no blank line between two of its
    line feeds, keeps the step label its current text starts with or adds none, opens no block on a later line (nor
    on its first when the current text starts a line without a step label), adds no step line, heading, list item or
    quote, and agrees with its current text on a leading and a trailing line feed."""
    base = text(HS53_SPEC)
    for item_id in ("H1", "H2", "H3"):
        item = by_id(record())[item_id]
        cur, prop = item["current"], item["proposed"]
        plines = prop.split("\n")
        assert all(line.strip(" \t") for line in plines[1:-1]), item_id
        label = STEP_LINE.match(cur)
        if label:
            assert prop.startswith(label.group(0)), item_id
        else:
            assert not STEP_LINE.match(prop), item_id
        pos = base.index(cur)
        starts_line = pos == 0 or base[pos - 1] == "\n"
        if starts_line and not label:
            assert not opens_block(plines[0]), item_id
        for line in plines[1:]:
            assert not opens_block(line), (item_id, line)
        assert sum(1 for line in plines[1:] if STEP_LINE.match(line)) == 0
        assert cur.startswith("\n") == prop.startswith("\n"), item_id
        assert cur.endswith("\n") == prop.endswith("\n"), item_id


# ---------------------------------------------------------------------------------------------------- 5. section 14

def test_section14_contents_in_readme_order():
    """HE5 README, Changes (E3) and Files: section 14 holds the items (the three DECIDED items, with their places and
    decisions), both superseded quotes with their replacements and items, the residual, what follows and both
    obligations, in that order."""
    rec = record()
    s14 = section14(text(SPEC))
    assert s14.startswith(SECTION14_HEADING + "\n")
    order = []
    for item in [i for i in rec["items"] if i["kind"] == "DECIDED"]:
        order.append(f"| {item['id']} | {item['section']} | {', '.join(item['decisions'])} |")
    for path, quote, _lines, replacement, items in SUPERSEDED_README:
        order += [f'"{quote}"', f"`{path}`", f"{replacement} ({', '.join(items)})"]
    residual = rec["residuals"][0]
    order += [f"- {residual['id']}: {residual['text']}", "Follow-up: T04 and HE-008",
              "Edge record v12 registers the I02/I03 inputs beside this amendment"]
    order += [f"{o['id']} ({o['label']})" for o in rec["obligations"]]
    flat = norm(s14)
    cursor = 0
    for piece in order:
        found = flat.find(norm(piece), cursor)
        assert found >= 0, piece
        cursor = found + len(norm(piece))
    assert [o["id"] for o in rec["obligations"]] == OBLIGATION_IDS
    assert flat.endswith("Every E01-E12 obligation stays OPEN_UNPROVEN.")


def test_section14_pinned_and_rendered_by_model():
    """HE5 README, Files ("section 14 is rendered from the record alone") and Changes (E3): the published section 14,
    from its heading to the end of the file, matches its sha256 regression pin (Q-CB2-7) and equals the model's
    public `render_section14` over the record, less the renderer's one leading line feed (model-derived)."""
    s14 = section14(text(SPEC)).encode("utf-8")
    assert len(s14) == SECTION14_BYTES and sha(s14) == SECTION14_SHA256
    rendered = model.render_section14(record())
    assert rendered == "\n" + s14.decode("utf-8")


# ---------------------------------------------------------------------------------------------------- 6. superseded

def test_superseded_clauses():
    """HE5 README, Superseded clauses: exactly two entries in the README's order; each sha256 is that file's bytes'
    sha256; each quote occurs in its file at the lines the README cites; each replacement is the README's "It now
    reads" text; each names the README's items. The model's SUPERSEDED constant agrees (model-derived)."""
    rec = record()
    readme = norm("\n".join(readme_section(text(HE5_README), "## Superseded clauses")))
    assert "The closed list holds 2 adopted clauses" in readme
    assert [s["path"] for s in rec["supersedes"]] == [entry[0] for entry in SUPERSEDED_README]
    for entry, (path, quote, (first, last), replacement, items) in zip(rec["supersedes"], SUPERSEDED_README):
        cite = f"lines {first}-{last}" if first != last else f"line {first}"
        assert f'"{quote}" (`{path}`, {cite})' in readme
        assert f'It now reads: "{replacement}" ({", ".join(items)})' in readme
        data = raw(path)
        assert entry["sha256"] == sha(data)
        assert norm(entry["quote"]) == quote
        body = data.decode("utf-8")
        spans = []
        start = body.find(entry["quote"])
        while start >= 0:
            line = body[:start].count("\n") + 1
            spans.append((line, line + entry["quote"].count("\n")))
            start = body.find(entry["quote"], start + 1)
        assert (first, last) in spans, (path, spans)
        assert entry["replacement"] == replacement
        assert entry["items"] == items
    guide_lines = text(GUIDE).split("\n")
    assert "unexpected inherited FD" in guide_lines[117]
    assert [tuple(s) for s in model.SUPERSEDED] == [(s["path"], s["quote"]) for s in rec["supersedes"]]


# ---------------------------------------------------------------------------------------------------- 7. decisions

def test_decisions_and_dispositions():
    """HE5 README, Decisions and Files: the four decision ids in the README's order, each holding the words the README
    quotes; Q-HE5-12 holds "Drop post-exec reads"; every decision is cited; each disposition lists exactly the items
    that cite its decision (computed here) and only record obligations, in record order."""
    rec = record()
    section = readme_section(text(HE5_README), "## Decisions")
    readme = norm("\n".join(section))
    ids = [re.match(r"\*\*([A-Z0-9-]+)", b).group(1) for b in bullets(section)]
    assert ids == ["Q-HE5-9", "Q-HE5-12", "Q-EV12-1", "MON-HE005-CLOSE"]
    assert [d["id"] for d in rec["ownerDecisions"]] == ids
    decisions = {d["id"]: d for d in rec["ownerDecisions"]}
    for decision_id, quotes in DECISION_QUOTES.items():
        held = norm(decisions[decision_id]["decision"] + " " + decisions[decision_id]["source"])
        for quote in quotes:
            assert norm(quote) in readme, quote
            assert norm(quote) in held, (decision_id, quote)
        assert decisions[decision_id]["date"] == "2026-10-26"
    assert "Drop post-exec reads" in decisions["Q-HE5-12"]["decision"]
    assert DESIGN_SHA256 in readme and DESIGN_SHA256 in decisions["MON-HE005-CLOSE"]["source"]
    obligation_ids = [o["id"] for o in rec["obligations"]]
    dispositions = {d["decision"]: d for d in rec["dispositions"]}
    for decision_id in ids:
        citing = [i["id"] for i in rec["items"] if decision_id in i["decisions"]]
        assert citing, decision_id
        assert dispositions[decision_id]["items"] == citing, decision_id
        listed = dispositions[decision_id]["obligations"]
        assert listed == [o for o in obligation_ids if o in listed], decision_id
    for item in rec["items"]:
        assert set(item["decisions"]) <= set(ids), item["id"]


def test_decision_state_matches_model_constant():
    """HE5 README, Decisions (owner and monitor decisions): every decision carries the model's decided state
    (model-derived constant)."""
    assert all(d["state"] == model.DECIDED for d in record()["ownerDecisions"])


# ---------------------------------------------------------------------------------------------------- 8. obligations

def test_obligations_and_residual():
    """HE5 README, Obligations, Residual and Files: O-R10-HE005 and O-T04-HE5 in order with the README's owners and
    texts; the DECIDED items name exactly those two, H3 names both, and no item names another; one residual,
    R-HE5-POSTEXEC, citing Q-HE5-12, follow-up T04 and HE-008."""
    rec = record()
    section = readme_section(text(HE5_README), "## Obligations")
    parsed = [re.match(r"\*\*(O-[A-Z0-9-]+)\*\* \(([^)]*)\): (.*)", b).groups() for b in bullets(section)]
    assert [p[0] for p in parsed] == OBLIGATION_IDS == [o["id"] for o in rec["obligations"]]
    for (oid, owner, words), obligation in zip(parsed, rec["obligations"]):
        assert obligation["owner"] == owner, oid
        assert loose(obligation["text"]) == loose(words), oid
    assert "H3 names both" in "\n".join(section)
    items = by_id(rec)
    assert refs(items["H3"]["proposed"]) == set(OBLIGATION_IDS)
    named = set().union(*(refs(items[k]["proposed"]) for k in ("H1", "H2", "H3")))
    assert named == set(OBLIGATION_IDS)
    for item in rec["items"]:
        assert refs(item["proposed"]) - refs(item["current"]) <= set(OBLIGATION_IDS), item["id"]
    residual_section = bullets(readme_section(text(HE5_README), "## Residual"))
    assert len(residual_section) == 1
    match = re.match(r"\*\*(R-[A-Z0-9-]+):\*\* (.*)", residual_section[0])
    rid, words = match.groups()
    assert [r["id"] for r in rec["residuals"]] == [rid] == ["R-HE5-POSTEXEC"]
    residual = rec["residuals"][0]
    assert residual["decisions"] == ["Q-HE5-12"] and "Q-HE5-12 (b)" in words
    assert residual["followUp"] == "T04 and HE-008" and words.endswith("Follow-up: T04 and HE-008.")
    readme_body = words.split(" (§8")[0]
    assert loose(residual["text"]).startswith(loose(readme_body))
    assert "(§8" in residual["text"]


# ---------------------------------------------------------------------------------------------------- 9, 10

def test_not_amended_matches_readme():
    """HE5 README, What it does not change: the record's six non-amendments are the README's six entries, in order
    (trailing ";" or "." and the first letter's case ignored)."""
    entries = bullets(readme_section(text(HE5_README), "## What it does not change"))

    def key(value):
        value = value.rstrip(";.")
        return value[:1].lower() + value[1:]
    assert len(entries) == 6
    assert [key(v) for v in record()["notAmended"]] == [key(v) for v in entries]


def test_record_strings_hold_no_other_line_separator():
    """HE5 README, Files (the model's limits): no string in the record, key or value, holds a line separator other
    than the line feed (every str.splitlines boundary but the line feed is checked)."""
    found = []

    def walk(value):
        if isinstance(value, str):
            found.extend(ch for ch in value if ch in SEPARATORS)
        elif isinstance(value, dict):
            for key, inner in value.items():
                walk(key)
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)
    walk(record())
    assert found == []


# ---------------------------------------------------------------------------------------------------- 11. the model

def test_model_accepts_published_contract():
    """HE5 README, Files (the model row): the model's `check(read)` over the tree returns without a refusal, and so
    does it for the record re-serialised by this file's own read (the baseline of every mutation) (model-derived)."""
    out = model.check(reader())
    assert isinstance(out, dict)
    model.check(reader(consistent(record())))


def test_model_constants_agree_with_readme():
    """HE5 README, Files (the model's limits) and Changes: the model's public constants name the README's DECIDED items
    and places, steps, obligations, residual, title and head (model-derived constants)."""
    items = by_id(record())
    assert model.REQUIRED_DECIDED == ("H1", "H2", "H3")
    assert model.DECIDED_PLACES == {"H1": ("5.4", "W3"), "H2": ("5.4", "W4"), "H3": ("5.4", "W5")}
    assert model.STEPS == ("W1", "W2", "W3", "W4", "W5", "W6")
    assert model.REQUIRED_OBLIGATIONS == tuple(OBLIGATION_IDS)
    assert model.REQUIRED_RESIDUALS == ("R-HE5-POSTEXEC",)
    assert model.KINDS == ("DECIDED", "EDITORIAL")
    assert model.TITLE == (items["E1"]["current"], items["E1"]["proposed"])
    assert model.HEAD_LINE == items["E2"]["current"]
    assert model.HEAD_LINE + model.HEAD_EXTENSION == items["E2"]["proposed"]
    assert model.END_LINE == items["E3"]["current"]


# ---------------------------------------------------------------------------------------------------- 12. status

def test_status_covers_both_contract_parts():
    """HE5 README, header and Files (`status.json` row); README-v12, header: status.json covers both contract parts,
    the amendment and edge record v12, and states what the READMEs state: slot 270, MET-ENFORCE-043, nothing
    installed, no R10 file changed, E01-E12 OPEN_UNPROVEN, the two superseded texts carried byte-identical. The
    README's status line is not compared with status.json's contract state."""
    he5 = norm(text(HE5_README))
    edge = norm(text(EDGE_README))
    assert ("The candidate's status for both contract parts of slot 270, this amendment and edge record v12; it"
            " governs") in he5
    assert "(`architecture/host-interface-amendment-he5/status.json`, which covers both contract parts of the slot)" \
        in edge
    assert "slot 270 (MET-ENFORCE-043, EDGE-V12)" in he5
    assert ("It installs nothing and proves no enforcement obligation; E01-E12 stay OPEN_UNPROVEN. No R10 file changes"
            " in this slot.") in he5
    st = json.loads(raw(STATUS))
    assert st["packet"] == "MET-ENFORCE-043" and st["slot"] == "270"
    assert "edge record v12" in st["workItem"] and "amendment HE5" in st["workItem"]
    preds = {p["record"]: p["sha256"] for p in st["predecessorRecord"]}
    assert preds == {HS53_RECORD: sha(raw(HS53_RECORD)), EDGE_V11: sha(raw(EDGE_V11))}
    files = [set(s["files"]) for s in st["supersedes"]]
    assert any({HS53_RECORD, HS53_SPEC} <= f for f in files)
    assert any(EDGE_V11 in f for f in files)
    assert st["installed"] is False
    assert "No R10 file changes in this slot." in st["nonClaims"]
    assert any("Nothing is installed" in c and "E01-E12" in c and "OPEN_UNPROVEN" in c for c in st["nonClaims"])
    for _path, quote, _lines, _replacement, _items in SUPERSEDED_README:
        carried = [c for c in st["carried"] if f'"{quote}"' in norm(c["item"])]
        assert len(carried) == 1, quote
        assert "byte-identical" in carried[0]["action"], quote


# ---------------------------------------------------------------------------------------------------- 13. edge v12

def test_edge_record_v12():
    """README-v12, the v12 record section, its table, Commits and Schema: 81 rows, v11's 79 first and unchanged in
    order, then the two table rows (paths, HE-005B, BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, the sha256 and
    byte count computed here, the stated commit, no providerPacket); `supersedes` is v11's sha256 and the README's
    value; the carried members equal v11's; schema v2, no key or status added."""
    readme = text(EDGE_README)
    flat = norm(readme)
    v11 = json.loads(raw(EDGE_V11))
    v12 = json.loads(raw(EDGE_V12))
    assert "edge record v11's 79 artefacts, unchanged and in order" in flat and "81 rows in all" in flat
    assert len(v11["artifacts"]) == 79 and len(v12["artifacts"]) == 81
    assert v12["artifacts"][:79] == v11["artifacts"]
    expected = [
        (PROVIDER_SCHEMA, "host-enforcement/contracts/broker-handoff-v1/channel.schema.json", "e7e9558fb50b", 42572),
        (PROVIDER_VECTORS, "host-enforcement/contracts/broker-handoff-v1/vectors.json", "80d8da953c41", 47254),
    ]
    for row, (provider, consumer, prefix, size) in zip(v12["artifacts"][79:], expected):
        assert (f"| `{provider}` | `{prefix}…` | {size:,} | `8f3cc3a8ef34` | none | HE-005B | `{consumer}` |"
                " REGISTERED_BEFORE_USE |") in readme
        data = raw(provider)
        assert len(data) == size
        assert row["sha256"] == sha(data) and row["sha256"].startswith(prefix)
        assert row["providerPath"] == provider and row["consumerPath"] == consumer
        assert row["consumerPacket"] == "HE-005B"
        assert row["relation"] == "BYTE_IDENTICAL" and row["status"] == "REGISTERED_BEFORE_USE"
        assert row["mode"] == "100644"
        assert re.fullmatch(r"[0-9a-f]{40}", row["providerCommit"]) and row["providerCommit"].startswith(
            "8f3cc3a8ef34")
        assert "providerPacket" not in row
    v11_sha = sha(raw(EDGE_V11))
    assert f"`sha256:{v11_sha}`" in readme
    assert v12["supersedes"]["path"] == EDGE_V11
    assert v12["supersedes"]["sha256"] == "sha256:" + v11_sha
    assert v12["supersedes"]["packet"] == "MET-ENFORCE-042" and "binds v11 (MET-ENFORCE-042)" in flat
    for key in ("ownerDecision", "rules", "notArtifacts", "statuses", "ownerDecisions"):
        assert f"`{key}`" in readme
        assert v12[key] == v11[key], key
    assert "`planeon.internal.artifact-edge-registry/v2`" in readme
    assert v12["schemaVersion"] == v11["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
    assert set(v12) == set(v11)
    v11_keys = set().union(*(set(r) for r in v11["artifacts"]))
    assert all(set(r) <= v11_keys for r in v12["artifacts"])
    assert {r["status"] for r in v12["artifacts"]} <= set(v12["statuses"])
    assert (v12["graph"], v12["consumer"], v12["provider"]) == (v11["graph"], v11["consumer"], v11["provider"])
    assert "(operator -> harness-engineering, buildArtifact)" in readme
    notes = norm(" ".join(v12["notes"]))
    assert "positive only" in notes and "DATA_CHECK_ONLY" in notes and "I02/I03" in notes
    assert "No R10 file changes in this slot." in notes


# ---------------------------------------------------------------------------------------------------- 14. pins

def test_decided_words_pinned_and_claims_hold():
    """HE5 README, Changes (C1-6): the normalised words of H1-H3's `proposed` match their regression pins, and each
    Changes-table claim holds in those words. A plain prose line moved from W3 to W4 (round 2's MV4) fails the pin;
    the model's `check` accepts that record by design (model-derived)."""
    rec = record()
    assert decided_pins_hold(rec)
    table = {row[0]: norm(row[2]) for row in changes_table()}
    for item_id, readme_words, record_words in CHANGE_CLAIMS:
        assert norm(readme_words) in table[item_id], (item_id, readme_words)
        for words in record_words:
            assert words in H_PINS[item_id], (item_id, words)
    moved = record()
    items = by_id(moved)
    line = "descriptor the child holds is closed in W4, before exec."
    assert items["H1"]["proposed"].endswith("\n" + line)
    items["H1"]["proposed"] = items["H1"]["proposed"][: -len(line) - 1]
    items["H2"]["proposed"] = items["H2"]["proposed"] + "\n" + line
    assert not decided_pins_hold(moved)
    model.check(reader(consistent(moved)))


# ---------------------------------------------------------------------------------------------------- 15. check_steps

def test_check_steps_called_directly():
    """HE5 README, Files (the model's limits; C2-3, Q-CB2-4): direct calls of the model's public
    `check_steps(record, base, effective)` with hand-made texts: (c) a changed W2 line and a changed W6 line are
    refused; (b) a block-start line that HS53's same step holds is spared, the identical line in another step is
    refused; (a) swapped step lines are refused (model-derived)."""
    rec = record()
    base = text(HS53_SPEC)
    eff = text(SPEC)

    def call(b, e):
        model.check_steps(rec, b.encode("utf-8"), e.encode("utf-8"))

    call(base, eff)
    with pytest.raises(ValueError):
        call(base, once(eff, "leaf. In v6.12 `cgroup_post_fork`", "leaf. In v6.13 `cgroup_post_fork`"))
    with pytest.raises(ValueError):
        call(base, once(eff, "reports `populated 0`, and only then", "reports `populated 1`, and only then"))
    assert opens_block(BLOCK_LINE.rstrip("\n"))
    base_b = once(base, W3_END, W3_END + BLOCK_LINE)
    eff_b = once(eff, W3_END, W3_END + BLOCK_LINE)
    call(base_b, eff_b)
    with pytest.raises(ValueError):
        call(base_b, once(eff_b, W5_END, W5_END + BLOCK_LINE))
    with pytest.raises(ValueError):
        call(base_b, once(eff, W5_END, W5_END + BLOCK_LINE))
    lines = eff.split("\n")
    i4 = next(i for i, line in enumerate(lines) if line.startswith("W4. "))
    i5 = next(i for i, line in enumerate(lines) if line.startswith("W5. "))
    i6 = next(i for i, line in enumerate(lines) if line.startswith("W6. "))
    with pytest.raises(ValueError):
        call(base, "\n".join(lines[:i4] + lines[i5:i6] + lines[i4:i5] + lines[i6:]))
    relabelled = list(lines)
    relabelled[i4], relabelled[i5] = "W5. " + lines[i4][4:], "W4. " + lines[i5][4:]
    with pytest.raises(ValueError):
        call(base, "\n".join(relabelled))


# ---------------------------------------------------------------------------------------------------- 17 + mutations

def _decided_moved_to_w6():
    rec = record()
    item = by_id(rec)["H1"]
    current = "reports `populated 0`, and only then releases the leaf."
    assert text(HS53_SPEC).count(current) == 1
    item.update(section="5.4 W6, the descriptor check", current=current,
                proposed="reports `populated 0`, and only then releases the leaf, with fd 4 closed.",
                baseLines=base_lines(text(HS53_SPEC), current))
    e3 = by_id(rec)["E3"]
    e3["proposed"] = once(e3["proposed"], "| H1 | 5.4 W3, the descriptor check |",
                          "| H1 | 5.4 W6, the descriptor check |")
    return consistent(rec)


def _with_proposed(item_id, change):
    def build():
        rec = record()
        item = by_id(rec)[item_id]
        item["proposed"] = change(item["proposed"])
        return consistent(rec)
    return build


def _carriage_return():
    rec = record()
    by_id(rec)["H1"]["why"] += "\r"
    return consistent(rec)


def _superseded_reordered():
    rec = record()
    rec["supersedes"].reverse()
    e3 = by_id(rec)["E3"]
    lines = e3["proposed"].split("\n")
    a = next(i for i, line in enumerate(lines) if line.startswith('| "FD3 is the sole'))
    b = next(i for i, line in enumerate(lines) if line.startswith('| "on an O_PATH'))
    lines[a], lines[b] = lines[b], lines[a]
    e3["proposed"] = "\n".join(lines)
    return consistent(rec)


def _superseded_third():
    rec = record()
    quote = "for a script the kernel hands the interpreter"
    assert quote in text(NPV4)
    rec["supersedes"].append({"path": NPV4, "sha256": sha(raw(NPV4)), "quote": quote, "replacement": "x",
                              "items": ["H3"]})
    e3 = by_id(rec)["E3"]
    lines = e3["proposed"].split("\n")
    b = next(i for i, line in enumerate(lines) if line.startswith('| "on an O_PATH'))
    lines.insert(b + 1, f'| "{quote}" | `{NPV4}` | x (H3) |')
    e3["proposed"] = "\n".join(lines)
    return consistent(rec)


def _residual_removed():
    rec = record()
    rec["residuals"] = []
    e3 = by_id(rec)["E3"]
    prop = e3["proposed"]
    e3["proposed"] = prop[: prop.index("Stated residuals:")] + prop[prop.index("Edge record v12 registers"):]
    return consistent(rec)


def _obligation_renamed():
    rec = json.loads(json.dumps(record(), ensure_ascii=False).replace("O-T04-HE5", "O-T04-HE6"))
    return consistent(rec)


def _undeclared_decision():
    rec = record()
    by_id(rec)["H2"]["decisions"].append("Q-HE5-99")
    e3 = by_id(rec)["E3"]
    row = "| H2 | 5.4 W4, the child's pre-exec calls | Q-HE5-9, Q-EV12-1, MON-HE005-CLOSE"
    e3["proposed"] = once(e3["proposed"], row + " |", row + ", Q-HE5-99 |")
    return consistent(rec)


def _disposition_missing_item():
    rec = record()
    rec["dispositions"][0]["items"].remove("H2")
    return consistent(rec)


def _uncited_decision():
    rec = record()
    extra = copy.deepcopy(rec["ownerDecisions"][0])
    extra["id"] = "Q-HE5-99"
    rec["ownerDecisions"].append(extra)
    rec["dispositions"].append({"decision": "Q-HE5-99", "items": [], "obligations": [], "summary": "x"})
    return consistent(rec)


def _decided_dropped():
    rec = record()
    rec["items"] = [i for i in rec["items"] if i["id"] != "H2"]
    for disposition in rec["dispositions"]:
        disposition["items"] = [i for i in disposition["items"] if i != "H2"]
    e3 = by_id(rec)["E3"]
    lines = e3["proposed"].split("\n")
    e3["proposed"] = "\n".join(line for line in lines if not line.startswith("| H2 | "))
    return consistent(rec)


def _quote_line_break_moved():
    rec = record()
    rec["supersedes"][0]["quote"] = "FD3 is the sole inherited\nnon-stdio descriptor"
    assert rec["supersedes"][0]["quote"] not in text(GUIDE)
    return consistent(rec)


def _byte_changed(path, old, new):
    def build():
        data = raw(path)
        assert data.count(old) == 1
        return {path: data.replace(old, new)}
    return build


def _last_byte_changed(path):
    def build():
        data = raw(path)
        return {path: data[:-1] + (b" " if data[-1:] == b"\n" else b"\n")}
    return build


MUTATIONS = [
    ("decided-item-moved-to-W6", _decided_moved_to_w6),
    ("proposed-opens-W7-step-line", _with_proposed("H2", lambda p: p + "\nW7. The child also reports.")),
    ("proposed-holds-list-item", _with_proposed("H2", lambda p: p + "\n- one more call")),
    ("proposed-holds-heading", _with_proposed("H3", lambda p: p + "\n### 5.4a The worker script")),
    ("proposed-holds-quote", _with_proposed("H1", lambda p: p + "\n> a quoted line")),
    ("proposed-holds-blank-line", _with_proposed("H1", lambda p: p.replace("\n", "\n\n", 1))),
    ("proposed-adds-step-label", _with_proposed("H2", lambda p: "W4. " + p)),
    ("proposed-drops-step-label", _with_proposed("H3", lambda p: p[len("W5. "):])),
    ("proposed-trailing-line-feed-disagrees", _with_proposed("H1", lambda p: p + "\n")),
    ("proposed-names-another-obligation",
     _with_proposed("H2", lambda p: once(p, "(W02d).", "(W02d; O-R10-HE006)."))),
    ("hs53-step-line-copied-into-another-step", _with_proposed("H3", lambda p: p + "\n" + HS53_W4_STEP_LINE)),
    ("carriage-return-in-a-string", _carriage_return),
    ("superseded-reordered", _superseded_reordered),
    ("superseded-third-entry", _superseded_third),
    ("superseded-quote-not-in-file", _quote_line_break_moved),
    ("residual-removed", _residual_removed),
    ("obligation-renamed", _obligation_renamed),
    ("item-cites-undeclared-decision", _undeclared_decision),
    ("decision-not-cited", _uncited_decision),
    ("disposition-missing-item", _disposition_missing_item),
    ("decided-item-dropped", _decided_dropped),
    ("hs53-spec-one-byte", _byte_changed(HS53_SPEC, HEADING_0, HEADING_0[:-1] + b"Y")),
    ("published-spec-one-byte", _byte_changed(SPEC, HEADING_0, HEADING_0[:-1] + b"Y")),
    ("hs53-record-one-byte", _last_byte_changed(HS53_RECORD)),
    ("superseded-file-one-byte", _last_byte_changed(GUIDE)),
]


def test_moved_block_start_line_refused():
    """HE5 README, Files (the model's limits; MON-EV12-CR2-GO): a consistent record whose H3 copies the block-start
    step line of HS53's W4 into W5 is refused by `check` (model-derived refusal, input through this file's read)."""
    overrides = dict(MUTATIONS)["hs53-step-line-copied-into-another-step"]()
    lines = text(HS53_SPEC).split("\n")
    _span, _labels, spans = steps(lines)
    assert HS53_W4_STEP_LINE in lines[spans["W4"][0]:spans["W4"][1]] and opens_block(HS53_W4_STEP_LINE)
    with pytest.raises(ValueError):
        model.check(reader(overrides))


@pytest.mark.parametrize("name,build", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_refused(name, build):
    """HE5 README, Files (the model's limits and the model row): each mutation, entered only through this file's own
    read(path), is refused by the model's `check` (model-derived refusal; the README states no refusal texts)."""
    overrides = build()
    with pytest.raises(ValueError):
        model.check(reader(overrides))
