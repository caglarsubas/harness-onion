#!/usr/bin/env python3
"""W03 plan record v2 (architecture/w03-plan-v2/plan.json, W03-AMEND): the v1 plan with the owner's HE-002 decisions.

check(read) validates the closed record through an injected byte reader:
- the two toolchains partition W02d's seven roles;
- every obligation names packets that the plan defines;
- every repository source it cites exists;
- v2 is exactly v1 (architecture/w03-plan/plan.json, byte-identical) with the AMENDMENT below applied.
"""
from __future__ import annotations

import hashlib
import json
import re

RECORD_PATH = "architecture/w03-plan-v2/plan.json"
V1_RECORD_PATH = "architecture/w03-plan/plan.json"
V1_SHA256 = "40b501f48fe0eb13d64d2e0cf7fa542817f0fa3034d86058c233d1a3accaff9a"
SCHEMA = "planeon.internal.w03-plan/v2"
V1_SCHEMA = "planeon.internal.w03-plan/v1"
ALLOWLISTS_PATH = "architecture/seccomp-allowlists-v2/allowlists.json"
PLAN_README = "architecture/w03-plan-v2/README.md"
V1_PLAN_README = "architecture/w03-plan/README.md"
ANCHOR = re.compile(r'"[A-Za-z0-9_.-]+"\Z|[A-Za-z0-9_][A-Za-z0-9_.-]*[A-Za-z0-9_]\Z')
REQUIRED_OBLIGATIONS = ("LIC-RUST-STD", "LIC-GATE", "TR-SETXID", "TR-PARALLELISM", "TR-FDS", "SEC-QW4", "SEC-8",
                        "I05-5", "I05-6", "I07-3", "I07-4", "I07-5", "GATE-OPENAT", "EDGE-1")
RUST_COMMITS = {"1.99.0": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"}
MUSL_PATCHES = ["CVE-2025-26519", "CVE-2026-40200", "CVE-2026-6042"]
MUSL_THREAD_FLAGS = 0x7D0F00  # musl 1.2.5 pthread_create.c:243-245
LINES = re.compile(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*\Z")
OWNER_QUESTIONS = ("Q1", "Q2", "Q3", "Q5", "Q-L3", "Q-S", "Q-HE2-A", "Q-HE2-B", "Q-HE2-C", "Q-HE2-D", "Q-HE2-E",
                   "Q-HE2-F", "Q-HE2-G")
SELECTED = {"Q1": "a", "Q2": "a", "Q3": "a", "Q5": "a", "Q-L3": "L3-a", "Q-S": "S-b", "Q-HE2-A": "a", "Q-HE2-B": "a",
            "Q-HE2-C": "a", "Q-HE2-D": "a", "Q-HE2-E": "a+b", "Q-HE2-F": "all-five", "Q-HE2-G": "b"}
# The owner's HE-002 decisions (2026-10-11, relayed by the lane monitor) as an exact v1 -> v2 transformation.
AMENDMENT = json.loads('{"decisions":[{"id":"Q-HE2-A","selected":"a","summary":"R10 copies the six I05/I07 v3 contract fixtures and six contract READMEs byte-exact, with no model or validator code; the operator -> harness-engineering buildArtifact edge is registered as an edge-registry record (architecture/artifact-edges/) in W03-AMEND before HE-002 merges, covering HE-000\'s transport files retroactively; architecture/repositories.yaml is not edited."},{"id":"Q-HE2-B","selected":"a","summary":"HE-002 is an independent implementation from the pinned contract set; the pinned models and validator lines are specification only where the READMEs are silent, each listed as model-defined behaviour; no line-by-line translation."},{"id":"Q-HE2-C","selected":"a","summary":"HE-002 splits into HE-002 (I05 logic and the I07 frame and byte checks), HE-002B (the I07 PolicyGate) and HE-002C (the durable journal and failure-marker stores)."},{"id":"Q-HE2-D","selected":"a","summary":"Standard library only; SHA-256 tested against NIST CAVP vectors; revisited at HE-003\'s TLS."},{"id":"Q-HE2-E","selected":"a+b","summary":"R10-local vectors R10-L01 to R10-L03, and the supplementary I05-4 vectors in harness-onion (architecture/i05-gate-channel-v3-supplement/, W03-AMEND)."},{"id":"Q-HE2-F","selected":"all-five","summary":"Plan changes (all five, as the owner answered): the HE-002/HE-002B/HE-002C split; the I05 and I07 channel substrate moves to HE-003; HE-002C owns the gate\'s single journal format, I07 records included; a new HE-002S takes SEC-4 and HI-7 for EFFECT_GATE; the vehicle is the meta packet W03-AMEND."},{"id":"Q-HE2-G","selected":"b","summary":"The gate opens files only through one audited openat module (the EFFECT_GATE allowlist grants openat, not open); a source check forbids std::fs opens in the gate; T04\'s trace confirms the per-architecture syscalls; no W02d contract change."}],"newPackets":{"W03-0":[{"id":"W03-AMEND","where":"meta","summary":"This plan\'s successor (owner decision Q-HE2-F): the HE-002 split, the channel substrate moved to HE-003, HE-002C\'s single journal format and HE-002S; the operator -> harness-engineering buildArtifact edge registry record (Q-HE2-A) and the supplementary I05-4 vectors (Q-HE2-E) (this packet)."}],"HE-002":[{"id":"HE-002B","where":"R10","summary":"Effect gate framing, I07: the PolicyGate over the I05 gate (maintenance, writable kinds, rendering, the 10-second write bound, the I07 journal records), against the I07 v3 vectors."},{"id":"HE-002C","where":"R10","summary":"Effect gate durable stores: the gate\'s single journal (I05 and I07 records) and the failure-marker store, byte formats, fsync and read-back, torn-record detection and the process restart; files opened only through the audited openat module."},{"id":"HE-002S","where":"R10","summary":"EFFECT_GATE process seal: capabilities, no_new_privs and RLIMIT_CORE=0, then the published compiled seccomp program."}]},"newSummaries":{"HE-002":"Effect gate framing, I05: strict wire codec, schema subset, the I05 v3 gate logic with the in-memory journal and failure marker, against the I05 v3 vectors, the supplementary I05-4 vectors and the I07 v3 frame and byte checks.","HE-003":"Effect gate substrate: the I05 and I07 channel substrate (SOCK_SEQPACKET listeners, per-frame custody, the 2-second answer bound), I04 TLS and HTTP, connection stamping C1-C7, the 900 s upstream bound."},"reassign":{"I05-3":{"from":["HE-002","HE-003"],"to":["HE-002C","HE-003"]},"I05-4":{"from":["HE-002"],"to":["W03-AMEND","HE-002"]},"I07-2":{"from":["HE-007"],"to":["HE-002C","HE-007"]},"SEC-4":{"from":["HE-002","HE-004","HE-005","HE-006","HE-007"],"to":["HE-002S","HE-004","HE-005","HE-006","HE-007"]},"HI-7":{"from":["HE-002","HE-004","HE-005","HE-006","HE-007","HE-008"],"to":["HE-002S","HE-004","HE-005","HE-006","HE-007","HE-008"]}},"newObligations":[{"after":"I05-4","row":{"id":"I05-5","source":"architecture/i05-gate-channel-v3/README.md:22","text":"The I05 v3 gate logic reproduces every I05 v3 vector exactly: configuration refusals, frame, byte and agreement checks, and transcripts with their journal and failure marker.","packets":["HE-002"],"scope":"W03"}},{"after":"I05-5","row":{"id":"I05-6","source":"architecture/i05-gate-channel-v3/README.md:46-52,63-64","text":"The I05 channel substrate: the AF_UNIX SOCK_SEQPACKET listener with one channel per generation, per-frame kernel custody, and the 2-second answer bound.","packets":["HE-003"],"scope":"W03"}},{"after":"I07-2","row":{"id":"I07-3","source":"architecture/i07-policy-write-v3/README.md:21","text":"The I07 v3 frame and byte checks pass against the I07 v3 schema (the error-code prefix compared).","packets":["HE-002"],"scope":"W03"}},{"after":"I07-3","row":{"id":"I07-4","source":"architecture/i07-policy-write-v3/README.md:21","text":"The I07 v3 PolicyGate reproduces every I07 v3 kind, render and outcome check and every transcript exactly.","packets":["HE-002B"],"scope":"W03"}},{"after":"I07-4","row":{"id":"I07-5","source":"architecture/i07-policy-write-v3/README.md:43-44","text":"The I07 channel substrate: one writer session at a time on the maintenance socket and per-frame custody.","packets":["HE-003"],"scope":"W03"}},{"after":"I07-5","row":{"id":"GATE-OPENAT","source":"owner-decision:Q-HE2-G","text":"The gate opens files only through one audited openat module; a source check forbids std::fs opens in the gate; T04\'s trace confirms the per-architecture syscall set against the compiled programs.","packets":["HE-002C","T04"],"scope":"W03"}},{"after":"GATE-OPENAT","row":{"id":"EDGE-1","source":"docs/alpha-2/ENFORCEMENT_INTEGRATION.md:111-113","text":"Register the operator -> harness-engineering buildArtifact edge for every harness-onion file R10 holds, before R10 uses it; a later file, or another version of a listed file, needs a new registry record first.","packets":["W03-AMEND"],"scope":"W03"}}],"notClaimed":["No module logic exists in R10; HE-001 merged the host-enforcement scaffold only.","No host-enforcement artifact is released or enrolled on a host; the verifier builds the scaffold binaries only to check them.","E01-E12 stay OPEN_UNPROVEN."]}')
SELECTION_PATH = "architecture/backend-distribution/selection.json"

WHERE = ("meta", "owner-root", "R10", "native", "other")
MAX_BYTES = 4_194_304
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
OBLIGATION_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
PACKET_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate plan key")
        return dict(items)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "plan record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda name: (_ for _ in ()).throw(ValueError("nonfinite plan number")))


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message):
    require(type(value) is str and value != "" and "\x00" not in value, message)


def _texts(value, message):
    require(type(value) is list and value and all(type(item) is str and item for item in value)
            and len(set(value)) == len(value), message)


def _source(read, source, decisions=()):
    """A cited source: an owner decision of this plan, or a repository file with a line range or an anchor token."""
    if source.startswith("owner-decision:"):
        require(source[len("owner-decision:"):] in decisions, "an owner decision of this plan: " + source)
        return
    path, _, where = source.partition(":")
    require(path not in (RECORD_PATH, PLAN_README, V1_RECORD_PATH, V1_PLAN_README),
            "an obligation cannot cite the plan itself: " + source)
    require(path and not path.startswith("/") and "\\" not in path
            and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe source path: " + source)
    try:
        raw = read(path)
    except OSError:
        raise ValueError("cited source missing: " + source) from None
    if where:
        text = raw.decode("utf-8")
        if LINES.fullmatch(where):
            count = text.count("\n") + (0 if text.endswith("\n") else 1)
            for piece in where.split(","):
                bounds = [int(n) for n in piece.split("-")]
                require(all(1 <= n <= count for n in bounds) and bounds == sorted(bounds),
                        "cited lines outside the file or reversed: " + source)
        else:
            require(ANCHOR.fullmatch(where) and len(where.strip('"')) >= 4
                    and re.search(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_.-])" % re.escape(where), text),
                    "a cited anchor is an identifier or quoted key present as a whole token: " + source)


def _amended(read, value) -> None:
    """v2 equals the byte-identical v1 record with AMENDMENT applied, and nothing else changed."""
    try:
        raw = read(V1_RECORD_PATH)
    except OSError:
        raise ValueError("the v1 plan record is missing") from None
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == V1_SHA256, "the v1 plan record is byte-identical")
    v1 = _json(raw)
    require(v1["schemaVersion"] == V1_SCHEMA, "v1 plan schema")
    packet_ids = {row["id"] for row in v1["packets"]}
    obligation_ids = {row["id"] for row in v1["obligations"]}
    require(set(AMENDMENT["newSummaries"]) <= packet_ids and set(AMENDMENT["newPackets"]) <= packet_ids
            and set(AMENDMENT["reassign"]) <= obligation_ids, "every amendment key names a v1 row")
    expect = dict(v1)
    expect["schemaVersion"] = SCHEMA
    expect["ownerDecisions"] = v1["ownerDecisions"] + AMENDMENT["decisions"]
    packets = []
    for row in v1["packets"]:
        row = dict(row)
        if row["id"] in AMENDMENT["newSummaries"]:
            row["summary"] = AMENDMENT["newSummaries"][row["id"]]
        packets.append(row)
        packets.extend(AMENDMENT["newPackets"].get(row["id"], []))
    expect["packets"] = packets
    obligations = []
    for row in v1["obligations"]:
        row = dict(row)
        if row["id"] in AMENDMENT["reassign"]:
            require(row["packets"] == AMENDMENT["reassign"][row["id"]]["from"], "v1 obligation packets: " + row["id"])
            row["packets"] = AMENDMENT["reassign"][row["id"]]["to"]
        obligations.append(row)
    for item in AMENDMENT["newObligations"]:
        ids = [row["id"] for row in obligations]
        require(item["after"] in ids and item["row"]["id"] not in ids, "amendment obligation placement")
        obligations.insert(ids.index(item["after"]) + 1, item["row"])
    expect["obligations"] = obligations
    expect["notClaimed"] = AMENDMENT["notClaimed"]
    require(value == expect, "the v2 plan is exactly v1 with the owner's HE-002 amendment")
    canonical = (json.dumps(expect, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    require(read(RECORD_PATH) == canonical, "the v2 plan record is in v1's exact formatting")


def check(read) -> dict:
    try:
        return _check(read)
    except (TypeError, KeyError, AttributeError, IndexError) as error:
        raise ValueError("malformed plan record: %s" % error) from None


def _check(read) -> dict:
    value = _json(read(RECORD_PATH))
    _amended(read, value)
    _closed(value, ("schemaVersion", "ownerDecisions", "toolchains", "buildToolchains", "scope", "packets", "obligations",
                    "notClaimed"), "closed plan record")
    require(value["schemaVersion"] == SCHEMA, "plan schema")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and [row.get("id") for row in decisions if type(row) is dict] == list(OWNER_QUESTIONS),
            "owner decisions in order: " + ", ".join(OWNER_QUESTIONS))
    for row in decisions:
        _closed(row, ("id", "selected", "summary"), "closed owner decision")
        require(row["selected"] == SELECTED[row["id"]], "the owner's recorded choice")
        _text(row["summary"], "decision summary")
    tool = value["toolchains"]
    _closed(tool, ("CPYTHON_3_12", "RUST_MUSL_STATIC"), "the two toolchains")
    cpython, rust = tool["CPYTHON_3_12"], tool["RUST_MUSL_STATIC"]
    _closed(cpython, ("roles", "python", "libc"), "closed CPython toolchain")
    require(cpython["python"] == "3.12.14", "CPython 3.12.14")
    _text(cpython["libc"], "CPython libc rule")
    _closed(rust, ("roles", "rust", "targets", "linking", "musl", "threads", "startupRecheck", "startupConstraints",
                   "crates"), "closed Rust toolchain")
    recheck = rust["startupRecheck"]
    _closed(recheck, ("reference", "pinned", "result", "findings"), "closed start-up re-check")
    require(recheck["result"] == "SAME_STARTUP_SYSCALLS" and recheck["pinned"].startswith(
        "Rust " + rust["rust"]["version"]), "start-up re-check result for the pinned Rust")
    _text(recheck["reference"], "re-check reference")
    _texts(recheck["findings"], "re-check findings")
    _closed(rust["rust"], ("version", "commit"), "Rust pin")
    require(RUST_COMMITS.get(rust["rust"]["version"]) == rust["rust"]["commit"], "the Rust version's release commit")
    require(rust["targets"] == ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"], "the two musl targets")
    _closed(rust["musl"], ("version", "patches", "source"), "musl pin")
    require(rust["musl"]["version"] == "1.2.5" and rust["musl"]["patches"] == MUSL_PATCHES, "musl 1.2.5 and its patches as bundled")
    _text(rust["musl"]["source"], "musl source")
    _closed(rust["threads"], ("syscall", "flags", "source", "w02d"), "thread creation record")
    require(rust["threads"]["syscall"] == "clone", "musl creates threads with clone")
    require(type(rust["threads"]["flags"]) is str and re.fullmatch(r"0x[0-9a-f]+", rust["threads"]["flags"])
            and int(rust["threads"]["flags"], 16) == MUSL_THREAD_FLAGS, "musl 1.2.5's documented thread flags")
    require(MUSL_THREAD_FLAGS & 0x7E030900 == 0x10900, "musl's thread flags pass W02d NATIVE_STATIC's thread rule")
    for key in ("linking", "crates"):
        _text(rust[key], "Rust " + key)
    _texts(rust["startupConstraints"], "start-up constraints")
    allowlists = _json(read(ALLOWLISTS_PATH))
    roles = set(allowlists["roles"])
    _texts(cpython["roles"], "CPython roles")
    _texts(rust["roles"], "Rust roles")
    require(set(cpython["roles"]) | set(rust["roles"]) == roles and not set(cpython["roles"]) & set(rust["roles"]),
            "the toolchains partition W02d's roles")
    for role in cpython["roles"]:
        require(allowlists["roles"][role].get("runtimeBase") == "CPYTHON_3_12", "CPython roles use W02d's CPython base")
    for role in rust["roles"]:
        require(allowlists["roles"][role].get("runtimeBase") == "NATIVE_STATIC", "Rust roles use W02d's native base")
    build = value["buildToolchains"]
    _closed(build, ("GO_AGENT_BUILD",), "build toolchains")
    _closed(build["GO_AGENT_BUILD"], ("for", "go", "goNote", "moduleCache", "build"), "closed Go build toolchain")
    require(build["GO_AGENT_BUILD"]["go"] == "1.26.7", "the Go build uses R10's pinned Go 1.26.7")
    for key in ("for", "goNote", "moduleCache", "build"):
        _text(build["GO_AGENT_BUILD"][key], "Go build " + key)
    scope = value["scope"]
    _closed(scope, ("repository", "root", "modules", "support", "signer", "amends"), "closed scope")
    require(scope["repository"] == "caglarsubas/mas-harness-operator" and scope["root"] == "host-enforcement/"
            and scope["modules"] == ["containment", "broker", "observer", "gate", "writer"]
            and scope["support"] == ["host-image", "enrollment"], "owner decision Q5 scope")
    for key in ("signer", "amends"):
        _text(scope[key], "scope " + key)
    packets = value["packets"]
    require(type(packets) is list and packets, "packets")
    for row in packets:
        _closed(row, ("id", "where", "summary"), "closed packet")
        require(PACKET_ID.fullmatch(row["id"]) and row["where"] in WHERE, "packet id and place")
        _text(row["summary"], "packet summary")
    packet_ids = [row["id"] for row in packets]
    require(len(packet_ids) == len(set(packet_ids)), "duplicate packet")
    obligations = value["obligations"]
    require(type(obligations) is list and obligations, "obligations")
    for row in obligations:
        _closed(row, ("id", "source", "text", "packets", "scope"), "closed obligation")
        require(OBLIGATION_ID.fullmatch(row["id"]), "obligation id")
        _text(row["source"], "obligation source")
        _text(row["text"], "obligation text")
        _texts(row["packets"], "obligation packets")
        require(set(row["packets"]) <= set(packet_ids), "obligation packets are planned: " + row["id"])
        require(row["scope"] in ("W03", "OUTSIDE_W03") and (row["scope"] == "OUTSIDE_W03") == ("R12" in row["packets"]),
                "only an obligation outside W03 goes to R12, and then only there: " + row["id"])
        require(row["scope"] == "W03" or row["packets"] == ["R12"], "an outside obligation names R12 alone")
        _source(read, row["source"], [row["id"] for row in value["ownerDecisions"]])
    ids = [row["id"] for row in obligations]
    require(len(ids) == len(set(ids)), "duplicate obligation")
    by_id = {row["id"]: row for row in obligations}
    used = {packet for row in obligations for packet in row["packets"]}
    require(used == set(packet_ids), "every planned packet discharges an obligation, and only planned packets")
    selection = _json(read(SELECTION_PATH))
    cited = {row["source"] for row in obligations}
    for item in selection["openItems"]:
        require(SELECTION_PATH + ":" + item["id"] in cited, "the selection's open item is registered: " + item["id"])
    require("LIC-RUST-STD" in by_id and by_id["LIC-RUST-STD"]["packets"] == ["LIC-HOST"],
            "Rust std's license closure goes through LIC-HOST")
    require("W02D-V3" in packet_ids and "SEC-8" in by_id and "W02D-V3" in by_id["SEC-8"]["packets"],
            "owner decision Q-S (S-b): W02d v3 discharges the steady-state calls")
    require(any(rule.get("name") == "poll" for rule in allowlists["runtimeBases"]["NATIVE_STATIC"]["rules"]),
            "W02d v2's NATIVE_STATIC grants poll")
    for required in REQUIRED_OBLIGATIONS:
        require(required in {row["id"] for row in obligations}, "required obligation registered: " + required)
    _texts(value["notClaimed"], "non-claims")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("W03 plan valid: toolchains partition the W02d roles; every obligation has a planned packet.")
