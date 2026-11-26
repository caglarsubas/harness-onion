#!/usr/bin/env python3
"""Validate MET-016 (the hrfix decalign HR-295-FIX-001 and DEC-ALIGN-296-FIX-001, K = 0): V1 this packet's files by digest; E1 each owning record's checker and, where it has one, its model from their era bytes; E2 the base files unchanged; E3 the authored edits at their named lines; V4 the registry rider; V6 the hunk-class record under v2.5."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import copy
import difflib
import hashlib
import json
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/hrfix-decalign-authority.json"
AUTHORITY_SHA256 = "8b510e81c6f232c68589a2d6c88a5be1b0e92313c70d1afaa70eb86e0a7ffe5c"
VALIDATOR_PATH = "scripts/validate_met_016.py"
BASE_COMMIT = "9a78ed88ece963bc115deabd92c2beb3aa29b12b"
NEW_PACKET = "MET-016"
PREVIOUS_PACKET = "MET-015"
MAX_FILE_BYTES = 16_777_216
# Test routes cover the top-level ci/test_ files as well as tests/.
TEST_PREFIXES = ("tests/", "ci/test_")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate hrfix-decalign authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite hrfix-decalign authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _path(path: Any) -> None:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and "\\" not in path and not any(ord(char) < 32 for char in path)
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")


def regular_bytes(path: str) -> bytes:
    _path(path)
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_FILE_BYTES, "bounded regular source file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "hrfix decalign history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed hrfix decalign history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/hrfix-decalign-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 322
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 322-packet base")
    for name, expected in value["baselinePackets"].items():
        require(type(name) is str and name and "/" not in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name)
                and _sha(expected), "predecessor packet identity")
    for path, expected in value["newFiles"].items():
        _path(path)
        require(_sha(expected), "new source digest")
    for path in value["changedFiles"]:
        _path(path)
    special = {AUTHORITY_PATH, VALIDATOR_PATH, "task-packets/" + NEW_PACKET + ".yaml"}
    require(not (set(value["changedFiles"]) & set(value["newFiles"]))
            and not (special & (set(value["changedFiles"]) | set(value["newFiles"])))
            and all(not path.startswith("task-packets/") or path == "task-packets/README.md"
                    for path in set(value["changedFiles"]) | set(value["newFiles"])),
            "disjoint source routes and immutable predecessor packets")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096, "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and 0 <= hunk["at"] <= MAX_FILE_BYTES
                    and prior_at < hunk["at"] and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES and hunk["at"] + len(removed) <= MAX_FILE_BYTES,
                    "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _packet_byte_rules() -> MappingProxyType:
    record = authority()
    return MappingProxyType(dict(record["baselinePackets"],
                                 **{NEW_PACKET: record["packetSha256"]}))


_PACKET_BYTE_RULES = _packet_byte_rules()


def _new_packet_rule() -> tuple[str, str]:
    checksum = _PACKET_BYTE_RULES[NEW_PACKET]
    raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(raw) == checksum, "packet YAML drift: " + NEW_PACKET)
    return checksum, digest(canonical(safe_load(raw)))


_NEW_PACKET_RULE = _new_packet_rule()


@lru_cache(maxsize=1)
def _packet_rules_for(source_root: Path, authority_sha: str) -> MappingProxyType:
    """Freeze expected payload digests once per exact source-root/authority pin."""
    require(source_root == ROOT and authority_sha == AUTHORITY_SHA256,
            "packet source identity changed")
    _checked_authority_raw()
    own_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(own_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    rules = {NEW_PACKET: _NEW_PACKET_RULE}
    for name, checksum in _PACKET_BYTE_RULES.items():
        if name == NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == checksum, "packet YAML drift: " + name)
        rules[name] = (checksum, digest(canonical(safe_load(raw))))
    return MappingProxyType(rules)


def _packet_rules() -> MappingProxyType:
    return _packet_rules_for(ROOT, AUTHORITY_SHA256)


# Only expected parsed-data digests are cached, never a validation verdict.
# Historical traversal checks just this layer's packet. Full payload validation
# hashes every supplied packet anew, and validate() rereads every on-disk YAML.


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(type(at) is int and cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    return _undo_this_layer(path, raw)


def _undo_this_layer(path: str, raw: bytes) -> bytes:
    """Apply only this layer's reviewed inverse; callers have already rechecked authorities."""
    rule = _PROJECTION_RULES.get(path)
    if rule is None:
        return raw
    current_sha = digest(raw)
    require(current_sha in (rule["beforeSha256"], rule["afterSha256"]),
            "unreviewed current source: " + path)
    if current_sha == rule["beforeSha256"]:
        return raw
    before = _inverse(raw, rule["reverseHunks"])
    require(digest(before) == rule["beforeSha256"], "predecessor bytes: " + path)
    return before


def historical_test_bytes(raw: bytes) -> bytes:
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
    require(type(packets) is dict, "packet mapping")
    current_ids = set(_PACKET_BYTE_RULES)
    require(NEW_PACKET in current_ids and set(packets) == current_ids,
            "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    try:
        supplied_sha = digest(canonical(packets[NEW_PACKET]))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("changed packet payload: " + NEW_PACKET) from exc
    require(supplied_sha == _NEW_PACKET_RULE[1],
            "changed packet payload: " + NEW_PACKET)
    return {name: packets[name] for name in current_ids - {NEW_PACKET}}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET}
            and all(rules[name][0] == expected
                    for name, expected in record["baselinePackets"].items())
            and rules[NEW_PACKET][0] == record["packetSha256"],
            "pinned packet data inventory")
    for name, (_byte_sha, payload_sha) in rules.items():
        try:
            supplied_sha = digest(canonical(packets[name]))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("changed packet payload: " + name) from exc
        require(supplied_sha == payload_sha, "changed packet payload: " + name)


# MET-016 (rulings: CONTRACT_298 section 2) adds, in a K = 0 step, two fix members, each landing in the
# owning files of an earlier slot's records: HR-295-FIX-001 (F1-F5 to slot 295's HR-COMPACTION-GOV-001,
# HR-REPLAY-FIXTURES-001 and HR-APPROVAL-OUTCOME-001, with the re-pins they move) and DEC-ALIGN-296-FIX-001
# (D1-D5 to slot 296's GR-DECISION-RECORD-001 and REG-ALIGN-001's checker). Repository bytes are read only
# through reviewed_bytes; an era file is refused unless bound by digest on every read, a changed file by the
# authority's afterSha256. Each refusal is a pure check over the values read. Checked here: V1 the packet's
# twenty-one changed files by digest; E1 per owning record, its checker and its model from their era bytes (the
# record passes its checker; where the record has vectors and a model they also replay here to their
# expectation; HR-REPLAY-FIXTURES-001's replay takes MAS-RA-002's and GR-DECISION-RECORD-001's era models;
# REG-ALIGN-001 has no replay half); E2 the base files unchanged; E3 class-other hunks only at the named
# spans, read under v2.5; V4 the registry rider; V6 the hunk-class record under v2.5. Last, this layer's
# own inverse hunks are the canonical ones.
PACKET_FILES = (
    'architecture/agent-loop-compaction/record.json',
    'architecture/agent-loop-compaction/vectors.json',
    'architecture/approval-outcome/record.json',
    'architecture/approval-outcome/vectors.json',
    'architecture/decision-record/reason-codes.json',
    'architecture/decision-record/vectors.json',
    'architecture/redteam-fixtures/record.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json',
    'architecture/replay-fixtures/record.json',
    'architecture/replay-fixtures/vectors.json',
    'scripts/agent_loop_compaction.py',
    'scripts/approval_outcome.py',
    'scripts/decision_record.py',
    'scripts/replay_fixtures.py',
    'scripts/validate_decision_record.py',
    'scripts/validate_regulatory_alignment.py',
    'scripts/validate_replay_fixtures.py',
    'tests/test_decision_record.py',
    'tests/test_regulatory_alignment.py',
    'tests/test_replay_fixtures.py',
)
BASE_FILES = (
    'architecture/agent-loop-compaction/schema.json',
    'architecture/approval-outcome/schema.json',
    'architecture/artifact-edges/README-v13.md',
    'architecture/artifact-edges/operator-harness-engineering-v13.json',
    'architecture/broker-handoff-inputs-v2/channel.schema.json',
    'architecture/broker-handoff-inputs-v2/vectors.json',
    'architecture/decision-record/README.md',
    'architecture/decision-record/decision-record.schema.json',
    'architecture/decision-record/status.json',
    'architecture/model-weights/record.json',
    'architecture/model-weights/schema.json',
    'architecture/model-weights/vectors.json',
    'architecture/redteam-fixtures/schema.json',
    'architecture/redteam-fixtures/vectors.json',
    'architecture/regulatory-alignment-README.md',
    'architecture/regulatory-alignment.json',
    'architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005',
    'architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3',
    'architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a',
    'architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655',
    'architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591',
    'architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa',
    'architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726',
    'architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json',
    'architecture/replay-fixtures/fixtures/split-fx-dev.json',
    'architecture/replay-fixtures/schema.json',
    'legal/license-policy-amendment-v3/README.md',
    'legal/license-policy-amendment-v3/amendment.json',
    'scripts/broker_handoff_transcript_v2.py',
    'scripts/redteam_fixtures.py',
    'scripts/run_manifest.py',
    'scripts/validate_agent_loop_compaction.py',
    'scripts/validate_approval_outcome.py',
    'scripts/validate_edge_record_v13.py',
    'scripts/validate_model_weights.py',
    'scripts/validate_redteam_fixtures.py',
    'task-packets/EXEC-ML-ADOPT-PINS-001.yaml',
    'tests/test_agent_loop_compaction.py',
    'tests/test_approval_outcome.py',
    'tests/test_edge_record_v13.py',
    'tests/test_model_weights.py',
    'tests/test_redteam_fixtures.py',
)
REGISTRY_BASE_SHA256 = "e64bb65731220d93cd8e1551f4f4eef965723cba8d63249ac328bd925bb61828"
BASE_SHA256 = MappingProxyType({
    "architecture/agent-loop-compaction/schema.json": "7c417668a36a8a825aa157909b51794980b2c57f7d94892f973d612e844e78d9",
    "architecture/approval-outcome/schema.json": "9761fea64edd60d94f2a334c71124dbac4a064094c8092cc40a05bf9368b89e6",
    "architecture/artifact-edges/README-v13.md": "4c15590d34eabee19fd8396888be4d0b0ffdfd1496955d98dcda255ffa5af7b3",
    "architecture/artifact-edges/operator-harness-engineering-v13.json": "4f1b77aa3c0ae93307d2b793d92de2416af8630c27688f925745350c7cbd1226",
    "architecture/broker-handoff-inputs-v2/channel.schema.json": "b050af6bec767beef0796ee4a25edb76b6e761a9b793a4ffd16b4907e910f34e",
    "architecture/broker-handoff-inputs-v2/vectors.json": "b6154ebc18fe2fcb552971f88af5065441f757eba1b70cddef0090fda260a43d",
    "architecture/decision-record/README.md": "0ff769568fe284f437d781aec649cf3ba1bdbd8efa4b7511481b56607e5d4233",
    "architecture/decision-record/decision-record.schema.json": "56e9694bfb93c04c66e058eeda412b6e8ca187c9d66285baec717112f659bad6",
    "architecture/decision-record/status.json": "fe54c9b78f133c63e339316730090263469def180d298180aeb9dffea63474d2",
    "architecture/model-weights/record.json": "0e2f083f97089a0099064ccafd1778c4af22773d206494eed716b811f1266ce3",
    "architecture/model-weights/schema.json": "de04c8d21c105a7f953ae07d703b9568dad4f21115b08a49c4ed0de5b14e3295",
    "architecture/model-weights/vectors.json": "86ccfff1d25b5f6326b1b568334bb0b983e3733386ac833e0d8a30ea2bedcdd6",
    "architecture/redteam-fixtures/schema.json": "c8efa99c951236f10840776c87a1947ecb966996fa37fc6a84f4efdb695e330d",
    "architecture/redteam-fixtures/vectors.json": "3927dbf02217cb2be6661218213ba79ed41311683e19aae4eb404129a0c9ba51",
    "architecture/regulatory-alignment-README.md": "5fce1c75110b0222f603ea0fed3a2af705ec4e0dc06f3c68b9ec8c24f69de733",
    "architecture/regulatory-alignment.json": "98532820261fa1a51a67998fff1126586329a5b5ef7fe09e0e026501b24e95e1",
    "architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005": "1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005",
    "architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3": "579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3",
    "architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a": "5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a",
    "architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655": "747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655",
    "architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591": "acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591",
    "architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa": "af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa",
    "architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726": "e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json": "7270f3af455f87e6cb1160b8f15bfe6e00c7602178c52bef6ec7ba1d37a3cdca",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json": "081a2f36d05dc04aaa70921ac7a73beef6814937761b8601ed0b65ddee56ca10",
    "architecture/replay-fixtures/fixtures/split-fx-dev.json": "4d41d4b3831364c1b11432f12652590ce3b20c4923f2eced5a67a4cc12821251",
    "architecture/replay-fixtures/schema.json": "dd8242f5965f3d89a801005b8de92d923fb7ba621532d637b4b50669113d1f19",
    "legal/license-policy-amendment-v3/README.md": "ca6e12ff8fa36abf701a5452c77ce8e1524021d367d04e04ed435b9745043773",
    "legal/license-policy-amendment-v3/amendment.json": "bd945219dff8005353765c3d59992a853bd96cc9b1a4a3e059d64359707bc1fc",
    "scripts/broker_handoff_transcript_v2.py": "6344e54d229ef46efa3698e2068b05ff247257750307ad749ddc2bbad06e94f9",
    "scripts/redteam_fixtures.py": "6a8d2e368d5895125d618e6a2d257c03a38b84c09f89b36b25d444d8ebd42773",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e",
    "scripts/validate_agent_loop_compaction.py": "74f626fc206edb2dd09d798e3c3c75bb55a63656cecfc7b4a72903c56a533340",
    "scripts/validate_approval_outcome.py": "19cde90072ba7e34904a6d5bcb2ef0e0b7e9cce661a672a37885ae0f556435a7",
    "scripts/validate_edge_record_v13.py": "f3d3eb218e709d81b6ca110e1d3e1df268097c48888acbbf9e7b8f799690d2e4",
    "scripts/validate_model_weights.py": "27fd70749930d104e74c3a173be79bc25945a44352d7e609937089e09716f969",
    "scripts/validate_redteam_fixtures.py": "fdeda77d86774c2fd1dc89343e215c099b38bca25c3f203a42c5f380f139d7ee",
    "task-packets/EXEC-ML-ADOPT-PINS-001.yaml": "05b84bf42325995eb928c310623fa109aba2e99fc0765701e23569565d89734f",
    "tests/test_agent_loop_compaction.py": "f9d531b1deeca6a5a1b8c9617ae670f9f17340d2d4f784a8d5c387608d5ec81d",
    "tests/test_approval_outcome.py": "d6d7796ad42bdb78df9ab9bfe605df77001a0a9ae882ba6fb2a875c983025775",
    "tests/test_edge_record_v13.py": "e5593e6fc2ce2127e937ec40b5956b60843cdb22d1a82ee32b60572ac8bb1eb9",
    "tests/test_model_weights.py": "529af8b0516aaeef7a01d060edfefb6531fcc883236f653bb3500ea9262ebaaf",
    "tests/test_redteam_fixtures.py": "fd53c6a5175ec3c4225b19e894b82b85c9d414a8b9d853167e2f8ca750e5a093",
})
ERA_SHA256 = MappingProxyType({
    "architecture/agent-loop-compaction/record.json": "71baf0f1cc96a98eef52e955e2dec3670d02b37ed35db8ace009b88964e66746",
    "architecture/agent-loop-compaction/schema.json": "7c417668a36a8a825aa157909b51794980b2c57f7d94892f973d612e844e78d9",
    "architecture/agent-loop-compaction/vectors.json": "df7029ec322f1afbf208b0b37a2a7f683a1e1948312460f8ec9bad7626a1d0c4",
    "architecture/agent-loop/README.md": "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a",
    "architecture/agent-loop/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/status.json": "0410907c3f6b9ac6907fcadc7767678b01c65c24593b0d5ae84a95ca63c581ad",
    "architecture/approval-outcome/record.json": "e6b1b6afef526f588a254ac2c4df5d076983cafd90ec88980e30cb70349181b9",
    "architecture/approval-outcome/schema.json": "9761fea64edd60d94f2a334c71124dbac4a064094c8092cc40a05bf9368b89e6",
    "architecture/approval-outcome/vectors.json": "cba4bb16d70e7bc6eaa0177e1e93b3852228c717c5355f0a60936fc85be7cb7c",
    "architecture/artifact-edges/README-v13.md": "4c15590d34eabee19fd8396888be4d0b0ffdfd1496955d98dcda255ffa5af7b3",
    "architecture/artifact-edges/operator-harness-engineering-v13.json": "4f1b77aa3c0ae93307d2b793d92de2416af8630c27688f925745350c7cbd1226",
    "architecture/broker-handoff-inputs-v2/channel.schema.json": "b050af6bec767beef0796ee4a25edb76b6e761a9b793a4ffd16b4907e910f34e",
    "architecture/broker-handoff-inputs-v2/vectors.json": "b6154ebc18fe2fcb552971f88af5065441f757eba1b70cddef0090fda260a43d",
    "architecture/decision-record/README.md": "0ff769568fe284f437d781aec649cf3ba1bdbd8efa4b7511481b56607e5d4233",
    "architecture/decision-record/decision-record.schema.json": "56e9694bfb93c04c66e058eeda412b6e8ca187c9d66285baec717112f659bad6",
    "architecture/decision-record/reason-codes.json": "3facd3c5c97c7564628c9563c9c1790a20addcdbcd2d05f82b86d71c1b70b6ba",
    "architecture/decision-record/status.json": "fe54c9b78f133c63e339316730090263469def180d298180aeb9dffea63474d2",
    "architecture/decision-record/vectors.json": "f558fabf91c2c71beaad72f8afddc48e6c087dd07ba7e75442d823a3472c40a8",
    "architecture/model-weights/record.json": "0e2f083f97089a0099064ccafd1778c4af22773d206494eed716b811f1266ce3",
    "architecture/model-weights/schema.json": "de04c8d21c105a7f953ae07d703b9568dad4f21115b08a49c4ed0de5b14e3295",
    "architecture/model-weights/vectors.json": "86ccfff1d25b5f6326b1b568334bb0b983e3733386ac833e0d8a30ea2bedcdd6",
    "architecture/redteam-fixtures/record.json": "652f172dc110e852498bf1699433a078f18e07e1fc4142824acca3d9973ff905",
    "architecture/redteam-fixtures/schema.json": "c8efa99c951236f10840776c87a1947ecb966996fa37fc6a84f4efdb695e330d",
    "architecture/redteam-fixtures/vectors.json": "3927dbf02217cb2be6661218213ba79ed41311683e19aae4eb404129a0c9ba51",
    "architecture/regulatory-alignment-README.md": "5fce1c75110b0222f603ea0fed3a2af705ec4e0dc06f3c68b9ec8c24f69de733",
    "architecture/regulatory-alignment.json": "98532820261fa1a51a67998fff1126586329a5b5ef7fe09e0e026501b24e95e1",
    "architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005": "1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005",
    "architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3": "579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3",
    "architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a": "5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a",
    "architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655": "747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655",
    "architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591": "acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591",
    "architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa": "af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa",
    "architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726": "e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json": "7270f3af455f87e6cb1160b8f15bfe6e00c7602178c52bef6ec7ba1d37a3cdca",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json": "55e4f9c2c404c9b16b7b66e1f559105c56cfcea6f1a5307ce1f22506f56f4a29",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json": "081a2f36d05dc04aaa70921ac7a73beef6814937761b8601ed0b65ddee56ca10",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json": "8558998c99976735b16a2183ad27400a0c2e636674d852d76bb00289564fd20b",
    "architecture/replay-fixtures/fixtures/split-fx-dev.json": "4d41d4b3831364c1b11432f12652590ce3b20c4923f2eced5a67a4cc12821251",
    "architecture/replay-fixtures/record.json": "73e759140786fe64f45894e6121fed3b3f65a4babeeaf13d47ed145b9bffe48c",
    "architecture/replay-fixtures/schema.json": "dd8242f5965f3d89a801005b8de92d923fb7ba621532d637b4b50669113d1f19",
    "architecture/replay-fixtures/vectors.json": "1614e144820be47c7e9ba7e51bdaeb614cf5a447661b162fcd53081c3c4a92f7",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "16b8cf87bc1aa1b5dc97f41536f27fc7cb0a088fb9fa0869653d9fd810e0dc11",
    "architecture/run-manifest/README.md": "279d374e5ddd1b6305611f3565a7af14046b305e59cf9634a88bd358818ce826",
    "architecture/run-manifest/evaluation-record.schema.json": "8b34740168f5a96f0186b69f9a1a43c544fdd971ed052f8e723c14dda1c3e625",
    "architecture/run-manifest/run-manifest.schema.json": "ec62c1322179c44df40220a21806e1a0d17d25cc437a9a7e252cd4b1cf9d9636",
    "architecture/run-manifest/status.json": "eb3ddd45e43ab6b2dc8c1272e338c49cf15bbe91794e22ddb47026ac1b28b5b7",
    "ci/chain_checkpoint.py": "8c8789073698f4e7441b6fda6e7fae8675ad9e8cdd3b30c1a4471809fdc874a0",
    "legal/license-policy-amendment-v3/README.md": "ca6e12ff8fa36abf701a5452c77ce8e1524021d367d04e04ed435b9745043773",
    "legal/license-policy-amendment-v3/amendment.json": "bd945219dff8005353765c3d59992a853bd96cc9b1a4a3e059d64359707bc1fc",
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68",
    "scripts/agent_loop_compaction.py": "58b60e9258203f453243f160ac36b7ab4cab221f1df02f6a8a3bc46f3aff43c6",
    "scripts/approval_outcome.py": "fc62ba716163ddec63e6999ffd577bf621a310bcad97851641ecb516cf278404",
    "scripts/broker_handoff_transcript_v2.py": "6344e54d229ef46efa3698e2068b05ff247257750307ad749ddc2bbad06e94f9",
    "scripts/decision_record.py": "2a17c8a3c79c28e72b35967441858f5a8e51834c2063fb1c86494eecdc7aea1d",
    "scripts/redteam_fixtures.py": "6a8d2e368d5895125d618e6a2d257c03a38b84c09f89b36b25d444d8ebd42773",
    "scripts/replay_fixtures.py": "67ff76abb97c7b4c1adfa3521b97a4fe65501c4d882f528f7180641411b1e0bc",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e",
    "scripts/validate_agent_loop_compaction.py": "74f626fc206edb2dd09d798e3c3c75bb55a63656cecfc7b4a72903c56a533340",
    "scripts/validate_approval_outcome.py": "19cde90072ba7e34904a6d5bcb2ef0e0b7e9cce661a672a37885ae0f556435a7",
    "scripts/validate_decision_record.py": "c701b73d99a340d0327a036a6c02d55362e42a8c35072d07cc43ca69fb48ff86",
    "scripts/validate_edge_record_v13.py": "f3d3eb218e709d81b6ca110e1d3e1df268097c48888acbbf9e7b8f799690d2e4",
    "scripts/validate_model_weights.py": "27fd70749930d104e74c3a173be79bc25945a44352d7e609937089e09716f969",
    "scripts/validate_redteam_fixtures.py": "fdeda77d86774c2fd1dc89343e215c099b38bca25c3f203a42c5f380f139d7ee",
    "scripts/validate_regulatory_alignment.py": "02ac41002665b48f64e7f0614862a79da3a15fd6bd63adc8c9c952b56ca23feb",
    "scripts/validate_replay_fixtures.py": "04682b10ae3a7533d18f8c0a0104ceb688aee49b29d2281615c0b98bad8d30ce",
    "task-packets/EXEC-ML-ADOPT-PINS-001.yaml": "05b84bf42325995eb928c310623fa109aba2e99fc0765701e23569565d89734f",
    "tests/test_agent_loop_compaction.py": "f9d531b1deeca6a5a1b8c9617ae670f9f17340d2d4f784a8d5c387608d5ec81d",
    "tests/test_approval_outcome.py": "d6d7796ad42bdb78df9ab9bfe605df77001a0a9ae882ba6fb2a875c983025775",
    "tests/test_decision_record.py": "8cbbd9f23912b066e2326c06a8f9e8c229ffd739aa01ccd3e59411f0b2701641",
    "tests/test_edge_record_v13.py": "e5593e6fc2ce2127e937ec40b5956b60843cdb22d1a82ee32b60572ac8bb1eb9",
    "tests/test_model_weights.py": "529af8b0516aaeef7a01d060edfefb6531fcc883236f653bb3500ea9262ebaaf",
    "tests/test_redteam_fixtures.py": "fd53c6a5175ec3c4225b19e894b82b85c9d414a8b9d853167e2f8ca750e5a093",
    "tests/test_regulatory_alignment.py": "c0a1c2019c72faf0172d9c269ed19df00998a16de7e63a951af20429b5577818",
    "tests/test_replay_fixtures.py": "f5cfaef54ad9bf445b7e598bbc710a28ad6f986174aea16ee56d4b512f83d33b",
})
ERRATA_LINES = MappingProxyType({
    "architecture/agent-loop-compaction/record.json": ((16, 16), (20, 20), (117, 117), (119, 119)),
    "architecture/agent-loop-compaction/vectors.json": ((103, 103), (165, 165)),
    "architecture/approval-outcome/record.json": ((12, 12), (16, 16), (175, 175), (280, 280), (312, 312)),
    "architecture/approval-outcome/vectors.json": ((1340, 1340), (2261, 2261)),
    "architecture/decision-record/reason-codes.json": ((13, 13), (21, 21), (25, 25), (161, 161), (243, 243), (282, 282), (318, 318), (382, 382)),
    "architecture/decision-record/vectors.json": ((2645, 2645),),
    "architecture/redteam-fixtures/record.json": ((34, 34), (38, 38), (42, 42), (46, 46), (50, 50)),
    "architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json": ((35, 35),),
    "architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json": ((40, 40),),
    "architecture/replay-fixtures/record.json": ((12, 12), (16, 16), (142, 142), (146, 146), (272, 272), (339, 339)),
    "architecture/replay-fixtures/vectors.json": ((101, 101), (136, 136), (164, 164), (198, 198), (201, 201), (240, 240), (425, 425), (464, 464), (515, 515), (554, 554), (603, 603), (608, 608), (620, 620), (625, 625), (680, 680), (694, 694), (744, 744), (798, 798), (857, 857), (911, 911), (968, 968), (1022, 1022), (1079, 1079), (1133, 1133), (1165, 1165), (1170, 1170), (1221, 1221), (1578, 1578), (1609, 1609), (1645, 1645), (1675, 1675), (1710, 1710), (1776, 1776), (1800, 1800), (1854, 1854), (1891, 1891), (1917, 1917), (1943, 1943), (1964, 1965), (1981, 1981), (1985, 1986), (1995, 1996), (2026, 2027), (2043, 2043), (2047, 2048), (2057, 2058), (2087, 2088), (2104, 2104), (2108, 2109), (2118, 2119), (2142, 2143), (2159, 2159), (2163, 2164), (2173, 2174), (2197, 2198), (2214, 2214), (2218, 2219), (2228, 2229), (2252, 2253), (2269, 2269), (2273, 2274), (2283, 2284), (2307, 2308), (2324, 2324), (2328, 2329), (2352, 2353), (2369, 2369), (2373, 2373), (2383, 2384), (2407, 2408), (2424, 2424), (2428, 2429), (2438, 2439), (2465, 2465), (2481, 2481), (2485, 2486), (2495, 2496), (2519, 2520), (2536, 2536), (2540, 2541), (2550, 2551), (2574, 2575), (2591, 2591), (2595, 2596), (2601, 2601), (2605, 2606), (2616, 2618), (2620, 2620), (2637, 2638), (2652, 2652), (2691, 2691), (2734, 2734), (2738, 2739), (2748, 2749), (2778, 2779), (2793, 2793), (2832, 2832), (2875, 2875), (2879, 2880), (2889, 2890), (2914, 2915), (2931, 2931), (2935, 2936), (2941, 2941), (2945, 2946), (2956, 2958), (2960, 2960), (2974, 2975), (2989, 2989), (3028, 3028), (3071, 3071), (3075, 3076), (3085, 3086), (3091, 3091), (3096, 3098), (3100, 3100), (3104, 3104), (3113, 3113), (3148, 3148), (3166, 3166), (3201, 3201), (3221, 3221), (3256, 3256), (3272, 3272), (3361, 3361), (3402, 3402), (3471, 3471), (3512, 3512), (3578, 3578), (3619, 3619), (3682, 3682), (3723, 3723), (3786, 3786), (3827, 3827), (3879, 3879), (3944, 3944)),
    "scripts/agent_loop_compaction.py": ((62, 62), (64, 64), (73, 73), (79, 79), (81, 81)),
    "scripts/approval_outcome.py": ((287, 287), (322, 323)),
    "scripts/decision_record.py": ((42, 43), (60, 60), (135, 135), (140, 140), (159, 160), (187, 187), (221, 223)),
    "scripts/replay_fixtures.py": ((8, 8), (314, 315), (318, 318), (323, 323), (328, 328), (330, 331), (370, 370), (380, 381), (392, 392), (480, 481), (495, 496), (517, 517), (519, 519), (527, 527), (530, 530)),
    "scripts/validate_decision_record.py": ((17, 17), (59, 59), (217, 217)),
    "scripts/validate_regulatory_alignment.py": ((9, 9), (13, 13), (20, 20), (57, 57), (91, 91), (104, 104), (119, 119), (127, 127), (160, 162), (186, 186)),
    "scripts/validate_replay_fixtures.py": ((19, 20), (34, 34), (37, 37), (258, 258)),
    "tests/test_ci_performance.py": ((169, 169),),
    "tests/test_credential_lifecycle.py": ((362, 362),),
    "tests/test_decision_record.py": ((247, 247),),
    "tests/test_regulatory_alignment.py": ((9, 9), (138, 138)),
    "tests/test_replay_fixtures.py": ((33, 33), (105, 105), (119, 120), (124, 124)),
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.5 keeps v2.3's vocabulary
NORMALISED = ("bridge", "cascade", "record", "register")                   # the mechanics forms v2.5 normalises
HUNK_RULE_SHA256 = "106e577175d692a5d627b2b21a0adfab8c4cb9cc4e06d7d45d97be5ef663c778"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-016 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-016 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-016 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-016 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-016 bound file drift: " + path)
    return raw


def _parsed(raw: Any) -> Any:
    """raw as this layer's strict JSON, or None when it is not bytes holding such JSON."""
    try:
        return parse(raw) if type(raw) is bytes else None
    except ValueError:
        return None


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def check_registry(raw: Any, briefs: Any) -> None:
    """V4: the registry differs from the base by exactly this packet's one rider, appended last and pointing at the
    generic packet brief with the sha256 of the brief's bytes; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list and type(briefs) is dict
           and all(type(briefs[rider[2]]) is bytes for rider in RIDERS)
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == registry["briefs"][-len(RIDERS):]
           == [{"kind": rider[0], "series": rider[1], "path": rider[2], "sha256": digest(briefs[rider[2]]),
                "version": rider[3]} for rider in RIDERS]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-016 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-016 V1 the packet files are exactly the twenty-one")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-016 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def _v25_source(path: str) -> bytes:
    """The reader's era-verified bytes with one alias line: its v2.5 copy answers as `classify` (the identity rule's
    attribute names hold `classify`, not `classify_v25`)."""
    return _verified(path) + b"\nclassify = classify_v25\n"


def _era_rule(path: str, name: str) -> types.ModuleType:
    """The reader's v2.5 rule as an era model, executed from its verified bytes plus the alias line (no import, no
    bytecode); it imports only the standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_v25_source(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _v24_context(record: Any, context: Any) -> dict:
    """v2.5's inputs from this step's authority and the record's context (the reader's context_v24 form): the catalog
    pair from the authority's baselinePackets size, then countPairs; no products (K = 0); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": [], "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.5: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.5's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files; and
    every class equals v2.5's class at its position."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-016 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-016 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": []},
           "MET-016 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-016 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-016 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the hunk-class record (bound by its newFiles digest), the changed files (bound by their afterSha256) and
    the reader's copy of v2.5, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()
              if "reverseHunks" in entry}
    rule = _era_rule(READER_PATH, READER_NAME)
    side = _parsed(raw)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).count(
        b'RULE_V25_SHA256 = "' + HUNK_RULE_SHA256.encode("ascii") + b'"') == 1 else None
    context = _v24_context(record, side["hunkClassContext"]) if _holds(
        lambda: _v24_context(record, side["hunkClassContext"]) is not None) else None
    check_hunk_record(raw, record["changedFiles"], afters, rule.classify, context, rule_sha)


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's executed copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its reviewed bytes; named imports resolve to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_errata(classes: Any, changed: Any, befores: Any) -> None:
    """E3: class-other (authored) hunks fall only on the named files; each carries one, and each such hunk lies inside one
    of its file's named base-line spans: placed in the before bytes by its offset plus the earlier hunks' shift, its
    before-text is there, and the base lines it spans are within the span; every other hunk is a mechanics form v2.5
    normalises."""
    _bound(lambda: type(classes) is dict and type(changed) is dict
           and all(cls in NORMALISED or (cls == "other" and path in ERRATA_LINES) for path in classes for cls in classes[path]),
           "MET-016 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-016 E3 the named file carries its authored hunk: " + path)
        before, shift = befores[path], 0
        for position, (cls, hunk) in enumerate(zip(classes[path], changed[path]["reverseHunks"])):
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            at = hunk["at"] + shift
            shift += len(inserted) - len(removed)
            if cls == "other":
                start = before[:at].count(b"\n") + 1
                end = start + inserted[:-1].count(b"\n")
                _bound(lambda: before[at:at + len(inserted)] == inserted
                       and any(first <= start and end <= last for first, last in spans),
                       "MET-016 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


MEMBERS = (                                     # the owning records, in CONTRACT_298 section 3's member order
    MappingProxyType({"item": "HR-COMPACTION-GOV-001", "module": "agent_loop_compaction",
                      "model": "scripts/agent_loop_compaction.py", "modelName": "_met_016_agent_loop_compaction",
                      "checker": "scripts/validate_agent_loop_compaction.py", "checkerName": "_met_016_validate_agent_loop_compaction",
                      "record": "architecture/agent-loop-compaction/record.json", "vectors": "architecture/agent-loop-compaction/vectors.json",
                      "bases": ()}),
    MappingProxyType({"item": "HR-REPLAY-FIXTURES-001", "module": "replay_fixtures",
                      "model": "scripts/replay_fixtures.py", "modelName": "_met_016_replay_fixtures",
                      "checker": "scripts/validate_replay_fixtures.py", "checkerName": "_met_016_validate_replay_fixtures",
                      "record": "architecture/replay-fixtures/record.json", "vectors": "architecture/replay-fixtures/vectors.json",
                      "bases": (('run_manifest', 'scripts/run_manifest.py'), ('decision_record', 'scripts/decision_record.py'))}),
    MappingProxyType({"item": "HR-APPROVAL-OUTCOME-001", "module": "approval_outcome",
                      "model": "scripts/approval_outcome.py", "modelName": "_met_016_approval_outcome",
                      "checker": "scripts/validate_approval_outcome.py", "checkerName": "_met_016_validate_approval_outcome",
                      "record": "architecture/approval-outcome/record.json", "vectors": "architecture/approval-outcome/vectors.json",
                      "bases": ()}),
    MappingProxyType({"item": "GR-DECISION-RECORD-001", "module": "decision_record",
                      "model": "scripts/decision_record.py", "modelName": "_met_016_decision_record",
                      "checker": "scripts/validate_decision_record.py", "checkerName": "_met_016_validate_decision_record",
                      "record": "architecture/decision-record/reason-codes.json", "vectors": "architecture/decision-record/vectors.json",
                      "bases": ()}),
    MappingProxyType({"item": "REG-ALIGN-001", "module": "regulatory_alignment",
                      "model": None, "modelName": None,
                      "checker": "scripts/validate_regulatory_alignment.py", "checkerName": "_met_016_validate_regulatory_alignment",
                      "record": "architecture/regulatory-alignment.json", "vectors": None,
                      "bases": ()}),
)
COMPACTION, REPLAY, APPROVAL, DECISION, ALIGNMENT = MEMBERS
SLOT = 298
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/298.json"
READER_NAME = "_met_016_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_015.py",
                                 "prevTest": "tests/test_met_015.py", "steps": (1, 1), "countPairs": ()})


def _era_checker(member: Any) -> tuple:
    """A member's model and checker, each executed from its era-verified bytes (no import from this layer); the
    checker's imports of the model, and of a base model the member names, resolve to the era copies: under `scripts`
    (CONTRACT_295 4a N2) and under their bare names (ORC-295-C2-Q1 (a)), the same objects. Each base runs with the
    bases listed before it injected, the model with all of them (CONTRACT_296 4a difference 1 (ii); BUILD_PLAN_296
    ERR-4), and a member with no model gets its checker alone with its bases (difference 1 (i))."""
    era = {}

    def injected() -> dict | None:
        return dict(era, scripts=types.SimpleNamespace(**era)) if era else None
    for name, path in member["bases"]:
        era[name] = _era_model(path, "_met_016_" + name, injected())
    model = None
    if member["model"] is not None:
        model = _era_model(member["model"], member["modelName"], injected())
        era[member["module"]] = model
    checker = _era_model(member["checker"], member["checkerName"], injected())
    return model, checker


def check_compaction(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-COMPACTION-GOV-001): the record passes the era checker (CG_SHAPE to CG_VECTOR) over this era's bytes; and
    the head itself replays every vector, by the vectors file's own list and independently of the checker's, through the
    era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-016 E1 the compaction record passes its checker (CG_SHAPE to CG_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-016 E1 every compaction vector replays through its era model to its expectation")


def validate_compaction(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(COMPACTION)
    vectors = json.loads(_verified(COMPACTION["vectors"]))
    check_compaction(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_replay_fixtures(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-REPLAY-FIXTURES-001): the record passes the era checker (RF_SHAPE to RF_VECTOR) over this era's bytes; and
    the head itself replays every vector, by the vectors file's own list and independently of the checker's, through the
    era model over the vectors' stores, MAS-RA-002's era model and GR-DECISION-RECORD-001's era model
    to its expectation (the count is the parsed list's
    length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-016 E1 the replay-fixture record passes its checker (RF_SHAPE to RF_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-016 E1 every replay-fixture vector replays through its era model to its expectation")


def validate_replay_fixtures(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay through the
    era model's replay_vectors (ORC-295-C2-Q2 (a)), with MAS-RA-002's run_manifest (a base file) and
    GR-DECISION-RECORD-001's decision model (a packet file; F5 injects it) from their era bytes."""
    model, checker = _era_checker(REPLAY)
    vectors = json.loads(_verified(REPLAY["vectors"]))
    rm = _era_model(REPLAY["bases"][0][1], "_met_016_" + REPLAY["bases"][0][0])
    dr = _era_model(REPLAY["bases"][1][1], "_met_016_" + REPLAY["bases"][1][0])
    check_replay_fixtures(vectors, checker.check(_era_read),
                          model.replay_vectors(vectors["cases"], vectors["stores"], rm, dr))


def check_approval_outcome(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-APPROVAL-OUTCOME-001): the record passes the era checker (AO_RECORD to AO_VECTOR) over this era's bytes;
    and the head itself replays every vector, by the vectors file's own list and independently of the checker's,
    through the era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-016 E1 the approval outcome record passes its checker (AO_RECORD to AO_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-016 E1 every approval outcome vector replays through its era model to its expectation")


def validate_approval_outcome(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(APPROVAL)
    vectors = json.loads(_verified(APPROVAL["vectors"]))
    check_approval_outcome(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_decision_record(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (GR-DECISION-RECORD-001): the record passes the era checker (DR_SHAPE to DR_VECTOR) over this era's bytes;
    and the head itself replays every vector, by the vectors file's own list and independently of the checker's,
    through the era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-016 E1 the decision record passes its checker (DR_SHAPE to DR_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-016 E1 every decision record vector replays through its era model to its expectation")


def validate_decision_record(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(DECISION)
    vectors = json.loads(_verified(DECISION["vectors"]))
    check_decision_record(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_regulatory_alignment(refusals: Any) -> None:
    """E1 (REG-ALIGN-001): the record passes the era checker (RA_SHAPE to RA_SOURCES) over this era's bytes; the
    member has no vectors file and no model, so there is no replay half (CONTRACT_296 4a difference 3)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-016 E1 the regulatory alignment record passes its checker (RA_SHAPE to RA_SOURCES)")


def validate_regulatory_alignment(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader; no vectors are read."""
    model, checker = _era_checker(ALIGNMENT)
    check_regulatory_alignment(checker.check(_era_read))


def _era_read(path: Any) -> bytes:
    """The checker's injected reader: an era file's verified bytes; any other path is refused (a ValueError), so a
    packet reference outside the era does not resolve."""
    return _verified(path)


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2: the files of slots 295's, 296's and 297's members (each head's PACKET_FILES at its merge) and MAS-RA-002's
    model, less the files the two fix members change, equal their base bytes, and this step's authority names
    none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-016 E2 the base files equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-016 E2 this step changes no base file")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def validate_met_016(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the packet's files), E1 per member in section 1's order (the checker and the
    model), E2 (the base files), E3 (the authored edits), V4 (the registry) and V6 (the hunk-class record); last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_compaction(packets)
    validate_replay_fixtures(packets)
    validate_approval_outcome(packets)
    validate_decision_record(packets)
    validate_regulatory_alignment(packets)
    validate_base_files()
    validate_errata()
    validate_registry()
    validate_hunk_record()
    validate_canonical_hunks()


def _trim(at: int, removed: bytes, inserted: bytes) -> tuple[int, bytes, bytes]:
    head = 0
    while head < min(len(removed), len(inserted)) and removed[head] == inserted[head]:
        head += 1
    tail = 0
    while (tail < min(len(removed), len(inserted)) - head
           and removed[len(removed) - 1 - tail] == inserted[len(inserted) - 1 - tail]):
        tail += 1
    return at + head, removed[head:len(removed) - tail], inserted[head:len(inserted) - tail]


def canonical_hunks(after: bytes, before: bytes) -> tuple[tuple[int, bytes, bytes], ...]:
    """The canonical byte-minimal reverse hunks (record authorityHunks.algorithm) that turn after back into before."""
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    runs = []
    for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if b - a == d - c:
            runs += [_trim(offsets[a + i], current[a + i], previous[c + i]) for i in range(b - a)
                     if current[a + i] != previous[c + i]]
        else:
            runs.append(_trim(offsets[a], b"".join(current[a:b]), b"".join(previous[c:d])))
    merged: list[tuple[int, bytes, bytes]] = []
    for at, removed, inserted in runs:
        if merged and at <= merged[-1][0] + len(merged[-1][1]):
            prior_at, prior_removed, prior_inserted = merged[-1]
            merged[-1] = (prior_at, after[prior_at:at + len(removed)],
                          prior_inserted + after[prior_at + len(prior_removed):at] + inserted)
        else:
            merged.append((at, removed, inserted))
    return tuple(merged)


def check_canonical_hunks(path: str, rule: Any, after: Any) -> None:
    """Q-PERF40-4 for one path: the rule's hunks are the canonical byte-minimal ones, from this era's bytes."""
    require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
    before = _undo_this_layer(path, after)
    require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        check_canonical_hunks(path, rule, reviewed_bytes(path))


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "hrfix decalign validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 323 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 323-packet catalog")
    packets = {}
    for path in paths:
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
                    else record["baselinePackets"][path.stem])
        require(digest(raw) == expected, "packet YAML drift: " + path.stem)
        packets[path.stem] = safe_load(raw)
    validate_packet_payloads(packets)
    packet = packets[NEW_PACKET]
    previous = packets[PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == [PREVIOUS_PACKET]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 64
            and commands == previous["offlineAcceptanceCommands"]
            and not any(VALIDATOR_PATH in argv for argv in commands),
            "closed source-only hrfix-decalign packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted hrfix-decalign packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_016(packets)


if __name__ == "__main__":
    validate()
    print("Hrfix decalign valid: 323 current specifications at slot 298; exact 322-packet predecessor; contract reviewed.")
