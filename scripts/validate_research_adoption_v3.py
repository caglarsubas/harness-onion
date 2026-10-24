#!/usr/bin/env python3
"""Validate the MET-ADOPT-004 research adoption v3 records and the exact 235-to-234 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
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
    import validate_host_interface_hs43 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_host_interface_hs43 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/research-adoption-v3-authority.json"
AUTHORITY_SHA256 = "8b71b081df3b07303c54df9afcfdb509e0af32e6a2b9560b0fb13a898b66f7cf"
VALIDATOR_PATH = "scripts/validate_research_adoption_v3.py"
BASE_COMMIT = "0d776f75bdca0844d4c6884a29c9fb82b3a61c78"
NEW_PACKET = "MET-ADOPT-004"
PREVIOUS_PACKET = "MET-PERF-038"
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
            require(key not in result, "duplicate research-adoption-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite research-adoption-v3 authority number")

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
    """Newest first: every newer authority, then this one, each read exactly once."""
    successor._checked_authority_raw()
    return _checked_own_authority_raw()


def _checked_own_authority_raw() -> bytes:
    """Fresh complete read of this layer's authority only; callers reach newer
    authorities through exactly one successor route per public call."""
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "research adoption v3 history authority digest")
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
    }, "closed research adoption v3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/research-adoption-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 234
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 234-packet base")
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
    """Undo the newer successor, then this step; every authority is read once."""
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 234-era byte string is already older than the successor layer.
    # Every newer authority and this one are still rechecked before this fast return.
    if rule is not None and digest(raw) == rule["beforeSha256"]:
        _checked_authority_raw()
        return raw
    # The successor route freshly rechecks every newer authority exactly once.
    raw = successor.historical_bytes(path, raw)
    _checked_own_authority_raw()
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
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    raw = successor.historical_test_bytes(raw)
    _checked_own_authority_raw()
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        current = successor.current_test_bytes(before)
        _checked_own_authority_raw()
        return current
    current = successor.historical_bytes(matches[0], regular_bytes(matches[0]))
    _checked_own_authority_raw()
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return successor.current_test_bytes(current)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    packets = successor.historical_catalog(packets)
    _checked_own_authority_raw()
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


# MET-ADOPT-004 (roadmap RA-LICENSE-001; owner decisions Q-HO4-2 to Q-HO4-4, Q-RL-AB, Q-RL-LAYOUT and Q-RL-C, 2026-10-14,
# via the lane monitor, and the user's chat permissions for the reads) publishes research adoption v3 beside the
# byte-identical 2026-09 record, its map and the v2 crosswalk: the licence clarification of litellm, pgvector, langfuse
# and phoenix at pinned commits (each licence text by git blob id and SHA-256 only, never its text) and the 29 planned
# baselines re-checked once with a pinned HEAD commit. Repository bytes are read only through reviewed_bytes, so a later
# bridged successor projects its own edits away first. Every reviewed file of this era is bound by digest before anything
# is parsed and on every later read, and the record's model is executed from this era's bytes (it imports only the
# standard library), so a later revision of it cannot change how this layer judges its era. The repository outcomes,
# pinned commits, scoped artifacts, baseline summary and decision IDs are restated here independently of the records.
OVERLAY_DIR = "architecture/research-adoption-v3/"
LICENCES = OVERLAY_DIR + "licences.json"
BASELINES = OVERLAY_DIR + "planned-baselines.json"
README = OVERLAY_DIR + "README.md"
MODEL = "scripts/research_adoption_v3.py"
# The 2026-09 record, its map, the v2 crosswalk and the licence policy stay byte-identical: v3 is published beside them.
FROZEN_PATHS = ("architecture/research-adoption.json", "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
                "architecture/research-adoption-v2/crosswalk.json", "legal/third-party-license-policy.yaml")
ERA_SHA256 = MappingProxyType({
    "architecture/research-adoption-v2/crosswalk.json": "e1b57c70a63f9b71994b2c25b4c786c9721f34ef34f08729ae6e9fc209010a75",
    "architecture/research-adoption-v3/README.md": "533949a6a33f7a1f1fe40ce8a031ac521ec1905b44fd8c3f6edeb22998bb132f",
    "architecture/research-adoption-v3/licences.json": "4677016fffa1c8049f5ab8d465b063065759e0e9bfe2607355819aed4a0d8fc5",
    "architecture/research-adoption-v3/planned-baselines.json": "33454a56ad7a938da07f612a3112845e6e2b6b675ce8b62caadff79d33e9ac3c",
    "architecture/research-adoption.json": "18dadbbe9aa29b69d18b9ded27e27f6057cf03b437190d14477b2c6908dbc5d5",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md": "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d",
    "legal/third-party-license-policy.yaml": "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0",
    "scripts/research_adoption_v3.py": "68ca03e38e51c0b25a9e579cf4632c016466950763a30f52e17fb360e3f7fc19",
})
DECISIONS = ("Q-HO4-2", "Q-HO4-3", "Q-HO4-4", "Q-RL-AB", "USER-CHAT-AB", "Q-RL-LAYOUT", "Q-RL-C", "USER-CHAT-C")
PINNED = {"BerriAI/litellm": "ccc656873d846e0883b25bce897721bd0e55648c",
          "pgvector/pgvector": "f37c13f68b57d2c3472b2214fbcff699d6d34876",
          "langfuse/langfuse": "fb4449adbdd9f4686e015cb97ac1130b15586a85",
          "Arize-ai/phoenix": "57f8951466de3fa120196ba9a0396b254ea8882d"}
OUTCOMES = {"BerriAI/litellm": ("DENY_UNKNOWN_LICENSE", "DESIGN_REFERENCE_ONLY"),
            "pgvector/pgvector": ("DEFAULT_ALLOWED", "REUSE_AFTER_GATES"),
            "langfuse/langfuse": ("DENY_UNKNOWN_LICENSE", "DESIGN_REFERENCE_ONLY"),
            "Arize-ai/phoenix": ("DENIED", "DESIGN_REFERENCE_ONLY")}
# Each repository's scoped artifacts and their outcomes; phoenix-sqlean is Zlib, on no list of policy 0.3.0 (note N-2),
# and litellm's terraform provider holds a truncated licence text (note N-4), so its artifact leaves that directory out.
SCOPED = {"BerriAI/litellm": {"litellm-without-enterprise-and-terraform-provider": "DEFAULT_ALLOWED"},
          "pgvector/pgvector": {},
          "langfuse/langfuse": {"langfuse-without-ee": "DEFAULT_ALLOWED"},
          "Arize-ai/phoenix": {"phoenix-js-cli": "DEFAULT_ALLOWED", "phoenix-js-config": "DEFAULT_ALLOWED",
                               "phoenix-js-evals": "DEFAULT_ALLOWED", "phoenix-js-mcp": "DEFAULT_ALLOWED",
                               "phoenix-client": "DEFAULT_ALLOWED", "phoenix-otel": "DEFAULT_ALLOWED",
                               "phoenix-sqlean": "DENY_UNKNOWN_LICENSE"}}
# The 15 fetched licence blobs by SHA-256 (repository, then path): the operator-side texts these records stand for.
FETCHED_SHA256 = MappingProxyType({
    "BerriAI/litellm LICENSE": "b170d6bf8e8835dd357e011681db028f4d51e2fb0ea892058f56e01fb39b8273",
    "BerriAI/litellm enterprise/LICENSE.md": "a3160d1176cb556447255ca8652855486d681f8025550291828796a439e1b2f9",
    "BerriAI/litellm terraform/provider/LICENSE": "a82f7ec70737c73fe4c78ec1f58c0d7aeec36e25500ccc1922f7bae1bb39104e",
    "BerriAI/litellm vscode-extension/LICENSE": "bedb01b52def8531f9c294b69a533afd787d0076f3cb99914d579b79a5e77d9d",
    "pgvector/pgvector LICENSE": "6bba9ebeb73e27477463b05e5ef1bf303bccbddb3db9bbc95905d351604d6a87",
    "langfuse/langfuse .agents/skills/skill-creator/license.txt": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "langfuse/langfuse LICENSE": "fd09d42b5b16606ad2042cc1edf3a82da1c47743709f170c959c74758af229d6",
    "langfuse/langfuse ee/LICENSE": "760f5202be4f31f9f8ca43a3c558bebaa5187fa7d7eccad6a32de8392cdccee6",
    "Arize-ai/phoenix LICENSE": "1c5916f5112e30e92f291002bb02cf4f4851c9d1dbdf3360f9f745b7de2d775f",
    "Arize-ai/phoenix js/packages/phoenix-cli/LICENSE": "869963dbff4a3f4e5dc08aabae02b1310a819d41883a669a31400dc35f3b586d",
    "Arize-ai/phoenix js/packages/phoenix-evals/LICENSE": "1d0cf3d5d40e37421c0e1cdaf45670c3edf16a70bcb95bf90b0b8abc14817ea2",
    "Arize-ai/phoenix js/packages/phoenix-mcp/LICENSE": "2244539aa0d8efefb33b65e94ce10ff7381025e6e4bb35ceb976b5f0b202f46d",
    "Arize-ai/phoenix packages/phoenix-client/LICENSE": "eaf2723a549ed4fd3d7696ca1882b228f1b8ac308664c17d76b1b55dca054e0f",
    "Arize-ai/phoenix packages/phoenix-sqlean/LICENSE": "1eefe6802a5cab3964b69c38ef3d8005fb95fe7ef6ac0984cad9f61b38c26d39",
    "Arize-ai/phoenix src/phoenix/vendor/json_canonicalization_scheme/LICENSE.PSF": "af99833f38f9849acc41e2ca1de50a3cb266e712713efa6f377bae4befb16482",
})
SUMMARY = {"baselines": 29, "licenceChanged": 0, "archivedChanged": 0, "archived": 0,
           "policyOutcomes": {"DEFAULT_ALLOWED": 27, "PLANNED_UNRESOLVED": 2}, "clarified": 2,
           "repositories": {name: outcome for name, (outcome, _) in OUTCOMES.items()}}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ADOPT-004 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed research adoption v3 source: " + path)
    return raw


def _era_model() -> types.ModuleType:
    """The record's model of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_adopt_004_research_adoption_v3")
    module.__file__ = str(ROOT / MODEL)
    exec(compile(_verified(MODEL), MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_research_adoption_v3() -> None:
    """Every reviewed byte first; then the model's checks from this era and the independent restatements."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the 2026-09 record, its map, the v2 crosswalk and the policy stay "
                                               "byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    model = _era_model()
    require(model.check(_verified) == SUMMARY, "the model's summary equals the restated one")
    record = parse(_verified(LICENCES))
    rows = {row["repository"]: row for row in record["repositories"]}
    require({name: (row["outcome"], row["licenceCeiling"]) for name, row in rows.items()} == OUTCOMES,
            "repository outcomes and ceilings as restated")
    require({name: row["pinnedCommit"] for name, row in rows.items()} == PINNED, "pinned commits as restated")
    require({name: {a["id"]: a["outcome"] for a in row["scopedArtifacts"]} for name, row in rows.items()} == SCOPED,
            "scoped artifacts as restated")
    require(tuple(row["id"] for row in record["decisions"]) == DECISIONS
            and all(row["date"] == "2026-10-14" for row in record["decisions"]), "decisions recorded and dated")
    require({"%s %s" % (name, text["path"]): text["sha256"] for name, row in rows.items() for text in row["licenceTexts"]
             if text["fetched"] is True} == dict(FETCHED_SHA256), "fetched licence digests as restated")
    require(record["boundaries"]["licenceTextsPublished"] is False and record["boundaries"]["copyAuthorization"] is False,
            "no licence text published and no copy authorized")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "research adoption v3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 263
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 263-packet catalog retaining the 235-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = record["packetSha256"] if path.stem == NEW_PACKET else record["baselinePackets"][path.stem]
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
            "closed source-only research-adoption-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted research-adoption-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_research_adoption_v3()


if __name__ == "__main__":
    validate()
    print("Research adoption v3 valid: 263 current specifications; 235-packet checkpoint and exact 234-packet predecessor; records reviewed.")
