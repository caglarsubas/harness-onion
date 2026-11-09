"""MET-PERF-049 (slot 286; CONTRACT_286 r6; the visionary's ruling Q-286-IDENTITY, DESIGN-286-READ section 6): the
history chain's identity rule with the era-replay reader clause (xi).

A reference model, not a validate_* layer. It extends MET-SECTOR-005's model (scripts/chain_identity_v3.py, called v3
here) by architecture/chain-era-replay/rule.json and one step clause, without changing v1, v2 or v3 or their records
(C-I1). The caller passes v1 and v2 as module objects and v3 bound by `pin_v3(v3, raw)`, which refuses unless the bytes
the caller read from v3's path hash to V3_SHA256 and the module is chain_identity_v3.py. This module imports no
repository module and reads nothing itself.

- `check_xi(previous_tree, current_tree)`: the clause (xi), the same text as chainmech's strictbridge_v2 form (xi)
  (CONTRACT_286 section 3.11, C8; MA008-P1-3). When the old head's previous-era top-level `_replay` holds
  `<model>.check(regular_bytes, X)`, the current `_replay` must hold `<model>.check(reviewed_bytes, X)` at that one
  position, the direction fixed and every other node of `_replay` equal (required: a live-reading bridged `_replay`
  refuses); a previous era with no such reader gives 0 and its `_replay`, if any, must be unchanged. Returns 0 or 1.
- `check(read, previous, rule, ext, ext3, ext4, slot, catalog, v1, v2, v3)`: v3's check, after (xi) on the old head
  alone. The old head's previous era is projected from its TRUE live bytes; then v3 runs over a `read` that serves the
  old head with the one token undone (counted 1) and a `previous` that, for that path, projects the live bytes, never
  the undone ones (the head's reverse hunks were recorded against the live file). v1's `edits == expected` therefore
  holds unchanged. The summary gains `xi`.
- `check_rules(ext3_raw, ext4_raw)`: the era-replay rule extends the inheritance rule by path, sha256 and clause, delta
  only, with its evidence record.
- `check_xi_vector(case)`: one record vector (sources of the previous and current `_replay`, and the expected outcome).
"""
from __future__ import annotations

import ast
import hashlib
import json

SCHEMA = "harness.planeon.ai/chain-era-replay-rule/v1"
VECTORS_SCHEMA = "harness.planeon.ai/chain-era-replay-vectors/v1"
V3_NAME = "chain_identity_v3.py"
V3_SHA256 = "29483ec356f0d2b10f778fc5c4fe642df94795f8249daa088e7a06c995c67fb9"
EXTENDS = ("architecture/chain-inheritance/rule.json", "ed2a4d41df9a3624ee4c0d835bd1586b075dfe32feffd7eb0d09cce9731a9b10", "xi")
READER = "_replay"
LIVE, PROJECTED = "regular_bytes", "reviewed_bytes"


def refuse(clause, detail):
    raise ValueError("identity %s: %s" % (clause, detail))


def need(ok, clause, detail):
    if not ok:
        refuse(clause, detail)


class PinnedV3:
    """v3 bound by its sha256 (pin_v3)."""


def pin_v3(v3, raw):
    """Bind v3: the caller's bytes must hash to V3_SHA256 and the module must be chain_identity_v3.py."""
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == V3_SHA256, "model",
         "chain_identity_v3.py is not the pinned v3 (%s)" % V3_SHA256[:8])
    need(str(getattr(v3, "__file__", "")).replace("\\", "/").rsplit("/", 1)[-1] == V3_NAME, "model",
         "the v3 module object is not chain_identity_v3.py")
    pinned = PinnedV3()
    pinned.module, pinned.raw = v3, raw
    return pinned


def _v3(pinned):
    need(isinstance(pinned, PinnedV3) and hashlib.sha256(pinned.raw).hexdigest() == V3_SHA256, "model",
         "v3 is not bound by pin_v3")
    return pinned.module


def _reader(tree):
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == READER]
    need(len(found) <= 1, "step", "more than one def %s" % READER)
    return found[0] if found else None


def _sites(fn, name):
    """The `<model>.check(<name>, X)` calls inside fn: a Name first argument, two arguments, no keywords."""
    return [node for node in ast.walk(fn) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "check" and isinstance(node.func.value, ast.Name) and len(node.args) == 2
            and not node.keywords and isinstance(node.args[0], ast.Name) and node.args[0].id == name] if fn else []


def check_xi(previous_tree, current_tree):
    """(xi) on the old head's previous-era and current trees; 0 or 1."""
    old, new = _reader(previous_tree), _reader(current_tree)
    before = _sites(old, LIVE)
    need(len(before) <= 1, "step", "more than one era-model replay reader in the previous era's %s" % READER)
    if not before:
        need((old is None) == (new is None) and (old is None or ast.dump(old) == ast.dump(new)), "step",
             "%s changed with no era-model replay reader in the previous era" % READER)
        return 0
    need(new is not None, "step", "the bridged layer lost its %s" % READER)
    need(not _sites(new, LIVE), "step", "a live-reading bridged %s (the era-model replay reader is not lifted)" % READER)
    lifted = _sites(new, PROJECTED)
    need(len(lifted) == 1, "step", "the era-model replay reader is lifted %d times" % len(lifted))
    back = ast.parse(ast.unparse(new))
    for node in _sites(_reader(back), PROJECTED):
        node.args[0].id = LIVE
    need(ast.dump(_reader(back)) == ast.dump(old), "step",
         "%s differs from its previous era beyond the one reader token" % READER)
    return 1


def check(read, previous, rule, ext, ext3, ext4, slot, catalog, v1, v2, v3):
    """(xi) on the old head, then v3's check over the old head with the token undone and its TRUE live projection."""
    m3 = _v3(v3)
    need(type(ext4) is dict and ext4.get("schemaVersion") == SCHEMA and ext4.get("clause", {}).get("id") == "xi", "rule",
         "the era-replay rule")
    chain = v1.walk_layers(read, rule)
    need(len(chain) >= 2 and chain[-1][0] == slot, "walk", "the head is not slot %d" % slot)
    _, module, _, current_tree = chain[-2]
    path = v1.validator_path(module)
    live = read(path)
    previous_tree = v1.parse(v1.text(previous(path, live), path), path)
    xi = check_xi(previous_tree, current_tree)
    if not xi:
        return dict(m3.check(read, previous, rule, ext, ext3, slot, catalog, v1, v2), xi=0)
    token, back = b".check(" + PROJECTED.encode() + b", ", b".check(" + LIVE.encode() + b", "
    need(live.count(token) == 1, "step", "the lifted reader token is not found once in the old head")
    undone = live.replace(token, back)

    def read_undone(target):
        return undone if target == path else read(target)

    def previous_live(target, source):
        return previous(target, live) if target == path else previous(target, source)

    return dict(m3.check(read_undone, previous_live, rule, ext, ext3, slot, catalog, v1, v2), xi=xi)


def check_rules(ext3_raw, ext4_raw):
    """The era-replay rule: its schema, the inheritance rule it extends (path, sha256, clause), the clause's text, the
    model and the evidence record; returns the parsed rule."""
    ext4 = json.loads(ext4_raw)
    need(ext4.get("schemaVersion") == SCHEMA, "rule", "the era-replay rule's schema")
    need(ext4.get("extends") == {"path": EXTENDS[0], "sha256": EXTENDS[1], "clause": EXTENDS[2]}
         and hashlib.sha256(ext3_raw).hexdigest() == EXTENDS[1], "rule", "the era-replay rule extends the inheritance rule")
    clause = ext4.get("clause", {})
    need(clause.get("id") == "xi" and clause.get("reader") == READER and clause.get("from") == LIVE
         and clause.get("to") == PROJECTED, "rule", "the clause (xi)")
    need(ext4.get("model", {}).get("path") == "scripts/chain_identity_v4.py"
         and ext4["model"].get("v3") == {"path": "scripts/" + V3_NAME, "sha256": V3_SHA256}, "rule", "the model")
    record = ext4.get("evidence", {}).get("ruling", {}).get("record", {})
    need(record.get("path") == "architecture/chain-era-replay/decisions.md" and len(record.get("sha256", "")) == 64,
         "rule", "the evidence record")
    return ext4


def check_xi_vector(case):
    """One record vector: {name, previous, current, expect} with expect 0, 1 or "refused"."""
    try:
        got = check_xi(ast.parse(case["previous"]), ast.parse(case["current"]))
    except ValueError:
        got = "refused"
    need(got == case["expect"], "vector", "%s: %r, not %r" % (case["name"], got, case["expect"]))
    return got


def check_vectors_record(vectors):
    need(type(vectors) is dict and vectors.get("schemaVersion") == VECTORS_SCHEMA and type(vectors.get("cases")) is list,
         "vector", "the vectors record")
    return [check_xi_vector(case) for case in vectors["cases"]]
