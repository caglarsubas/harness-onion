"""MET-PERF-042 (CHAIN-COMPACTION-001): the identity rule of the history chain (PLAN revision 11, section 3.1).

This module is a reference model, not a validate_* layer. The slot-255 layer validator runs it from its own era's
digest-pinned bytes through the era-loader shape (owner decision F3, 2026-10-21), and the slot-255 test imports it, pinned
to the same bytes, to check the live tree on every verify. It reads nothing itself: every source arrives as bytes from the
caller's reader (`read(path)`) and every previous-era source from the caller's one-step projection (`previous(path, raw)`).

What it checks, over source text only: every source is parsed with ast.parse and compared with another source parsed in
the same run, never with a stored dump; nothing checked is imported, compiled to a function or executed.
- item 1, the walk: one linear chain from scripts/validate_unified_roadmap.py through the frozen successor forms F189,
  F190 and F191+ to a head with no successor binding, and no other validate_* import anywhere;
- items 2-5, the class rules: G1 exact over 192..head, G2 modulo its listed constant positions, D by class (the bridged
  classes exact, historical_bytes as {192} and {193..head-1} by owner decision Q-CC-F2 (a), the head's forms equal to the
  old head's previous-era forms, _checked_authority_raw modulo its one message), and the pre-scaffold functions present;
- item 6, the step rule: every chain validator but the head equals its previous-era bytes as a whole module (exact AST,
  docstrings kept) except for the bump vocabulary (i)-(v), and the old head except for the bridge vocabulary (vi)-(x);
- item 7, the binding rule; item 8, the head's allow-list frozen in identity-rule.json;
- the compacted test files' shapes (C2), the fact map, and the records;
- item 9's predicates over plain records that the caller builds from the modules its process has imported.
Every refusal is a ValueError whose message starts with "identity " and names its clause.
"""
from __future__ import annotations

import ast
import copy
import json
import re

RUNNER_NAMES = ("runner_authority", "runner_history", "runner_historical_test", "runner_current_test", "runner_catalog")
D_FUNCTIONS = ("_checked_authority_raw", "historical_bytes", "historical_catalog", "historical_test_bytes",
               "current_test_bytes")
OWN_READ = "_checked_own_authority_raw"
GENERIC_BINDINGS = ("MAX_FILE_BYTES", "ROOT", "TEST_PREFIXES", "_VERIFIED_AUTHORITY", "_PROJECTION_RULES",
                    "_PACKET_BYTE_RULES", "_NEW_PACKET_RULE")
LOADER_NAMES = ("builtins", "exec", "eval", "compile", "__import__")
RESTRICTED_CALLS = ("setattr", "delattr", "vars", "globals", "locals", "getattr", "object")
MUTATORS = ("update", "setdefault", "pop", "clear", "__setitem__", "__setattr__", "__delattr__")
LIFT_SITES = ("reviewed_bytes:return", "validate:validator_raw", "validate:changedFiles", "validate:newFiles")
FIRST_SLOT = 189
FIRST_MODULE = "validate_unified_roadmap"
ROUTE_TEST = "test_newest_authority_is_freshly_checked_on_every_route"
PAYLOAD_TEST = "test_every_predecessor_payload_is_checked_without_a_verdict_cache"
READ_COUNT = "test_every_newer_authority_is_read_exactly_once_per_route"
CONFTEST = "tests/conftest.py"
IDENTITY_TESTS = ("test_identity_rule_holds_on_the_live_chain",
                  "test_runtime_bindings_are_the_frozen_ones_around_a_fan_in_pass")
OWN_ROUTES = ("authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads")
# The C2 forms of the payload test (alias P): the head keeps the full loop; a bridged layer keeps one mutation and adds the
# table check, whose oracle is the test's own code (R9).
PAYLOAD_HEAD = '''def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = packets()
    P.validate_packet_payloads(current)
    for name in sorted(P.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            P.validate_packet_payloads(current)
        current[name] = original
'''
PAYLOAD_BRIDGED = '''def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = layer_packets()
    P.validate_packet_payloads(current)
    for name in sorted(P.authority()["baselinePackets"])[:1]:
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            P.validate_packet_payloads(current)
        current[name] = original
    # MET-PERF-042 (C2): this layer's payload table against digests this test computes from the disk YAML.
    import hashlib
    import json
    table = P._packet_rules()
    assert set(table) == set(P.authority()["baselinePackets"]) | {P.NEW_PACKET}
    for name in sorted(table):
        raw = (P.ROOT / "task-packets" / (name + ".yaml")).read_bytes()
        payload = json.dumps(safe_load(raw), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
        assert table[name] == (hashlib.sha256(raw).hexdigest(), hashlib.sha256(payload).hexdigest()), name
'''
# The 28 generic scaffold tests (research A section 2.1) with their class (PLAN revision 11 section 3) and the reason.
SCAFFOLD = (
    ("test_exact_current_source_and_complete_history_chain", "E+P",
     "validate() and the own projection (E); the predecessor catalog walks (P); unchanged"),
    (PAYLOAD_TEST, "G+E",
     "validate_packet_payloads refuses a changed payload (G, G1); the layer's expected-payload table (E); compacted"),
    ("test_catalog_refuses_all_packet_substitution_and_loss", "G", "payload validation refuses substitution or loss"),
    (ROUTE_TEST, "E+P", "own routes read the own authority (E); X_old routes reach it (P); compacted"),
    ("test_changed_historical_tests_retain_their_test_identities", "E", "the layer's changed test files keep names"),
    ("test_historical_traversal_leaves_predecessor_refusal_to_its_owner", "G", "traversal passes predecessors through"),
    ("test_historical_traversal_freshly_checks_its_own_packet", "E", "the layer's own packet bytes and payload"),
    ("test_cached_expected_rules_do_not_cache_payload_or_authority_verdict", "G", "no verdict cache"),
    ("test_exact_inverse_and_forward_test_round_trip_across_layers", "E+P",
     "the own round trip (E); every predecessor's round trip (P); unchanged"),
    ("test_first_full_packet_check_refuses_changed_old_yaml", "G", "first full check refuses changed YAML"),
    ("test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again", "G", "pinned parsed data only"),
    ("test_cached_expected_rules_are_bound_to_source_root", "G", "rules bound to ROOT"),
    ("test_historical_catalog_reuses_frozen_packet_pins_but_rechecks_authority", "G", "pins reused, authority rechecked"),
    ("test_historical_catalog_does_not_initialize_predecessor_packet_rules", "G", "no predecessor rule initialisation"),
    ("test_acceptance_retains_every_inherited_command_and_wrapper", "E", "the layer's own packet's commands"),
    ("test_full_packet_expectations_initialize_once_and_remain_immutable", "G", "rules built once, immutable"),
    ("test_validator_checks_current_disk_packet_bytes_after_parsing", "E", "validate() refuses YAML drift"),
    ("test_inverse_parser_refuses_ambiguous_or_unbounded_hunks", "G", "the inverse parser"),
    ("test_normalized_validator_pin_rejects_source_mutation", "E", "the layer's validator pin"),
    ("test_new_projection_has_no_predecessor_validator_import", "E", "the layer's own imports"),
    ("test_ambiguous_test_projections_are_refused", "G", "ambiguous test projections"),
    ("test_untrusted_source_paths_are_refused", "G", "path hardening"),
    ("test_unlinked_bounded_source_reads", "G", "link and bound hardening"),
    ("test_authority_parser_rejects_duplicate_and_nonfinite_data", "G", "the authority parser"),
    ("test_source_read_detects_concurrent_change", "G", "concurrent-change hardening"),
    ("test_mutable_test_input_is_refused", "G", "bytes-only test routes"),
    ("test_inverse_rules_and_packet_expectations_are_immutable", "G", "frozen mappings"),
    (READ_COUNT, "P", "each newer authority read exactly once per route (runner's five routes); unchanged"),
)


def refuse(clause, detail):
    raise ValueError("identity %s: %s" % (clause, detail))


def need(ok, clause, detail):
    if not ok:
        refuse(clause, detail)


def parse(source, label):
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, TypeError) as exc:
        raise ValueError("identity parse: %s (%s)" % (label, exc.__class__.__name__)) from exc


def text(raw, label):
    try:
        return raw.decode("utf-8") if type(raw) is bytes else refuse("parse", "bytes required: " + label)
    except UnicodeDecodeError as exc:
        raise ValueError("identity parse: %s is not UTF-8" % label) from exc


def dunder(name):
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def top_functions(tree):
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def validator_path(module):
    return "scripts/%s.py" % module


def test_path(module):
    return "tests/test_%s.py" % module[len("validate_"):]


# ------------------------------------------------------------------------------------------------- item 1: the walk --

def successor_form(tree):
    """('F189' | 'F190' | 'F191+', next module) for a chain validator's successor binding, (None, None) for the head."""
    forms = []
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
               and ("validate_" in (getattr(node, "module", None) or "")
                    or any("validate_" in alias.name for alias in node.names))]
    for node in tree.body:
        if isinstance(node, ast.Try) and len(node.handlers) == 1:
            handler = node.handlers[0]
            body = [s for s in node.body if any(s is i for i in imports)]
            other = [s for s in handler.body if any(s is i for i in imports)]
            if not body and not other:
                continue
            need(isinstance(handler.type, ast.Name) and handler.type.id == "ImportError" and handler.name is None
                 and not node.orelse and not node.finalbody, "walk", "successor try form")
            if (len(body) == 1 and len(other) == 1 and isinstance(body[0], ast.Import) and len(body[0].names) == 1
                    and body[0].names[0].asname == "successor" and isinstance(other[0], ast.ImportFrom)
                    and other[0].module == "scripts" and other[0].level == 0 and len(other[0].names) == 1
                    and other[0].names[0].asname == "successor"
                    and other[0].names[0].name == body[0].names[0].name):
                forms.append(("F191+", body[0].names[0].name, body + other))
            elif (len(body) == 1 and len(other) == 1 and isinstance(body[0], ast.ImportFrom)
                  and isinstance(other[0], ast.ImportFrom) and other[0].module == "scripts." + str(body[0].module)
                  and [(a.name, a.asname) for a in body[0].names] == [(a.name, a.asname) for a in other[0].names]
                  and sorted(a.asname or "" for a in body[0].names) == sorted(RUNNER_NAMES)):
                forms.append(("F189", body[0].module, body + other))
            else:
                refuse("walk", "unknown successor try form")
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "__package__":
            need(len(node.body) == 1 and len(node.orelse) == 1 and isinstance(node.body[0], ast.ImportFrom)
                 and node.body[0].module == "scripts" and len(node.body[0].names) == 1
                 and node.body[0].names[0].asname == "successor" and isinstance(node.orelse[0], ast.Import)
                 and len(node.orelse[0].names) == 1 and node.orelse[0].names[0].asname == "successor"
                 and node.orelse[0].names[0].name == node.body[0].names[0].name, "walk", "F190 form")
            forms.append(("F190", node.body[0].names[0].name, [node.body[0], node.orelse[0]]))
    need(len(forms) <= 1, "walk", "more than one successor binding form")
    used = [s for form in forms for s in form[2]]
    need(all(any(node is s for s in used) for node in imports), "walk", "a validate_* import outside the frozen forms")
    return (forms[0][0], forms[0][1]) if forms else (None, None)


def walk_layers(read, rule):
    """Item 1. Returns [(slot, module, source text, tree)] from 189 to the head."""
    name, chain, seen = FIRST_MODULE, [], set()
    while name is not None:
        need(type(name) is str and re.fullmatch(r"validate_[a-z0-9_]+", name) is not None and name not in seen,
             "walk", "a repeated or malformed layer: %r" % (name,))
        seen.add(name)
        source = text(read(validator_path(name)), name)
        tree = parse(source, name)
        form, successor = successor_form(tree)
        slot = FIRST_SLOT + len(chain)
        expected = None if successor is None else "F189" if slot == FIRST_SLOT else "F190" if slot == FIRST_SLOT + 1 \
            else "F191+"
        need(form == expected, "walk", "%s binds its successor by %s, not %s" % (name, form, expected))
        chain.append((slot, name, source, tree))
        name = successor
    frozen = [row["module"] for row in rule["chain"]["layers"]]
    need([module for _, module, _, _ in chain[:len(frozen)]] == frozen and len(chain) > len(frozen),
         "walk", "the frozen chain prefix changed or no layer was added")
    return chain


# ---------------------------------------------------------------------------------------------- items 2-5: classes --

def constants(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Constant)]


def blanked(fn, positions):
    """The function's dump with the constants at the given ast.walk positions replaced by one marker."""
    fn = copy.deepcopy(fn)
    found = constants(fn)
    for index in positions:
        need(index < len(found), "G2", "constant position %d missing in %s" % (index, fn.name))
        found[index].value = "<G2>"
    return ast.dump(fn)


def check_classes(chain, rule, previous_head):
    """Items 2-5 over a walked chain; `previous_head` is the old head's previous-era tree (its head forms)."""
    funcs = {slot: top_functions(tree) for slot, _, _, tree in chain}
    head = chain[-1][0]
    bridged = [slot for slot in funcs if 192 <= slot < head]
    for name in rule["g1"]:
        dumps = set()
        for slot in bridged + [head]:
            need(name in funcs[slot], "G1", "%s missing at %d" % (name, slot))
            dumps.add(ast.dump(funcs[slot][name]))
        need(len(dumps) == 1, "G1", "%s is not one exact form over 192..head" % name)
    for name, spec in rule["g2"].items():
        slots = bridged + [head] if spec["range"] == "192..head" else bridged
        dumps = set()
        for slot in slots:
            need(name in funcs[slot], "G2", "%s missing at %d" % (name, slot))
            dumps.add(blanked(funcs[slot][name], spec["positions"]))
        need(len(dumps) == 1, "G2", "%s is not one form modulo its listed positions" % name)
        if spec["range"] != "192..head":
            need(name not in funcs[head], "G2", "%s present at the head" % name)
    for name, classes in rule["d"]["bridgedClasses"].items():
        covered = []
        for row in classes:
            last = head - 1 if row["last"] == "head-1" else row["last"]
            members = [slot for slot in bridged if row["first"] <= slot <= last]
            need(members and all(name in funcs[slot] for slot in members), "D", "%s class %s" % (name, row))
            need(len({ast.dump(funcs[slot][name]) for slot in members}) == 1, "D",
                 "%s class %s..%s is not one exact form" % (name, row["first"], row["last"]))
            covered += members
        need(sorted(covered) == bridged, "D", "%s classes do not cover 192..head-1" % name)
    old = top_functions(previous_head)
    for name in D_FUNCTIONS:
        need(name in funcs[head] and name in old, "D", "head form of %s missing" % name)
        mine, theirs = constants(funcs[head][name]), constants(old[name])
        differing = [i for i, (x, y) in enumerate(zip(mine, theirs))
                     if (type(x.value), x.value) != (type(y.value), y.value)]
        positions = differing if name == "_checked_authority_raw" else []
        need(len(mine) == len(theirs) and len(positions) <= 1
             and all(type(mine[i].value) is str for i in positions), "D", "the head's %s message position" % name)
        need(blanked(funcs[head][name], positions) == blanked(old[name], positions), "D",
             "the head's %s is not the head form" % name)
    for slot, names in rule["p0"].items():
        for name in names:
            need(name in funcs[int(slot)], "P0", "%s missing at %s" % (name, slot))


# ------------------------------------------------------------------------------------------------- item 7: binding --

def bound_names(node):
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.append((n.id, n))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((n.name, n))
        elif isinstance(n, ast.arg):
            out.append((n.arg, n))
        elif isinstance(n, ast.alias):
            out.append(((n.asname or n.name).split(".")[0], n))
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.append((n.name, n))
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            out.extend((name, n) for name in n.names)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            out.append((n.name, n))
        elif isinstance(n, ast.MatchMapping) and n.rest:
            out.append((n.rest, n))
    return out


def check_binding(slot, tree, head):
    """Item 7: successor (190..head-1) and 189's runner_* names are bound by their frozen import form only."""
    form, _ = successor_form(tree)
    protected = RUNNER_NAMES + (() if slot == FIRST_SLOT else ("successor",))
    allowed = {id(alias) for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in node.names if alias.asname in protected}
    counts = {}
    for name, node in bound_names(tree):
        if name in protected:
            need(id(node) in allowed, "binding", "%s rebound at %d" % (name, slot))
            counts[name] = counts.get(name, 0) + 1
    if slot == FIRST_SLOT:
        need(counts == {name: 2 for name in RUNNER_NAMES}, "binding", "189's runner_* import form")
    elif slot < head:
        need(counts == {"successor": 2} and form in ("F190", "F191+"), "binding", "successor import form at %d" % slot)
    else:
        need(counts == {}, "binding", "the head binds no successor")


# ------------------------------------------------------------------------------------------------ item 6: the step --

def depth(node):
    if not (isinstance(node, ast.Attribute) and node.attr == "NEW_PACKET"):
        return -1
    node, d = node.value, 0
    while isinstance(node, ast.Attribute) and node.attr == "successor":
        node, d = node.value, d + 1
    return d + 1 if isinstance(node, ast.Name) and node.id == "successor" else -1


def is_lift(a, b):
    return (isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id == "regular_bytes"
            and len(a.args) == 1 and not a.keywords
            and isinstance(b, ast.Call) and isinstance(b.func, ast.Attribute) and b.func.attr == "historical_bytes"
            and isinstance(b.func.value, ast.Name) and b.func.value.id == "successor" and len(b.args) == 2
            and not b.keywords and ast.dump(b.args[0]) == ast.dump(a.args[0]) and ast.dump(b.args[1]) == ast.dump(a))


def is_skip(stmt, target):
    return (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1 and isinstance(stmt.body[0], ast.Continue)
            and isinstance(stmt.test, ast.Compare) and len(stmt.test.ops) == 1 and isinstance(stmt.test.ops[0], ast.Eq)
            and isinstance(stmt.test.left, ast.Attribute) and stmt.test.left.attr == "stem"
            and isinstance(stmt.test.left.value, ast.Name) and stmt.test.left.value.id == target
            and depth(stmt.test.comparators[0]) == 1)


def _context(node, field, top):
    out = [type(node).__name__]
    if isinstance(node, ast.FunctionDef):
        out.append("def:validate" if node.name == "validate" and node in top else "def:" + node.name)
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        out.append("assign:" + node.targets[0].id)
    if isinstance(node, ast.For) and field == "body":
        out.append("for:" + ast.unparse(node.iter))
    if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call) \
            and getattr(node.left.func, "id", None) == "len" and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
        out.append("len==")
    return out


def _site(ctx):
    fn = next((c for c in reversed(ctx) if c.startswith("def:")), None)
    if fn == "def:reviewed_bytes" and "Return" in ctx:
        return "reviewed_bytes:return"
    if fn == "def:validate":
        for c in reversed(ctx):
            if c == "assign:validator_raw":
                return "validate:validator_raw"
            if c.startswith("for:") and "changedFiles" in c:
                return "validate:changedFiles"
            if c.startswith("for:") and "newFiles" in c:
                return "validate:newFiles"
    return None


def _walk(a, b, ctx, state):
    """The parallel walk of item 6: state holds N, the new id, L, bridge (bool), top (module-level functions), edits."""
    N, L, bridge, edits = state["N"], state["L"], state["bridge"], state["edits"]
    where = next((c for c in reversed(ctx) if c.startswith("def:")), "module level")
    if bridge and is_lift(a, b):
        site = _site(ctx)
        need(site is not None, "step", "a read lift outside the four sites at %d in %s" % (L, where))
        edits["viii:" + site] = edits.get("viii:" + site, 0) + 1
        return
    need(type(a) is type(b), "step", "node type %s -> %s at %d in %s" % (type(a).__name__, type(b).__name__, L, where))
    if isinstance(a, ast.Constant):
        if a.value == b.value and type(a.value) is type(b.value):
            return
        if type(a.value) is int and type(b.value) is int and a.value == N - 1 and b.value == N and ctx[-1] == "len==" \
                and "def:validate" in ctx:
            edits["i"] = edits.get("i", 0) + 1
            return
        if type(a.value) is str and type(b.value) is str and ctx[-1] == "msgarg":
            after = b.value
            if bridge:
                for phrase, key in ((" retaining the %d-packet checkpoint" % (N - 1), "x:catalog"),
                                    ("%d-packet checkpoint and " % (N - 1), "x:print")):
                    if after.count(phrase) == 1 and a.value.count(phrase) == 0:
                        after = after.replace(phrase, "", 1)
                        edits[key] = edits.get(key, 0) + 1
            new, k = re.subn(r"\b%d\b" % (N - 1), str(N), a.value)
            if k and new == after:
                edits["ii"] = edits.get("ii", 0) + 1
                return
        refuse("step", "constant %r -> %r at %d in %s" % (a.value, b.value, L, where))
    if isinstance(a, ast.Compare) and len(a.ops) == len(b.ops) == 1 and isinstance(a.ops[0], ast.Eq) \
            and isinstance(b.ops[0], ast.In) and not bridge:
        ok = ("def:validate" in ctx and L == N - 2 and depth(a.comparators[0]) == 1
              and isinstance(b.comparators[0], ast.Tuple) and [depth(e) for e in b.comparators[0].elts] == [1, 2]
              and ast.dump(a.left) == ast.dump(b.left))
        need(ok, "step", "an == -> in rewrite outside its form or layer at %d" % L)
        edits["v"] = edits.get("v", 0) + 1
        return
    if isinstance(a, (ast.Set, ast.Tuple, ast.List)) and len(b.elts) == len(a.elts) + 1:
        extra = b.elts[-1]
        load = isinstance(a, ast.Set) or isinstance(getattr(a, "ctx", None), ast.Load)
        if L == FIRST_SLOT and load and isinstance(a, ast.Set) and isinstance(extra, ast.Constant) \
                and extra.value == state["newid"] and not bridge:
            edits["iv"] = edits.get("iv", 0) + 1
        elif load and "def:validate" in ctx and depth(extra) == N - L:
            edits["iii"] = edits.get("iii", 0) + 1
        else:
            refuse("step", "a display gained %s at %d in %s" % (ast.unparse(extra)[:60], L, where))
        for x, y in zip(a.elts, b.elts):
            _walk(x, y, ctx, state)
        return
    if bridge and isinstance(a, ast.For) and "def:validate" in ctx and isinstance(a.target, ast.Name) \
            and isinstance(a.iter, ast.Name) and a.iter.id == "paths" and len(b.body) == len(a.body) + 1 \
            and is_skip(b.body[0], a.target.id):
        edits["ix"] = edits.get("ix", 0) + 1
        b = ast.For(target=b.target, iter=b.iter, body=b.body[1:], orelse=b.orelse, type_comment=b.type_comment)
    for field in a._fields:
        x, y = getattr(a, field, None), getattr(b, field, None)
        if isinstance(x, list):
            need(isinstance(y, list) and len(x) == len(y), "step", "list length %s at %d in %s" % (field, L, where))
            for k, (i, j) in enumerate(zip(x, y)):
                sub = ctx + _context(a, field, state["top"])
                if isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and field == "args" \
                        and ((a.func.id == "require" and k == 1) or a.func.id == "print"):
                    sub = sub + ["msgarg"]
                if isinstance(i, ast.AST):
                    _walk(i, j, sub, state)
                else:
                    need(i == j, "step", "value %s at %d in %s" % (field, L, where))
        elif isinstance(x, ast.AST):
            need(isinstance(y, ast.AST), "step", "field %s at %d in %s" % (field, L, where))
            _walk(x, y, ctx + _context(a, field, state["top"]), state)
        elif x != y and field not in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
            refuse("step", "field %s: %r -> %r at %d in %s" % (field, x, y, L, where))


def _strip_bridge(tree, new_head, edits):
    removed, body = {}, []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in D_FUNCTIONS + (OWN_READ,):
            removed[node.name] = node
            continue
        if isinstance(node, ast.Try) and new_head is not None and len(node.handlers) == 1:
            handler = node.handlers[0]
            imp = [s for s in node.body if isinstance(s, ast.Import) and len(s.names) == 1
                   and s.names[0].asname == "successor"]
            frm = [s for s in handler.body if isinstance(s, ast.ImportFrom) and s.module == "scripts"
                   and len(s.names) == 1 and s.names[0].asname == "successor"]
            if imp or frm:
                need(len(imp) == 1 and len(frm) == 1 and imp[0].names[0].name == frm[0].names[0].name == new_head
                     and isinstance(handler.type, ast.Name) and handler.type.id == "ImportError", "step",
                     "the bridge's import pair is not the F191+ form for " + str(new_head))
                node = copy.copy(node)
                node.body = [s for s in node.body if s is not imp[0]]
                handler = copy.copy(handler)
                handler.body = [s for s in handler.body if s is not frm[0]]
                node.handlers = [handler]
                edits["vi"] = edits.get("vi", 0) + 2
        body.append(node)
    return ast.Module(body=body, type_ignores=[]), removed


def check_step(previous, current, slot, count, newid, head, older=None, new_head=None):
    """Item 6 for one chain validator other than the head: `previous` and `current` are its previous-era and current
    trees; the old head (slot head-1) is checked against the bridge vocabulary, every other layer against the bump
    vocabulary. `older` is the next-older layer's current tree (the bridged class), `new_head` the head's module name."""
    edits = {}
    bridge = slot == head - 1
    a, b = previous, current
    if bridge:
        need(older is not None and new_head is not None, "step", "the bridge needs its references")
        a, _ = _strip_bridge(previous, None, {})
        b, removed = _strip_bridge(current, new_head, edits)
    state = {"N": count, "L": slot, "newid": newid, "bridge": bridge, "edits": edits,
             "top": _Top(a.body + b.body)}
    _walk(a, b, ["Module"], state)
    if bridge:
        reference = top_functions(older)
        for name in D_FUNCTIONS:
            need(name in removed and ast.dump(removed[name]) == ast.dump(reference[name]), "step",
                 "the old head's %s is not the bridged class" % name)
            edits["vii:" + name] = 1
        need(OWN_READ in removed and blanked(removed[OWN_READ], [1]) == blanked(reference[OWN_READ], [1]), "step",
             "the old head's %s is not the G2 form" % OWN_READ)
        edits["vii:" + OWN_READ] = 1
        expected = {"vi": 2, "ix": 1, "x:catalog": 1, "x:print": 1, "i": 1, "iii": 1, "ii": 2}
        expected.update({"viii:" + site: 1 for site in LIFT_SITES})
        expected.update({"vii:" + name: 1 for name in D_FUNCTIONS + (OWN_READ,)})
        need(edits == expected, "step", "the bridge's edits %s are not exactly (vi)-(x)" % sorted(edits.items()))
    return edits


class _Top:
    """Membership by identity for the module-level function nodes of both sides of one step."""

    def __init__(self, nodes):
        self.ids = {id(n) for n in nodes if isinstance(n, ast.FunctionDef)}

    def __contains__(self, node):
        return id(node) in self.ids


# ------------------------------------------------------------------------------------------------ item 8: allow-list --

def module_names(tree):
    names = {"successor"} | set(RUNNER_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {(alias.asname or alias.name).split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module in ("scripts", "jsonschema"):
            names |= {alias.asname or alias.name for alias in node.names
                      if node.module == "scripts" or alias.name in ("_keywords", "_utils", "validators")}
    return names


def import_form(node, alias):
    if isinstance(node, ast.Import):
        return ["import", alias.name, alias.asname]
    return ["from", node.module, alias.name, alias.asname, node.level]


def era_shape(fn, keep):
    fn = copy.deepcopy(fn)
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant):
            n.value = "<C>"
            n.kind = None
        elif isinstance(n, ast.Name) and n.id not in keep:
            n.id = "<N>"
        elif isinstance(n, ast.arg):
            n.arg = "<A>"
            n.annotation = None
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n.name = "<F>"
            n.returns = None
    return ast.dump(fn)


def is_loader_use(node):
    return (isinstance(node, ast.Name) and node.id in LOADER_NAMES) or (isinstance(node, ast.Attribute)
                                                                        and dunder(node.attr))


def loader_functions(tree):
    return [fn for fn in tree.body if isinstance(fn, ast.FunctionDef) and any(is_loader_use(n) for n in ast.walk(fn))]


def parents_of(tree):
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def enclosing_top(tree):
    owner = {}
    for top in tree.body:
        for n in ast.walk(top):
            owner[id(n)] = top if isinstance(top, ast.FunctionDef) else None
    return owner


def receiver_form(node, modules):
    if isinstance(node, ast.Name):
        if node.id in modules:
            return "module:" + node.id
        if node.id in ("bytes", "str", "int", "dict", "set", "frozenset", "tuple", "list"):
            return "builtin:" + node.id
        return "local"
    return type(node).__name__


def module_call_form(call, own, level, modules):
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in own:
            simple = all(isinstance(a, ast.Constant) or (isinstance(a, ast.Name) and a.id in level and a.id not in own
                                                         and a.id not in modules) for a in call.args) and not call.keywords
            return ["own"] if simple else ["own-nonconstant", func.id]
        return ["name", func.id]
    if isinstance(func, ast.Attribute):
        return ["attr", receiver_form(func.value, modules), func.attr]
    return ["other", type(func).__name__]


def binding_statement_forms(tree):
    out = {name: [] for name in GENERIC_BINDINGS}
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) \
            else []
        for target in targets:
            for n in ast.walk(target):
                if isinstance(n, ast.Name) and n.id in out:
                    out[n.id].append(ast.unparse(node))
    return out


def main_guard_form(node):
    test = node.test
    if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"
            and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq) and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__" and not node.orelse):
        body = node.body
        if (len(body) == 2 and all(isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) for s in body)
                and ast.unparse(body[0]) == "validate()" and isinstance(body[1].value.func, ast.Name)
                and body[1].value.func.id == "print" and len(body[1].value.args) == 1 and not body[1].value.keywords
                and isinstance(body[1].value.args[0], ast.Constant) and type(body[1].value.args[0].value) is str):
            return "validate-print"
    clone = copy.deepcopy(node)
    for n in ast.walk(clone):
        if isinstance(n, ast.Constant) and type(n.value) is str and n.value != "__main__":
            n.value = "<message>"
    return ast.unparse(clone)


def restricted_use_form(name, parents):
    call = parents.get(id(name))
    if isinstance(call, ast.Call) and call.func is name:
        if (name.id == "getattr" and len(call.args) in (2, 3) and not call.keywords
                and isinstance(call.args[1], ast.Constant) and type(call.args[1].value) is str):
            return "getattr-constant:" + call.args[1].value
        if name.id == "object" and not call.args and not call.keywords:
            return "object()"
        return "call:" + ast.unparse(call)
    return "reference:" + name.id


def bare_values(expr):
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return [v for e in expr.elts for v in bare_values(e)]
    if isinstance(expr, ast.Dict):
        return [v for e in list(expr.keys) + list(expr.values) if e is not None for v in bare_values(e)]
    if isinstance(expr, ast.IfExp):
        return bare_values(expr.body) + bare_values(expr.orelse)
    if isinstance(expr, ast.BoolOp):
        return [v for e in expr.values for v in bare_values(e)]
    if isinstance(expr, (ast.Starred, ast.NamedExpr)):
        return bare_values(expr.value)
    return [expr]


def alias_sites(tree, loaders):
    loader_nodes = {id(n) for fn in loaders for n in ast.walk(fn)}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and n.value is not None:
            yield "assignment value", n.value
        elif isinstance(n, ast.arguments):
            for d in list(n.defaults) + [d for d in n.kw_defaults if d is not None]:
                yield "default", d
        elif isinstance(n, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            yield "container element", n
        elif isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and n.value is not None:
            yield "return value", n.value
        elif isinstance(n, ast.Lambda):
            yield "return value", n.body
        elif isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            yield "container element", n.elt
        elif isinstance(n, ast.DictComp):
            yield "container element", n.key
            yield "container element", n.value
        elif isinstance(n, ast.Call):
            vars_builtins = (id(n) in loader_nodes and isinstance(n.func, ast.Name) and n.func.id == "vars"
                             and len(n.args) == 1 and isinstance(n.args[0], ast.Name) and n.args[0].id == "builtins")
            if not vars_builtins:
                for a in n.args:
                    yield "call argument", a
                for k in n.keywords:
                    yield "call argument", k.value


def store_roots(target):
    if isinstance(target, (ast.Tuple, ast.List)):
        return [r for e in target.elts for r in store_roots(e)]
    if isinstance(target, ast.Starred):
        return store_roots(target.value)
    if isinstance(target, (ast.Attribute, ast.Subscript)):
        node = target.value
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return [node]
    return []


def loader_shapes(rule, sources):
    """The eleven era-loader shapes, from their exemplars' sources (`sources[slot]` is a parsed tree)."""
    keep = set(rule["allowList"]["eraLoaders"]["keepNames"])
    shapes = set()
    for row in rule["allowList"]["eraLoaders"]["shapes"]:
        functions = top_functions(sources[row["exemplar"]["slot"]])
        need(row["exemplar"]["function"] in functions, "allow-list era loader", "exemplar missing")
        shapes.add(era_shape(functions[row["exemplar"]["function"]], keep))
    return shapes


def check_allow_list(slot, tree, rule, shapes, new_head):
    """Item 8 for one validator tree; `new_head` admits only what is open to a new head (otherwise the uses found today
    in this slot too); `shapes` is loader_shapes(rule, ...)."""
    allow = rule["allowList"]
    keep = set(allow["eraLoaders"]["keepNames"])
    found_here = lambda rows: [] if new_head else [row for row in rows if slot in row["slots"]]
    node_types, attributes = set(allow["nodeTypes"]), set(allow["attributeNames"])
    for n in ast.walk(tree):
        need(type(n).__name__ in node_types, "allow-list node type", type(n).__name__)
        if isinstance(n, ast.Attribute):
            need(n.attr in attributes, "allow-list attribute name", n.attr)
    modules = module_names(tree)
    own = set(top_functions(tree))
    imports = [row["form"] for row in allow["moduleImports"]]
    level = set()
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            level |= {name for name, _ in bound_names(node)}
    guards = 0
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and type(node.value.value) is str:
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                need(import_form(node, alias) in imports, "allow-list import", ast.unparse(node))
        elif isinstance(node, ast.Try):
            handler = node.handlers[0] if len(node.handlers) == 1 else None
            need(handler is not None and isinstance(handler.type, ast.Name) and handler.type.id == "ImportError"
                 and handler.name is None and not node.orelse and not node.finalbody, "allow-list import", "try form")
            for s in node.body + handler.body:
                need(isinstance(s, (ast.Import, ast.ImportFrom)), "allow-list import", "try body")
                for alias in s.names:
                    form = import_form(s, alias)
                    need(form in imports or ("validate_" in str(form) and not new_head), "allow-list import",
                         ast.unparse(s))
        elif isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and node.test.id == "__package__":
                need(not new_head, "allow-list module statement", "if __package__ form")
                continue
            form = main_guard_form(node)
            allowed = [row["form"] for row in allow["mainGuards"] if row["open"]] + \
                [row["form"] for row in found_here(allow["mainGuards"])]
            need(form in allowed, "allow-list main guard", form[:60])
            guards += 1
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                need(isinstance(target, ast.Name) or (isinstance(target, ast.Tuple)
                                                      and all(isinstance(e, ast.Name) for e in target.elts)),
                     "allow-list module statement", "assignment target")
            if node.value is not None:
                _module_value(node.value, allow, own, level, modules, slot, new_head)
        elif isinstance(node, ast.FunctionDef):
            for d in node.decorator_list:
                need([node.name, ast.unparse(d)] in [row["form"] for row in allow["decorators"]],
                     "allow-list decorator", node.name)
        else:
            refuse("allow-list module statement", type(node).__name__)
    need(guards <= 1, "allow-list main guard", "more than one")
    forms = binding_statement_forms(tree)
    for name in GENERIC_BINDINGS:
        spec = allow["genericBindings"][name]
        if new_head:
            need(forms[name] == [spec["headForm"]], "allow-list generic binding", name)
        else:
            frozen = [row["form"] for row in spec["formsFound"] if slot in row["slots"]]
            need(len(forms[name]) <= 1 and all(f in frozen for f in forms[name]), "allow-list generic binding", name)
    _function_bodies(tree, allow, keep, shapes, modules, own, slot, new_head)


def _module_value(value, allow, own, level, modules, slot, new_head):
    value_types = set(allow["moduleValueNodeTypes"])
    calls = [row["form"] for row in allow["moduleCallForms"] if row["open"] or (not new_head and slot in row["slots"])]
    for n in ast.walk(value):
        need(type(n).__name__ in value_types, "allow-list module value", type(n).__name__)
        if isinstance(n, ast.Name):
            need(n.id not in LOADER_NAMES + RESTRICTED_CALLS, "allow-list module value", n.id)
        if isinstance(n, ast.Attribute):
            need(not dunder(n.attr), "allow-list module value", n.attr)
        if isinstance(n, ast.Call):
            form = module_call_form(n, own, level, modules)
            need(form in calls, "allow-list call form", str(form))


def _function_bodies(tree, allow, keep, shapes, modules, own, slot, new_head):
    owner, parents = enclosing_top(tree), parents_of(tree)
    loaders = []
    for fn in loader_functions(tree):
        need(era_shape(fn, keep) in shapes, "allow-list era loader", fn.name)
        loaders.append(fn)
    loader_nodes = {id(n) for fn in loaders for n in ast.walk(fn)}
    imports = [row["form"] for row in allow["functionImports"] if row["open"] or (not new_head and slot in row["slots"])]
    restricted = [row["form"] for row in allow["restrictedUses"] if row["open"] or (not new_head and slot in row["slots"])]
    attributes = set(allow["attributeNames"])
    for n in ast.walk(tree):
        top = owner.get(id(n))
        if isinstance(n, (ast.Import, ast.ImportFrom)) and top is not None:
            for alias in n.names:
                need(import_form(n, alias) in imports, "allow-list function import", ast.unparse(n))
        if is_loader_use(n):
            need(id(n) in loader_nodes, "allow-list era loader", "a loader use outside the era-loader shapes")
        if isinstance(n, ast.Name) and n.id in RESTRICTED_CALLS and id(n) not in loader_nodes:
            form = restricted_use_form(n, parents)
            constant = form.startswith("getattr-constant:")
            need(form in restricted or (constant and "getattr-constant" in restricted
                                        and form[len("getattr-constant:"):] in attributes),
                 "allow-list restricted use", form)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "type":
            need(len(n.args) == 1 and not n.keywords, "allow-list restricted use", "three-argument type")
        if isinstance(n, ast.Global):
            need(top is not None and top.name in ("_checked_authority_raw", OWN_READ)
                 and n.names == ["_VERIFIED_AUTHORITY"], "allow-list global", ",".join(n.names))
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete, ast.For, ast.comprehension)):
            for target in n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]:
                for root in store_roots(target):
                    if isinstance(root, ast.Name) and (root.id in modules or root.id in own):
                        refuse("allow-list foreign store", ast.unparse(target))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in MUTATORS:
            for root in store_roots(n.func):
                if isinstance(root, ast.Name) and (root.id in modules or root.id in own):
                    refuse("allow-list foreign store", ast.unparse(n.func))
    for site, expr in alias_sites(tree, loaders):
        for value in bare_values(expr):
            if isinstance(value, ast.Name) and value.id in modules:
                refuse("allow-list alias", "%s %s" % (site, value.id))


# ------------------------------------------------------------------------------------------ the rule over one era --

def new_packet(tree):
    found = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "NEW_PACKET"
             and isinstance(n.value, ast.Constant) and type(n.value.value) is str]
    need(len(found) == 1, "walk", "the head's NEW_PACKET")
    return found[0]


def check(read, previous, rule, count):
    """Items 1-8 over one era: `read(path)` gives a validator's bytes in this era, `previous(path, raw)` its previous-era
    bytes (the head's one-step projection), `count` the era's packet count N. Returns a summary."""
    need(type(rule) is dict and rule.get("schemaVersion") == "harness.planeon.ai/chain-compaction-identity-rule/v1",
         "rule", "the identity rule record")
    chain = walk_layers(read, rule)
    head, head_module, _, head_tree = chain[-1]
    need(count == head, "walk", "the head is slot %d in a %d-packet era" % (head, count))
    newid = new_packet(head_tree)
    trees = {slot: tree for slot, _, _, tree in chain}
    previous_trees = {}
    edits = {}
    for slot, module, source, tree in chain[:-1]:
        path = validator_path(module)
        before = previous(path, source.encode("utf-8"))
        previous_trees[slot] = parse(text(before, path), path)
        result = check_step(previous_trees[slot], tree, slot, count, newid, head,
                            older=trees.get(slot - 1), new_head=head_module)
        for key, value in result.items():
            edits[key] = edits.get(key, 0) + value
    check_classes(chain, rule, previous_trees[head - 1])
    for slot, _, _, tree in chain:
        check_binding(slot, tree, head)
    check_allow_list(head, head_tree, rule, loader_shapes(rule, trees), new_head=True)
    return {"layers": len(chain), "head": head, "headModule": head_module, "newPacket": newid, "edits": edits}


# ------------------------------------------------------------------------------- C2: the compacted test files --

def _functions_of(tree):
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def _aliases(tree):
    return {a.asname or a.name: a.name for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "scripts"
            for a in n.names if a.name.startswith("validate_")}


def route_list(tree, label):
    fns = _functions_of(tree)
    need(ROUTE_TEST in fns, "C2 shape", "route test missing: " + label)
    marks = [d for d in fns[ROUTE_TEST].decorator_list if isinstance(d, ast.Call) and len(d.args) == 2
             and isinstance(d.args[0], ast.Constant) and d.args[0].value == "route" and isinstance(d.args[1], ast.List)
             and all(isinstance(e, ast.Constant) and type(e.value) is str for e in d.args[1].elts)]
    need(len(marks) == 1, "C2 shape", "one closed route list: " + label)
    return [e.value for e in marks[0].args[1].elts]


def twin_forms(tree):
    """Predecessor module -> (normalised setup, normalised call, route id) of every X_old route."""
    names = _aliases(tree)
    fn = _functions_of(tree)[ROUTE_TEST]
    setup, table, master = {}, None, None
    for stmt in fn.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target = stmt.targets[0].id
            if target == "master_raw":
                master = stmt.value
            elif target.startswith("old_"):
                setup[target[4:]] = stmt.value
            elif target == "calls":
                table = stmt.value
    need(isinstance(table, ast.Dict), "C2 shape", "the route table")

    def norm(node, alias):
        node = ast.parse(ast.unparse(node), mode="eval").body
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                if n.id == "master_raw" and master is not None:
                    n.id = "<master_raw>"
                elif n.id in names:
                    n.id = "M:" + names[n.id]
                elif n.id == "old_" + alias:
                    n.id = "<old>"
            elif isinstance(n, ast.Constant) and n.value == alias + "_old":
                n.value = "<route>"
        dumped = ast.dump(node)
        if master is not None:
            m = ast.parse(ast.unparse(master), mode="eval").body
            for n in ast.walk(m):
                if isinstance(n, ast.Name) and n.id in names:
                    n.id = "M:" + names[n.id]
            dumped = dumped.replace("Name(id='<master_raw>', ctx=Load())", ast.dump(m))
        return dumped

    out = {}
    for key, value in zip(table.keys, table.values):
        if isinstance(key, ast.Constant) and type(key.value) is str and key.value.endswith("_old"):
            alias = key.value[:-4]
            need(alias in names and alias in setup, "C2 shape", "route %s's alias and setup" % key.value)
            out[names[alias]] = (norm(setup[alias], alias), norm(value, alias), key.value)
    return out


def payload_form(tree, template, label):
    """The payload test equals the template with P as the file's own layer alias (the module it validates)."""
    fns = _functions_of(tree)
    need(PAYLOAD_TEST in fns, "C2 shape", "payload test missing: " + label)
    fn = fns[PAYLOAD_TEST]
    calls = [n.value.id for n in ast.walk(fn) if isinstance(n, ast.Attribute) and n.attr == "validate_packet_payloads"
             and isinstance(n.value, ast.Name)]
    need(calls, "C2 shape", "payload test alias: " + label)
    expected = ast.parse(template.replace("P.", calls[0] + ".")).body[0]
    need(ast.dump(ast.Module(body=fn.body, type_ignores=[])) == ast.dump(ast.Module(body=expected.body, type_ignores=[]))
         and ast.dump(fn.args) == ast.dump(expected.args) and not fn.decorator_list,
         "C2 shape", "the payload test is not its %s form (R9 oracle included): %s"
         % ("bridged" if template is PAYLOAD_BRIDGED else "head", label))
    return calls[0]


def scaffold_nodes(fn):
    count = 1
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and getattr(d.func, "attr", None) == "parametrize" and len(d.args) == 2 \
                and isinstance(d.args[1], (ast.List, ast.Tuple)):
            count *= len(d.args[1].elts)
    return count


def fact_map(read, previous, chain_modules, head):
    """The fact map of one era (the record architecture/chain-compaction/fact-map.json holds): read(path) gives a test
    file's bytes in this era, previous(path, raw) its previous-era bytes; chain_modules maps module -> slot."""
    by_slot = {slot: module for module, slot in chain_modules.items()}
    head_path = test_path(by_slot[head])
    head_tree = parse(text(read(head_path), head_path), head_path)
    head_routes = route_list(head_tree, head_path)
    head_twins = twin_forms(head_tree)
    need(head_routes[:8] == list(OWN_ROUTES) and len(head_routes) == 8 + head - FIRST_SLOT
         and sorted(chain_modules[m] for m in head_twins) == list(range(FIRST_SLOT, head)),
         "C2 shape", "the head keeps the full fan-in: " + head_path)
    payload_form(head_tree, PAYLOAD_HEAD, head_path)
    layers, totals = [], {"baseRouteNodes": 0, "droppedRouteNodes": 0, "adjacentKept": 0, "keptTwins": 0,
                          "layers": 0, "functionNamesLost": 0, "layersWithoutReadCountTest": []}
    instances = {name: {"files": 0, "nodes": 0} for name, _, _ in SCAFFOLD}
    for slot in range(192, head + 1):
        path = test_path(by_slot[slot])
        raw = read(path)
        tree = parse(text(raw, path), path)
        fns = _functions_of(tree)
        for name in instances:
            if name in fns:
                instances[name]["files"] += 1
                instances[name]["nodes"] += scaffold_nodes(fns[name])
        if slot == head:
            continue
        base_tree = parse(text(previous(path, raw), path), path)
        before, after = route_list(base_tree, path), route_list(tree, path)
        names = _aliases(base_tree)
        own = [r for r in before if not r.endswith("_old")]
        adjacent = [r for r in before if r.endswith("_old") and chain_modules.get(names.get(r[:-4])) == slot - 1]
        need(own == list(OWN_ROUTES) and len(adjacent) == 1 and after == own + adjacent, "C2 shape",
             "%s keeps its 8 own routes and the adjacent one only" % path)
        payload_form(tree, PAYLOAD_BRIDGED, path)
        lost = sorted(set(_functions_of(base_tree)) - set(fns))
        need(not lost, "C2 shape", "%s lost test functions %s" % (path, lost))
        twins = twin_forms(base_tree)
        has_read_count = READ_COUNT in fns
        dropped = []
        for r in before:
            if r in after:
                continue
            pred = names.get(r[:-4])
            need(pred in head_twins and pred in twins and twins[pred][:2] == head_twins[pred][:2], "C2 shape",
                 "%s %s has no identical-input twin in the head's fan-in" % (path, r))
            dropped.append({
                "route": r, "predecessorSlot": chain_modules[pred], "predecessorModule": pred,
                "keptTwin": {"file": head_path, "route": head_twins[pred][2],
                             "inputIdentity": "identical setup and call (aliases resolved to modules, master_raw inlined)"},
                "provenBy": ["the head's fan-in route %s (slot %d), identical input" % (head_twins[pred][2], head),
                             "the adjacent pairs (X, X+1) up to the head",
                             "the identity rule (D delegation shapes, step rule, binding rule, runtime binding check)"]
                + (["%s, kept in this file" % READ_COUNT] if has_read_count else [])})
        totals["baseRouteNodes"] += len(before)
        totals["droppedRouteNodes"] += len(dropped)
        totals["adjacentKept"] += 1
        totals["keptTwins"] += len(dropped)
        totals["layers"] += 1
        if not has_read_count:
            totals["layersWithoutReadCountTest"].append(slot)
        layers.append({"slot": slot, "module": by_slot[slot], "testFile": path, "ownRoutes": own,
                       "adjacentKept": adjacent, "dropped": dropped, "hasReadCountTest": has_read_count,
                       "payloadLoop": {"before": "%d single-packet mutations" % (slot - 1),
                                       "after": "one mutation (the first sorted name) and the layer's expected-payload "
                                                "table equal to digests computed by the test from the disk YAML",
                                       "droppedProvenBy": ["the head's full loop (G on one instance)",
                                                           "identity rule G1: validate_packet_payloads identical "
                                                           "192..head", "this layer's table check (E)"]}})
    return {
        "schemaVersion": "harness.planeon.ai/chain-compaction-fact-map/v1",
        "plan": "CHAIN-COMPACTION-001 PLAN revision 11, sections 3, 4 C2 and 6",
        "derivation": "the dropped routes are the previous era's routes that this era's files no longer list; each kept "
                      "twin is the head file's fan-in route for the same predecessor",
        "head": {"slot": head, "module": by_slot[head], "testFile": head_path, "routes": len(head_routes),
                 "payloadLoop": "full (every predecessor mutated alone)"},
        "bridgedLayers": "192..%d" % (head - 1),
        "scaffoldTests": [{"name": name, "class": cls, "reason": why, "instances": instances[name]}
                          for name, cls, why in SCAFFOLD],
        "unchangedScaffoldTests": "every scaffold test except the route and payload tests, in every file; both explicit "
                                  "blocks (the catalog walks and the round trips) failed the payload rule in M1",
        "totals": totals,
        "layers": layers,
    }


def never_shared(raw):
    """The conftest's literal NEVER_SHARED set (one assignment of a frozenset of string constants)."""
    tree = parse(text(raw, CONFTEST), CONFTEST)
    found = [node.value for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "NEVER_SHARED"]
    need(len(found) == 1 and isinstance(found[0], ast.Call) and isinstance(found[0].func, ast.Name)
         and found[0].func.id == "frozenset" and len(found[0].args) == 1 and isinstance(found[0].args[0], ast.Set)
         and all(isinstance(e, ast.Constant) and type(e.value) is str for e in found[0].args[0].elts),
         "conftest", "one literal NEVER_SHARED set")
    return {e.value for e in found[0].args[0].elts}


def check_record(read, previous, rule, facts, head_module, head):
    """C2's shapes and the fact map over one era: `facts` (the parsed fact-map.json) must equal the map recomputed from
    this era's test files and their previous-era bytes; the conftest never shares the identity tests."""
    need(set(IDENTITY_TESTS) <= never_shared(read(CONFTEST)), "conftest", "the identity tests are never shared")
    chain_modules = {row["module"]: row["slot"] for row in rule["chain"]["layers"]}
    chain_modules[head_module] = head
    need(len(chain_modules) == head - FIRST_SLOT + 1, "fact map", "the chain")
    recomputed = fact_map(read, previous, chain_modules, head)
    need(facts == json.loads(json.dumps(recomputed)), "fact map", "the record is not the map of this era's test files")
    return recomputed["totals"]


# ------------------------------------------------------------------------------------- item 9 over plain records --

def check_runtime(records):
    """Item 9's predicates over plain records built by the caller from the modules its process imported (no function
    object is built here). One record per chain module:
    {"slot", "module", "bytesStable": bool, "successor": bool | None, "runners": {name: bool},
     "functions": [{"name", "codeEqual", "globalsIsModule", "defaults", "expectedDefaults", "kwdefaults",
                    "expectedKwdefaults", "closureIsNone", "lru": None | {"wrapperType": bool, "parameters": dict}}],
     "generic": {name: bool}, "imports": [{"name", "matches": [bool, ...]}]}."""
    need(type(records) is list and records, "runtime", "no records")
    for record in records:
        label = "%s (%s)" % (record.get("module"), record.get("slot"))
        need(record.get("bytesStable") is True, "runtime bytes", "the file changed after import: " + label)
        if record["slot"] == FIRST_SLOT:
            need(sorted(record.get("runners", {})) == sorted(RUNNER_NAMES)
                 and all(v is True for v in record["runners"].values()), "runtime runner",
                 "189's runner_* names are not 190's functions: " + label)
        elif record.get("successor") is not None:
            need(record["successor"] is True, "runtime successor", "successor is not the next layer's module: " + label)
        for fn in record.get("functions", []):
            where = "%s.%s" % (record.get("module"), fn.get("name"))
            if fn.get("lru") is not None:
                need(fn["lru"].get("wrapperType") is True, "runtime lru_cache", "not functools' lru_cache wrapper: " + where)
                need(fn["lru"].get("parameters") == {"maxsize": 1, "typed": False}, "runtime lru_cache",
                     "cache parameters: " + where)
            need(fn.get("codeEqual") is True, "runtime code", "code differs from the imported bytes: " + where)
            need(fn.get("globalsIsModule") is True, "runtime globals", "globals are not the module's dict: " + where)
            need(fn.get("defaults") == fn.get("expectedDefaults"), "runtime defaults", "positional defaults: " + where)
            need(fn.get("kwdefaults") == fn.get("expectedKwdefaults"), "runtime defaults", "keyword defaults: " + where)
            need(fn.get("closureIsNone") is True, "runtime closure", "a module-level function with a closure: " + where)
        for name, ok in record.get("generic", {}).items():
            need(ok is True, "runtime generic", "%s does not hold its value: %s" % (name, label))
        for row in record.get("imports", []):
            need(any(m is True for m in row.get("matches", [])), "runtime import",
                 "%s is not the object its import names: %s" % (row.get("name"), label))
    return len(records)
