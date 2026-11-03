"""MET-SECTOR-005 (slot 278; CONTRACT_278 rev 4): the history chain's identity rule with the product-packet list and the
R13 inheritance guard.

A reference model, not a validate_* layer. It extends MET-PERF-044's model (scripts/chain_identity_v2.py, called v2
here) by architecture/chain-inheritance/rule.json, without changing v2 or architecture/chain-product-packets/: v2 and
its four records stay byte-identical (Q278-6 (b), MON-278-Q6-B). The caller passes v1 and v2 as module objects; v2 is
first bound by `pin_v2(v2, raw)`, which refuses unless the bytes the caller read from v2's path hash to V2_SHA256 and
the module is chain_identity_v2.py, and every entry point below that uses v2 rechecks that pin. This module imports no
repository module and reads nothing itself.

- `check(read, previous, rule, ext, ext3, slot, catalog, v1, v2)`: v2's check with the slot-aware P-form undo. A layer
  at slot >= CUT_SLOT that binds PRODUCT_PACKETS writes F1-F5, F6' (productPackets, productComparators closing the
  authority's key set) and F7 followed by F9 (the productComparators check) as the two statements before authority's
  first `for`; a layer below the cut writes v2's F1-F7; a layer that binds none writes none.
- `check_inheritance(ext3, products, catalogs, pins, read_packet, safe_load, v2)`: R13. For every product listed at a
  slot >= CUT_SLOT, the newest earlier catalog YAML naming its repository (by first slot; no git read) must be pinned
  in that layer's productComparators, must be its newest predecessor when it lists any, and must keep every argv of the
  comparator byte-exact and in order (the verifier's require_inherits).
- `check_products`, `layer_products`, `check_counts`, `check_allowed_paths` and v2's vector evaluators are v2's, called
  through the pin; `check_class_vector` is v2's with the case's slot (default 277, below the cut).
Every refusal is a ValueError whose message starts with "identity " and names its clause.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json

SCHEMA = "harness.planeon.ai/chain-inheritance-rule/v1"
VECTORS_SCHEMA = "harness.planeon.ai/chain-inheritance-vectors/v1"
V2_NAME = "chain_identity_v2.py"
V2_SHA256 = "23fe723ae060b13727118b5808541d0b40bfee22ac5e803955e324f4dd6d9a55"
EXTENDS = ("architecture/chain-product-packets/rule.json", "refusals")
CUT_SLOT = 278
COMPARATOR_FIELD = "productComparators"
BASE = "base"
BELOW_CUT = CUT_SLOT - 1


def refuse(clause, detail):
    raise ValueError("identity %s: %s" % (clause, detail))


def need(ok, clause, detail):
    if not ok:
        refuse(clause, detail)


# ----------------------------------------------------------------------------------------------------- the v2 pin --

class PinnedV2:
    """v2 bound to the exact bytes the caller read from its path (`pin_v2`)."""
    __slots__ = ("module", "raw")


def pin_v2(v2, raw):
    """Bind v2: the caller's bytes must hash to V2_SHA256 and the module must be chain_identity_v2.py."""
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == V2_SHA256, "model",
         "chain_identity_v2.py is not the pinned v2 (%s)" % V2_SHA256[:8])
    need(str(getattr(v2, "__file__", "")).replace("\\", "/").rsplit("/", 1)[-1] == V2_NAME, "model",
         "the v2 module object is not chain_identity_v2.py")
    pinned = PinnedV2()
    pinned.module, pinned.raw = v2, raw
    return pinned


def _v2(pinned):
    need(isinstance(pinned, PinnedV2), "model", "v2 is used only through pin_v2")
    return pin_v2(pinned.module, pinned.raw).module


# ---------------------------------------------------------------------------------------------- the rule records --

def check_rules(ext_raw, ext3_raw, v2):
    """(ext, ext3): v2's rule record, and this one, which extends it by digest and clause with the delta only."""
    m = _v2(v2)
    ext, ext3 = json.loads(ext_raw), json.loads(ext3_raw)
    m.check_ext(ext)
    need(type(ext3) is dict and ext3.get("schemaVersion") == SCHEMA, "rule", "the inheritance rule record")
    need(ext3.get("extends") == {"path": EXTENDS[0], "sha256": hashlib.sha256(ext_raw).hexdigest(), "clause": EXTENDS[1]},
         "rule", "the inheritance rule does not extend the pinned product-packet rule by digest and clause")
    need(ext3.get("refusals") == ["R13"] and "R13" not in ext["refusals"], "rule", "the refusal delta is not exactly R13")
    need(type(ext3.get("inheritance")) is dict and ext3["inheritance"].get("cutSlot") == CUT_SLOT, "rule",
         "the cut is not slot %d" % CUT_SLOT)
    need(ext3.get("model", {}).get("v2", {}).get("sha256") == V2_SHA256, "rule", "the rule's v2 pin is not V2_SHA256")
    return ext, ext3


# ------------------------------------------------------------------------------------------------- the P-forms --

F6_CUT = ("F6'", "authority",
          'set(value) == {"schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets", "packetSha256", '
          '"changedFiles", "newFiles", "validatorNormalizedSha256", "productPackets", "productComparators"}',
          'set(value) == {"schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets", "packetSha256", '
          '"changedFiles", "newFiles", "validatorNormalizedSha256"}')
P_FORMS_CUT = (F6_CUT,)
# F9, the productComparators check: from the cut, the statement right after F7, the two of them immediately before the
# body's first `for`; undone by removing it. A pin names an earlier catalog packet whose baseline digest it repeats.
COMPARATOR_CHECK = ("F9", "authority",
                    'require(type(value["productComparators"]) is dict\n'
                    '        and list(value["productComparators"]) == [p for p in PRODUCT_PACKETS if p in value["productComparators"]]\n'
                    '        and all(type(pin) is dict and set(pin) == {"packet", "sha256"} and type(pin["packet"]) is str\n'
                    '                and _sha(pin["sha256"]) and value["baselinePackets"].get(pin["packet"]) == pin["sha256"]\n'
                    '                for pin in value["productComparators"].values()),\n'
                    '        "product comparators")')


def p_form_counts(slot, v2):
    """{function: {fragment id: count}} a layer at `slot` that binds PRODUCT_PACKETS writes; v2's below the cut."""
    counts = copy.deepcopy(_v2(v2).p_form_counts())
    if slot >= CUT_SLOT:
        authority = counts["authority"]
        del authority["F6"]
        authority.update({"F6'": 1, COMPARATOR_CHECK[0]: 1})
    return counts


def _names_product(node, m):
    return m._names_product(node) or any(isinstance(n, ast.Constant) and n.value == COMPARATOR_FIELD
                                         for n in ast.walk(node))


def _undo_function(fn, binds, where, slot, m, v2):
    """Undo one class function's P-forms in place; the fragments found, and their places, must be the slot's."""
    found = {}
    if fn.name == m.AUTHORITY_CHECK[1]:
        dumps = {fid: ast.dump(ast.parse(text).body[0]) for fid, _, text in (m.AUTHORITY_CHECK, COMPARATOR_CHECK)}
        hits = {fid: [i for i, stmt in enumerate(fn.body) if ast.dump(stmt) == dump] for fid, dump in dumps.items()}
        loops = [i for i, stmt in enumerate(fn.body) if isinstance(stmt, ast.For)]
        for fid, places in hits.items():
            if places:
                found[fid] = len(places)
        if hits["F7"] or hits["F9"]:
            want = ({"F7": [loops[0] - 2], "F9": [loops[0] - 1]} if slot >= CUT_SLOT
                    else {"F7": [loops[0] - 1], "F9": []}) if loops else {}
            need(loops and hits == want, "P-form", ("%s at %s: the product checks are not the statements right before "
                 "the first for" if slot >= CUT_SLOT else "%s at %s: the productPackets check is not the one statement "
                 "before the first for") % (fn.name, where))   # below the cut: v2's own message
            for i in sorted(hits["F7"] + hits["F9"], reverse=True):
                del fn.body[i]
    undo = m._Undo([f for f in m.P_FORMS + P_FORMS_CUT if f[1] == fn.name])
    fn.body = [undo.visit(stmt) for stmt in fn.body]
    found.update(undo.found)
    expected = p_form_counts(slot, v2).get(fn.name, {}) if binds else {}
    need(found == expected, "P-form", "%s at %s: P-form fragments %s, expected %s"
         % (fn.name, where, sorted(found.items()), sorted(expected.items())))
    need(not _names_product(fn, m), "P-form",
         "%s at %s names the product list outside the accepted P-forms" % (fn.name, where))


def strip_products(tree, names, binds, where, *, slot, v2):
    """A copy of `tree` whose top-level class functions (in `names`) have the slot's P-forms undone (slot is required:
    a caller that forgets it fails at once)."""
    m = _v2(v2)
    tree = copy.deepcopy(tree)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            _undo_function(node, binds, where, slot, m, v2)
            ast.fix_missing_locations(node)
    return tree


# ------------------------------------------------------------------------------------------- the step and check --

def check_step(previous, current, L, S, C, K, products, newid, v1, v2, older=None, new_head=None, names=frozenset()):
    """v2's step rule for one non-head layer, with the slot-aware undo of the bridge's references."""
    m = _v2(v2)
    edits, bridge = {}, L == S - 1
    a, b = previous, current
    if bridge:
        need(older is not None and new_head is not None, "step", "the bridge needs its references")
        a, _ = v1._strip_bridge(previous, None, {})
        b, removed = v1._strip_bridge(current, new_head, edits)
    st = {"L": L, "S": S, "C": C, "Cold": C - 1 - K, "K": K, "products": tuple(products), "newid": newid,
          "bridge": bridge, "edits": edits, "top": v1._Top(a.body + b.body)}
    m._walk(a, b, ["Module"], st, v1)
    if bridge:
        reference = v1.top_functions(strip_products(older, names, bool(m.layer_products(older)), "%d" % (L - 1),
                                                    slot=L - 1, v2=v2))
        binds = bool(m.layer_products(current))
        stripped = {n: v1.top_functions(strip_products(ast.Module(body=[f], type_ignores=[]), names, binds, "%d" % L,
                                                       slot=L, v2=v2))[n]
                    for n, f in removed.items()}
        for name in v1.D_FUNCTIONS:
            need(name in stripped and ast.dump(stripped[name]) == ast.dump(reference[name]), "step",
                 "the old head's %s is not the bridged class" % name)
            edits["vii:" + name] = 1
        need(v1.OWN_READ in stripped
             and v1.blanked(stripped[v1.OWN_READ], [1]) == v1.blanked(reference[v1.OWN_READ], [1]),
             "step", "the old head's %s is not the G2 form" % v1.OWN_READ)
        edits["vii:" + v1.OWN_READ] = 1
        expected = {"vi": 2, "ix": 1, "x:catalog": 1, "x:print": 1, "i": 1, "iii": 1, "ii": 2}
        if K:
            expected["ix-p"] = 1
        expected.update({"viii:" + site: 1 for site in v1.LIFT_SITES})
        expected.update({"vii:" + name: 1 for name in v1.D_FUNCTIONS + (v1.OWN_READ,)})
        need(edits == expected, "step", "the bridge's edits %s are not exactly (vi)-(x-p)" % sorted(edits.items()))
    return edits


def check(read, previous, rule, ext, ext3, slot, catalog, v1, v2):
    """v2's items 1-8 over one era with S and C separate, the P-forms undone per slot. P = 0 returns v1's summary."""
    m = _v2(v2)
    m.check_ext(ext)
    need(type(ext3) is dict and ext3.get("inheritance", {}).get("cutSlot") == CUT_SLOT, "rule", "the inheritance rule")
    chain = v1.walk_layers(read, rule)
    head, head_module, _, head_tree = chain[-1]
    need(slot == head, "walk", "the head is slot %d, not %d" % (head, slot))
    products = {s: m.layer_products(tree) for s, _, _, tree in chain}
    total = sum(len(p) for p in products.values())
    need(catalog == slot + total, "counts", "C = %d is not S + P = %d + %d" % (catalog, slot, total))
    listed = {s: p for s, p in products.items() if p}
    if not total:
        summary = v1.check(read, previous, rule, slot)
        return dict(summary, slot=slot, catalog=catalog, products={})
    names = m.class_functions(rule, v1)
    for s, _, _, tree in chain:
        if not products[s]:
            for name in names & set(v1.top_functions(tree)):
                need(not _names_product(v1.top_functions(tree)[name], m), "P-form",
                     "%s at %d names the product list but binds none" % (name, s))
    newid = v1.new_packet(head_tree)
    trees = {s: tree for s, _, _, tree in chain}
    previous_trees, edits = {}, {}
    for s, module, source, tree in chain[:-1]:
        path = v1.validator_path(module)
        previous_trees[s] = v1.parse(v1.text(previous(path, source.encode("utf-8")), path), path)
        result = check_step(previous_trees[s], tree, s, head, catalog, len(products[head]), products[head], newid, v1,
                            v2, older=trees.get(s - 1), new_head=head_module, names=names)
        for key, value in result.items():
            edits[key] = edits.get(key, 0) + value
    normalized = [(s, mod, src, strip_products(t, names, bool(products[s]), "%d" % s, slot=s, v2=v2))
                  for s, mod, src, t in chain]
    old_head = previous_trees[head - 1]
    v1.check_classes(normalized, rule, strip_products(old_head, names, bool(m.layer_products(old_head)),
                                                      "%d (previous era)" % (head - 1), slot=head - 1, v2=v2))
    for s, _, _, tree in chain:
        v1.check_binding(s, tree, head)
    v1.check_allow_list(head, head_tree, rule, v1.loader_shapes(rule, trees), new_head=True)
    return {"layers": len(chain), "head": head, "headModule": head_module, "newPacket": newid, "edits": edits,
            "slot": slot, "catalog": catalog, "products": {str(s): list(p) for s, p in listed.items()}}


# ------------------------------------------------------------------------------------------- R13: inheritance --

def first_slots(catalogs):
    """{id: first slot}: the earliest layer whose catalog holds it; the base (older than every slot) is -1."""
    need(type(catalogs) is dict and BASE in catalogs, "R13", "the catalogs carry no base")
    first = {y: -1 for y in catalogs[BASE]}
    for s in sorted(k for k in catalogs if k != BASE):
        for y in sorted(catalogs[s]):
            first.setdefault(y, s)
    return first


def supersequence(old, new):
    """The verifier's require_inherits: every argv of `old` in `new`, byte-exact and in order; insertions allowed."""
    it = iter(new)
    return all(any(argv == candidate for candidate in it) for argv in old)


def check_inheritance(ext3, products, catalogs, pins, read_packet, safe_load, v2):
    """R13 for every product listed at a slot >= the cut (CONTRACT_278 s3 steps 1-6); returns the count judged."""
    m = _v2(v2)
    need(type(ext3) is dict and ext3.get("inheritance", {}).get("cutSlot") == CUT_SLOT, "rule", "the inheritance rule")
    first = first_slots(catalogs)
    path = lambda pid: "task-packets/%s.yaml" % pid

    def repository(pid):
        try:
            return m.line_repository(read_packet(path(pid)))
        except (ValueError, KeyError):
            refuse("R13", "unreadable repository line: %s" % pid)

    judged = 0
    for s in sorted(products):
        if s < CUT_SLOT:
            continue
        for p in products[s]:
            view = sorted(y for y, f in first.items() if f < s and y != p)
            repos = {y: repository(y) for y in view}                                     # step 1
            repo = repository(p)
            candidates = [y for y in view if repos[y] == repo]                           # step 2
            pin = (pins.get(s) or {}).get(p)
            if not candidates:
                need(pin is None, "R13", "unexpected comparator pin: %s" % p)
                judged += 1
                continue
            top = max(first[y] for y in candidates)                                      # step 3
            newest = [y for y in candidates if first[y] == top]
            need(len(newest) == 1, "R13", "ambiguous comparator for %s: %d YAMLs in its newest slot" % (p, len(newest)))
            comparator = newest[0]
            need(pin is not None, "R13", "missing comparator pin: %s" % p)                # step 4
            packet = pin.get("packet") if type(pin) is dict else None
            need(not (packet in repos and repos[packet] != repo), "R13", "foreign comparator pin: %s" % p)
            need(packet == comparator, "R13", "stale comparator pin: %s (the newest is %s)" % (p, comparator))
            need(pin.get("sha256") == hashlib.sha256(read_packet(path(comparator))).hexdigest(), "R13",
                 "comparator pin digest: %s" % p)
            doc = safe_load(read_packet(path(p)))
            preds = doc.get("predecessors") if type(doc) is dict else None             # step 5
            if preds:
                present = [x for x in preds if x in first and first[x] < s]
                need(present, "R13", "comparator is not the newest predecessor: %s lists none in the catalog" % p)
                ptop = max(first[x] for x in present)
                pnew = [x for x in present if first[x] == ptop]
                need(len(pnew) == 1, "R13", "ambiguous newest predecessor: %s" % p)
                need(pnew[0] == comparator, "R13", "comparator is not the newest predecessor: %s" % p)
            old = safe_load(read_packet(path(comparator)))["offlineAcceptanceCommands"]  # step 6
            need(supersequence(old, doc["offlineAcceptanceCommands"]), "R13",
                 "drops or reorders commands inherited from %s" % comparator)
            judged += 1
    return judged


# ----------------------------------------------------------------- v2's checks and evaluators, through the pin --

def layer_products(tree, v2):
    return _v2(v2).layer_products(tree)


def check_products(ext, products, read_packet, safe_load, chain_packets, v2):
    return _v2(v2).check_products(ext, products, read_packet, safe_load, chain_packets)


def check_counts(slot, catalog, products, v2):
    return _v2(v2).check_counts(slot, catalog, products)


def check_allowed_paths(allowed, changed, new, authority, validator, own_yaml, products, v2):
    return _v2(v2).check_allowed_paths(allowed, changed, new, authority, validator, own_yaml, products)


def check_step_vector(case, v1, v2):
    """v2's synthetic non-bridge step, through v3's slot-aware step (its slot is the case's L)."""
    a, b = ast.parse(case["before"]), ast.parse(case["after"])
    return check_step(a, b, case["L"], case["S"], case["C"], case["K"], case.get("products", []), case["newid"], v1, v2)


def check_class_vector(case, bases, rule, v1, v2):
    """v2's class-form case with the case's slot (default 277, below the cut): the slot's P-forms are undone, then every
    class function of the base must equal its K = 0 form exactly; a difference refuses under its class's clause."""
    m = _v2(v2)
    tree = ast.parse(m.class_form_source(case, bases))
    names = m.class_functions(rule, v1)
    funcs = v1.top_functions(strip_products(tree, names, bool(m.layer_products(tree)), case["id"],
                                            slot=case.get("slot", BELOW_CUT), v2=v2))
    base = v1.top_functions(ast.parse(bases[case["base"]]))
    for name in sorted(base):
        if ast.dump(funcs.get(name, ast.Pass())) != ast.dump(base[name]):
            clause = "G1" if name in rule["g1"] else "G2" if name in rule["g2"] else "D"
            refuse(clause, "%s is not its K = 0 form after the undo" % name)
    return sorted(base)


def check_vectors_record(vectors):
    need(type(vectors) is dict and vectors.get("schemaVersion") == VECTORS_SCHEMA, "vectors", "the vectors record")
    return vectors


def check_inheritance_vector(case, ext3, safe_load, v2):
    """One `inheritance` case: listed and pins keyed by decimal slot strings, catalogs by slot strings and "base"."""
    listed = {int(k): tuple(v) for k, v in case["listed"].items()}
    catalogs = {(k if k == BASE else int(k)): set(v) for k, v in case["catalogs"].items()}
    pins = {int(k): v for k, v in case["pins"].items()}
    files = {"task-packets/%s.yaml" % k: v.encode("utf-8") for k, v in case["files"].items()}
    return check_inheritance(ext3, listed, catalogs, pins, files.__getitem__, safe_load, v2)
