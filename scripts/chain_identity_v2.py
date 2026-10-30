"""MET-PERF-044 (CHAIN-PRODUCT-PUBLISH-001): the history chain's identity rule with the product-packet list.

A reference model, not a validate_* layer. It extends MET-PERF-042's model (scripts/chain_identity.py, called v1
here) by the vocabulary in architecture/chain-product-packets/rule.json, without changing v1 or
architecture/chain-compaction/. The caller passes v1 as a module object that it pinned by digest; this module imports
no repository module and reads nothing itself: sources arrive through the caller's `read(path)` and
`previous(path, raw)`.

- `check(read, previous, rule, ext, slot, catalog, v1)`: S (`slot`) and C (`catalog`) are separate; C must equal S + P,
  P the sum of K over every layer that binds PRODUCT_PACKETS. When P = 0 it returns v1's own check of the same era, so
  v2 = v1 on every P = 0 chain. When P > 0 it runs v1's walk, binding rule and allow-list, the step rule with N read per
  clause (`nReading`: C in (i), (ii) and (x); S in (iii) and (v)) and the publishing-step edits (i-p)..(v-p), (ix-p),
  and v1's class rules D, G1 and G2 over trees whose P-forms are undone. The P-forms are exactly the seven fragments
  F1-F7 of P_FORMS and AUTHORITY_CHECK (E1 section 4 items 3-5): a layer that binds PRODUCT_PACKETS writes every one of
  them, with the listed count, in its class function; a layer that binds none writes none; after the undo no class
  function names PRODUCT_PACKETS or "productPackets" (clause P-form).
- `check_products(ext, products, read_packet, safe_load, chain_packets)`: R2's form check, R3, R8 clause 2 and R12 for
  every listed product of every layer (rule.json `productId`, `productRepository`); `safe_load` is the caller's reader.
- `check_step_vector(case, v1)`, `check_class_vector(case, bases, rule, v1)` and the small evaluators below run
  vectors.json's synthetic cases.
Every refusal is a ValueError whose message starts with "identity " and names its clause.
"""
from __future__ import annotations

import ast
import copy
import json
import re

SCHEMA = "harness.planeon.ai/chain-product-packet-rule/v1"
VECTORS_SCHEMA = "harness.planeon.ai/chain-product-packet-vectors/v1"
BINDING = "PRODUCT_PACKETS"
AUTHORITY_FIELD = "productPackets"
ID_FORM = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+")


def refuse(clause, detail):
    raise ValueError("identity %s: %s" % (clause, detail))


def need(ok, clause, detail):
    if not ok:
        refuse(clause, detail)


# --------------------------------------------------------------------------------------------- the product list --

def layer_products(tree):
    """The layer's PRODUCT_PACKETS tuple, or () when the layer binds none (rule.json productList.bindingRule)."""
    found = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == BINDING]
    if not found:
        return ()
    need(len(found) == 1, "binding", "PRODUCT_PACKETS bound more than once")
    value = found[0].value
    need(isinstance(value, ast.Tuple) and value.elts, "binding",
         "PRODUCT_PACKETS is not a non-empty tuple (K = 0 binds none)")
    ids = []
    for element in value.elts:
        need(isinstance(element, ast.Constant) and type(element.value) is str and ID_FORM.fullmatch(element.value),
             "binding", "PRODUCT_PACKETS holds a non-id element")
        ids.append(element.value)
    need(len(set(ids)) == len(ids), "binding", "PRODUCT_PACKETS repeats an id")
    return tuple(ids)


def check_ext(ext):
    need(type(ext) is dict and ext.get("schemaVersion") == SCHEMA, "rule", "the product-packet rule record")
    names = ext["productRepository"]["allowedNames"]["names"]
    need(type(names) is list and len(names) == 12 and len(set(names)) == 12, "rule", "the twelve allowed names")
    need(ext["productRepository"]["refusedName"] not in names, "rule", "the refused name is not allowed")
    return re.compile(ext["productList"]["productId"][1])


def line_repository(raw):
    """The verifier's line rule (packet_repository): one inline `repository:` line, plain or JSON string."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        refuse("R12", "packet is not UTF-8")
    lines = [line[len("repository:"):].strip() for line in text.splitlines() if line.startswith("repository:")]
    need(len(lines) == 1, "R12", "the repository declaration is not a single inline line")
    value = lines[0]
    if value.startswith('"'):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            refuse("R12", "the repository declaration is not valid JSON")
    need(type(value) is str, "R12", "the repository value")
    return value


def check_products(ext, products, read_packet, safe_load, chain_packets=()):
    """Item 12: every listed product of every layer meets R2's form, R3, R8 clause 2 and R12. Returns the count."""
    path_form = check_ext(ext)
    names = set(ext["productRepository"]["allowedNames"]["names"])
    refused = ext["productRepository"]["refusedName"]
    count = 0
    for slot in sorted(products):
        for pid in products[slot]:
            path = "task-packets/%s.yaml" % pid
            need(path_form.fullmatch(path) is not None, "R2", "product id outside the PACKET_PATH form: %s" % pid)
            need(pid not in chain_packets, "R2", "product id equal to a chain packet id: %s" % pid)
            raw = read_packet(path)
            value = line_repository(raw)
            need(value != refused, "R3", "%s names this repository" % pid)
            need(value in names, "R8", "%s names a repository outside the twelve: %s" % (pid, value))
            doc = safe_load(raw)
            need(type(doc) is dict and doc.get("id") == pid, "R2", "%s: the YAML's id is not its file stem" % pid)
            need(doc.get("repository") == value, "R12", "%s: safe_load reads another repository than the line" % pid)
            count += 1
    return count


# --------------------------------------------------------------------------------- normalizing the P-forms away --

# The accepted P-form fragments (E1 section 4 items 3-5; README "The accepted P-forms"): in each class function named,
# the P-form expression is undone to its K = 0 form, matched as a whole expression by its exact AST.
P_FORMS = (
    ("F1", "historical_catalog", "set(packets) == current_ids | set(PRODUCT_PACKETS)", "set(packets) == current_ids"),
    ("F2", "historical_catalog", "current_ids - {NEW_PACKET} - set(PRODUCT_PACKETS)", "current_ids - {NEW_PACKET}"),
    ("F3", "validate_packet_payloads", "set(packets) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)",
     "set(packets) == old | {NEW_PACKET}"),
    ("F4", "validate_packet_payloads", "set(rules) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)",
     "set(rules) == old | {NEW_PACKET}"),
    ("F5", "_packet_byte_rules",
     'dict(record["baselinePackets"], **{NEW_PACKET: record["packetSha256"]}, **record["productPackets"])',
     'dict(record["baselinePackets"], **{NEW_PACKET: record["packetSha256"]})'),
    ("F6", "authority",
     'set(value) == {"schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets", "packetSha256", '
     '"changedFiles", "newFiles", "validatorNormalizedSha256", "productPackets"}',
     'set(value) == {"schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets", "packetSha256", '
     '"changedFiles", "newFiles", "validatorNormalizedSha256"}'),
)
# F7, item 5's check of productPackets (rule.json authorityRule): one statement of authority's body, exactly this one,
# placed immediately before the body's first `for` statement; undone by removing it.
AUTHORITY_CHECK = ("F7", "authority",
                   'require(type(value["productPackets"]) is dict\n'
                   '        and list(value["productPackets"]) == list(PRODUCT_PACKETS)\n'
                   '        and all(_sha(sha) for sha in value["productPackets"].values())\n'
                   '        and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),\n'
                   '        "product packets")')


def _expr(source):
    return ast.parse(source, mode="eval").body


def p_form_counts():
    """{function: {fragment id: count}}: what a layer that binds PRODUCT_PACKETS writes in each class function."""
    out = {}
    for fid, name, _, _ in P_FORMS + ((AUTHORITY_CHECK[0], AUTHORITY_CHECK[1], None, None),):
        out.setdefault(name, {})[fid] = 1
    return out


def _names_product(node):
    return any((isinstance(n, ast.Name) and n.id == BINDING) or (isinstance(n, ast.Attribute) and n.attr == BINDING)
               or (isinstance(n, ast.Constant) and n.value == AUTHORITY_FIELD) for n in ast.walk(node))


class _Undo(ast.NodeTransformer):
    """Replaces each whole expression equal to one of `forms` (by ast.dump, positions ignored) with its K = 0 form."""

    def __init__(self, forms):
        self.forms = [(fid, ast.dump(_expr(p_form)), k0) for fid, _, p_form, k0 in forms]
        self.found = {}

    def visit(self, node):
        if isinstance(node, ast.expr):
            dump = ast.dump(node)
            for fid, form, k0 in self.forms:
                if dump == form:
                    self.found[fid] = self.found.get(fid, 0) + 1
                    return _expr(k0)
        return super().visit(node)


def _undo_function(fn, binds, where):
    """Undo one class function's P-forms in place; the fragments found must be exactly the expected ones."""
    found = {}
    if fn.name == AUTHORITY_CHECK[1]:
        check = ast.dump(ast.parse(AUTHORITY_CHECK[2]).body[0])
        hits = [i for i, stmt in enumerate(fn.body) if ast.dump(stmt) == check]
        loops = [i for i, stmt in enumerate(fn.body) if isinstance(stmt, ast.For)]
        if hits:
            need(len(hits) == 1 and loops and hits[0] == loops[0] - 1, "P-form",
                 "%s at %s: the productPackets check is not the one statement before the first for" % (fn.name, where))
            del fn.body[hits[0]]
            found[AUTHORITY_CHECK[0]] = 1
    undo = _Undo([f for f in P_FORMS if f[1] == fn.name])
    fn.body = [undo.visit(stmt) for stmt in fn.body]
    found.update(undo.found)
    expected = p_form_counts().get(fn.name, {}) if binds else {}
    need(found == expected, "P-form", "%s at %s: P-form fragments %s, expected %s"
         % (fn.name, where, sorted(found.items()), sorted(expected.items())))
    need(not _names_product(fn), "P-form",
         "%s at %s names the product list outside the accepted P-forms" % (fn.name, where))


def strip_products(tree, names, binds, where="a layer"):
    """A copy of `tree` whose top-level class functions (in `names`) have their P-forms undone. `binds`: the layer binds
    PRODUCT_PACKETS, so every accepted fragment is required; otherwise none is allowed."""
    tree = copy.deepcopy(tree)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            _undo_function(node, binds, where)
            ast.fix_missing_locations(node)
    return tree


def class_functions(rule, v1):
    return set(rule["g1"]) | set(rule["g2"]) | set(v1.D_FUNCTIONS) | {v1.OWN_READ}


# ------------------------------------------------------------------------------------- the step rule with S and C --

def _pdepth(node):
    """d for `successor^d.PRODUCT_PACKETS`, else -1."""
    if not (isinstance(node, ast.Attribute) and node.attr == BINDING):
        return -1
    node, d = node.value, 0
    while isinstance(node, ast.Attribute) and node.attr == "successor":
        node, d = node.value, d + 1
    return d + 1 if isinstance(node, ast.Name) and node.id == "successor" else -1


def _is_pskip(stmt, target):
    """(ix-p): `if <target>.stem in successor.PRODUCT_PACKETS: continue`."""
    return (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
            and isinstance(stmt.body[0], ast.Continue)
            and isinstance(stmt.test, ast.Compare) and len(stmt.test.ops) == 1 and isinstance(stmt.test.ops[0], ast.In)
            and isinstance(stmt.test.left, ast.Attribute) and stmt.test.left.attr == "stem"
            and isinstance(stmt.test.left.value, ast.Name) and stmt.test.left.value.id == target
            and _pdepth(stmt.test.comparators[0]) == 1)


def _walk(a, b, ctx, st, v1):
    """v1's parallel walk with N read per clause: C_old -> C in (i), (ii), (x); S in (iii), (v); K adds (i-p)-(v-p)."""
    L, S, K, bridge, edits = st["L"], st["S"], st["K"], st["bridge"], st["edits"]
    where = next((c for c in reversed(ctx) if c.startswith("def:")), "module level")
    if bridge and v1.is_lift(a, b):
        site = v1._site(ctx)
        need(site is not None, "step", "a read lift outside the four sites at %d in %s" % (L, where))
        edits["viii:" + site] = edits.get("viii:" + site, 0) + 1
        return
    need(type(a) is type(b), "step", "node type %s -> %s at %d in %s" % (type(a).__name__, type(b).__name__, L, where))
    if isinstance(a, ast.Constant):
        if a.value == b.value and type(a.value) is type(b.value):
            return
        if type(a.value) is int and type(b.value) is int and a.value == st["Cold"] and b.value == st["C"] \
                and ctx[-1] == "len==" and "def:validate" in ctx:
            edits["i"] = edits.get("i", 0) + 1
            return
        if type(a.value) is str and type(b.value) is str and ctx[-1] == "msgarg":
            after = b.value
            if bridge:
                for phrase, key in ((" retaining the %d-packet checkpoint" % st["Cold"], "x:catalog"),
                                    ("%d-packet checkpoint and " % st["Cold"], "x:print")):
                    if after.count(phrase) == 1 and a.value.count(phrase) == 0:
                        after = after.replace(phrase, "", 1)
                        edits[key] = edits.get(key, 0) + 1
            new, k = re.subn(r"\b%d\b" % st["Cold"], str(st["C"]), a.value)
            if k and new == after:
                edits["ii"] = edits.get("ii", 0) + 1
                return
        refuse("step", "constant %r -> %r at %d in %s" % (a.value, b.value, L, where))
    if isinstance(a, ast.Compare) and len(a.ops) == len(b.ops) == 1 and isinstance(a.ops[0], ast.Eq) \
            and isinstance(b.ops[0], ast.In) and not bridge:
        tail = b.comparators[0].elts if isinstance(b.comparators[0], ast.Tuple) else []
        want = [1, 2] if not K else [1, 2, "p2"]
        got = [v1.depth(e) if not isinstance(e, ast.Starred) else ("p%d" % _pdepth(e.value)) for e in tail]
        ok = ("def:validate" in ctx and L == S - 2 and v1.depth(a.comparators[0]) == 1 and got == want
              and ast.dump(a.left) == ast.dump(b.left))
        need(ok, "step", "an == -> in rewrite outside its form or layer at %d" % L)
        edits["v"] = edits.get("v", 0) + 1
        return
    if isinstance(a, (ast.Set, ast.Tuple, ast.List)) and len(b.elts) > len(a.elts):
        extra = b.elts[len(a.elts):]
        load = isinstance(a, ast.Set) or isinstance(getattr(a, "ctx", None), ast.Load)
        if L == v1.FIRST_SLOT and load and isinstance(a, ast.Set) and not bridge \
                and [getattr(e, "value", None) for e in extra] == [st["newid"], *st["products"]] \
                and all(isinstance(e, ast.Constant) for e in extra):
            edits["iv"] = edits.get("iv", 0) + 1
        elif load and "def:validate" in ctx and v1.depth(extra[0]) == S - L and (
                (not K and len(extra) == 1)
                or (K and len(extra) == 2 and isinstance(extra[1], ast.Starred) and _pdepth(extra[1].value) == S - L)):
            edits["iii"] = edits.get("iii", 0) + 1
        else:
            gained = ", ".join(ast.unparse(e)[:40] for e in extra)
            refuse("step", "a display gained %s at %d in %s" % (gained, L, where))
        for x, y in zip(a.elts, b.elts):
            _walk(x, y, ctx, st, v1)
        return
    if bridge and isinstance(a, ast.For) and "def:validate" in ctx and isinstance(a.target, ast.Name) \
            and isinstance(a.iter, ast.Name) and a.iter.id == "paths" \
            and len(b.body) == len(a.body) + 1 + (1 if K else 0) \
            and v1.is_skip(b.body[0], a.target.id) and (not K or _is_pskip(b.body[1], a.target.id)):
        edits["ix"] = edits.get("ix", 0) + 1
        if K:
            edits["ix-p"] = edits.get("ix-p", 0) + 1
        b = ast.For(target=b.target, iter=b.iter, body=b.body[1 + (1 if K else 0):], orelse=b.orelse,
                    type_comment=b.type_comment)
    for field in a._fields:
        x, y = getattr(a, field, None), getattr(b, field, None)
        if isinstance(x, list):
            need(isinstance(y, list) and len(x) == len(y), "step", "list length %s at %d in %s" % (field, L, where))
            for k, (i, j) in enumerate(zip(x, y)):
                sub = ctx + v1._context(a, field, st["top"])
                if isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and field == "args" \
                        and ((a.func.id == "require" and k == 1) or a.func.id == "print"):
                    sub = sub + ["msgarg"]
                if isinstance(i, ast.AST):
                    _walk(i, j, sub, st, v1)
                else:
                    need(i == j, "step", "value %s at %d in %s" % (field, L, where))
        elif isinstance(x, ast.AST):
            need(isinstance(y, ast.AST), "step", "field %s at %d in %s" % (field, L, where))
            _walk(x, y, ctx + v1._context(a, field, st["top"]), st, v1)
        elif x != y and field not in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
            refuse("step", "field %s: %r -> %r at %d in %s" % (field, x, y, L, where))


def check_step(previous, current, L, S, C, K, products, newid, v1, older=None, new_head=None, names=frozenset()):
    """The step rule for one non-head layer at a step whose new head is slot S and lists K products."""
    edits, bridge = {}, L == S - 1
    a, b = previous, current
    if bridge:
        need(older is not None and new_head is not None, "step", "the bridge needs its references")
        a, _ = v1._strip_bridge(previous, None, {})
        b, removed = v1._strip_bridge(current, new_head, edits)
    st = {"L": L, "S": S, "C": C, "Cold": C - 1 - K, "K": K, "products": tuple(products), "newid": newid,
          "bridge": bridge, "edits": edits, "top": v1._Top(a.body + b.body)}
    _walk(a, b, ["Module"], st, v1)
    if bridge:
        reference = v1.top_functions(strip_products(older, names, bool(layer_products(older)), "%d" % (L - 1)))
        binds = bool(layer_products(current))
        stripped = {n: v1.top_functions(strip_products(ast.Module(body=[f], type_ignores=[]), names, binds,
                                                       "%d" % L))[n]
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


# ------------------------------------------------------------------------------------------------------ the check --

def check(read, previous, rule, ext, slot, catalog, v1):
    """Items 1-8 over one era with S and C separate. P = 0 returns v1's own summary of the same era."""
    check_ext(ext)
    chain = v1.walk_layers(read, rule)
    head, head_module, _, head_tree = chain[-1]
    need(slot == head, "walk", "the head is slot %d, not %d" % (head, slot))
    products = {s: layer_products(tree) for s, _, _, tree in chain}
    total = sum(len(p) for p in products.values())
    need(catalog == slot + total, "counts", "C = %d is not S + P = %d + %d" % (catalog, slot, total))
    listed = {s: p for s, p in products.items() if p}
    if not total:
        summary = v1.check(read, previous, rule, slot)
        return dict(summary, slot=slot, catalog=catalog, products={})
    names = class_functions(rule, v1)
    for s, _, _, tree in chain:
        if not products[s]:
            for name in names & set(v1.top_functions(tree)):
                need(not _names_product(v1.top_functions(tree)[name]), "P-form",
                     "%s at %d names the product list but binds none" % (name, s))
    newid = v1.new_packet(head_tree)
    trees = {s: tree for s, _, _, tree in chain}
    previous_trees, edits = {}, {}
    for s, module, source, tree in chain[:-1]:
        path = v1.validator_path(module)
        previous_trees[s] = v1.parse(v1.text(previous(path, source.encode("utf-8")), path), path)
        result = check_step(previous_trees[s], tree, s, head, catalog, len(products[head]), products[head], newid, v1,
                            older=trees.get(s - 1), new_head=head_module, names=names)
        for key, value in result.items():
            edits[key] = edits.get(key, 0) + value
    normalized = [(s, m, src, strip_products(t, names, bool(products[s]), "%d" % s)) for s, m, src, t in chain]
    old_head = previous_trees[head - 1]
    v1.check_classes(normalized, rule,
                     strip_products(old_head, names, bool(layer_products(old_head)), "%d (previous era)" % (head - 1)))
    for s, _, _, tree in chain:
        v1.check_binding(s, tree, head)
    v1.check_allow_list(head, head_tree, rule, v1.loader_shapes(rule, trees), new_head=True)
    return {"layers": len(chain), "head": head, "headModule": head_module, "newPacket": newid, "edits": edits,
            "slot": slot, "catalog": catalog, "products": {str(s): list(p) for s, p in listed.items()}}


# --------------------------------------------------------------------------------------------- vector evaluators --

def check_vectors_record(vectors):
    need(type(vectors) is dict and vectors.get("schemaVersion") == VECTORS_SCHEMA, "vectors", "the vectors record")
    return vectors


def check_step_vector(case, v1):
    """One synthetic non-bridge step: `before` and `after` are module sources; returns the edits."""
    a, b = ast.parse(case["before"]), ast.parse(case["after"])
    return check_step(a, b, case["L"], case["S"], case["C"], case["K"], case.get("products", []), case["newid"], v1)


def class_form_source(case, bases):
    """A class-form case's module: its base with each `edits` pair applied exactly once, and PRODUCT_PACKETS bound
    first when `products` is non-empty."""
    source = bases[case["base"]]
    for old, new in case["edits"]:
        need(source.count(old) == 1, "vectors", "the edit %r does not apply exactly once" % old[:50])
        source = source.replace(old, new)
    if case["products"]:
        source = "PRODUCT_PACKETS = (%s,)\n" % ", ".join(json.dumps(p) for p in case["products"]) + source
    return source


def check_class_vector(case, bases, rule, v1):
    """One class-form case: the P-forms are undone (refusing as strip_products does), and then every class function of
    the base must equal its K = 0 form, as D, G1 and G2 compare it; a difference refuses under its class's clause."""
    tree = ast.parse(class_form_source(case, bases))
    names = class_functions(rule, v1)
    funcs = v1.top_functions(strip_products(tree, names, bool(layer_products(tree)), case["id"]))
    base = v1.top_functions(ast.parse(bases[case["base"]]))
    for name in sorted(base):
        if ast.dump(funcs.get(name, ast.Pass())) != ast.dump(base[name]):
            clause = "G1" if name in rule["g1"] else "G2" if name in rule["g2"] else "D"
            refuse(clause, "%s is not its K = 0 form after the undo" % name)
    return sorted(base)


def check_counts(slot, catalog, products):
    need(catalog == slot + sum(len(p) for p in products), "counts", "C = %d is not S + P" % catalog)
    return True


def expected_allowed_paths(changed, new, authority, validator, own_yaml, products):
    """rule.json allowedPaths: changedFiles | newFiles | {authority, validator, own YAML} | the product YAMLs."""
    return set(changed) | set(new) | {authority, validator, own_yaml} | {"task-packets/%s.yaml" % p for p in products}


def check_allowed_paths(allowed, changed, new, authority, validator, own_yaml, products):
    need(len(allowed) == len(set(allowed)), "R11", "allowedPaths repeats a path")
    need(set(allowed) == expected_allowed_paths(changed, new, authority, validator, own_yaml, products), "R11",
         "allowedPaths is not the product-aware list")
    return True
