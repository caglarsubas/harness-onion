#!/usr/bin/env python3
"""MET-006 (SERVICE-EDGES-001): the checker of the service-edge record beside the catalog.

Reads architecture/service-edges.yaml, the catalog (architecture/services.yaml), the graph
(architecture/dependency-graph.yaml) and the record's schema (architecture/service-edges/schema.json), and refuses with a
rule id, SE-1 to SE-14 (CONTRACT_287 rev 6 section 4). Standard library plus the repository's safe YAML loader; the
schema's own JSON Schema check lives in tests/test_service_edges.py. The catalog, the graph and both catalog schemas stay
byte-equal: the record never repeats a dependency's mode, required flag or failure mode, which are read from the catalog
by the edge key consumer + dependency.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/service-edges.yaml"
SCHEMA_PATH = "architecture/service-edges/schema.json"
CATALOG_PATH = "architecture/services.yaml"
GRAPH_PATH = "architecture/dependency-graph.yaml"
SCHEMA_VERSION = "harness.planeon.ai/service-edges/v1alpha1"
U = "UNSPECIFIED"
HEADER = ("schemaVersion", "source", "externalProviders", "externalEndpointKinds", "edges", "handoffs", "graphMapping",
          "catalogGaps", "counts", "repeatedCalls")
ENTRY = ("consumer", "dependency", "lifecyclePhase", "requiredState", "owner", "transport", "timeout", "retry", "objectives",
         "capacityAndOverloadRule", "sli", "cache", "repeatedCallJustification", "degradation", "auditEvidence")
PHASES = ("INSTALL", "STARTUP", "ADMISSION", "INVOCATION", "BACKGROUND_RECONCILIATION", "OBSERVATION")
PROTOCOLS = ("HTTP", "GRPC", "POSTGRESQL", "KUBERNETES_API", "OTLP", "OCI_LAYOUT", "FILESYSTEM")
TIMEOUT_KEYS = {"SYNC": {"connectSeconds", "attemptSeconds", "ceilingSeconds", "deadline", "basis"},
                "ASYNC": {"publishAckSeconds", "basis"}, "CONTROL": {"reconcileSeconds", "basis"}, "ARTIFACT": {"fetchSeconds", "basis"}}
OBJECTIVES = {"SYNC": ("latency", "deadlinePropagation", "cancellation"), "ASYNC": ("lag", "acknowledgementAge"),
              "CONTROL": ("convergence",), "ARTIFACT": ("integrity", "readiness")}
PROVIDER_VALUES = ("OPERATOR", "TENANT", "TENANT_OR_OPERATOR", "PLATFORM_RELEASE")
# section 3.7's phrase map, matched in this order and in any case
PHRASE_MAP = (("tenant/operator-supplied", "TENANT_OR_OPERATOR"), ("digest-pinned", "PLATFORM_RELEASE"),
              ("operator-supplied", "OPERATOR"), ("tenant", "TENANT"))
SERVICE_KINDS = ("api", "gateway", "web-api", "collector")
CLASSES = {"policy-decision": "policy", "external.opa-engine": "policy", "registry-service": "registry",
           "external.postgresql": "database", "external.pgvector": "database"}
CLASS_ORDER = ("policy", "registry", "database")
HANDOFF_MEMBERS = {"REQUEST": {"kind", "branch", "from", "to", "via", "write", "lease"},
                   "CONTROLLER": {"kind", "from", "to", "via", "object", "consumerSide", "controllerSide"}}
OBJECT_MEMBERS = {"KUBERNETES_RESOURCE": {"kind", "resource", "subresource"}, "DATABASE_SCHEMA": {"kind", "schema", "objects"}}
KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REF = re.compile(r"^([A-Za-z0-9._/-]+)#L([1-9][0-9]*)$")
MESH = re.compile(r"\b(service mesh|mesh|sidecar|injected proxy|istio|linkerd|envoy)\b", re.I)
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}


def phrase_value(text):
    low = text.lower()
    return next((value for term, value in PHRASE_MAP if term in low), None)


def is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def key(c, d):
    return "%s->%s" % (c, d)


def shape_only(entry):
    """A SYNC entry whose deadline sum has an UNSPECIFIED term (section 3.3); a split entry uses its largest class."""
    r = entry.get("retry") if isinstance(entry.get("retry"), dict) else {}
    units = r.get("operations") if isinstance(r.get("operations"), list) else [r]
    atts = [u.get("maxAttempts") for u in units]
    t = entry.get("timeout") if isinstance(entry.get("timeout"), dict) else {}
    terms = [max(atts) if atts and all(isinstance(a, int) for a in atts) else U, t.get("attemptSeconds"),
             (r.get("backoff") or {}).get("maxSeconds")]
    return not all(is_number(v) for v in terms)


def file_reader(root=ROOT):
    """The default read: a regular file under the root, never a link; None when absent."""
    root = Path(root).resolve()

    def read(path):
        p = root / path
        return p.read_bytes() if p.is_file() and not p.is_symlink() else None
    return read


def load(root=ROOT, read=None):
    read = read or file_reader(root)
    return (safe_load(read(RECORD_PATH).decode("utf-8")), safe_load(read(CATALOG_PATH).decode("utf-8")),
            safe_load(read(GRAPH_PATH).decode("utf-8")), json.loads(read(SCHEMA_PATH).decode("utf-8")))


class Lines:
    """Cited lines at the head, by repository-relative path, through the read callable; never outside the root."""

    def __init__(self, read):
        self.read, self.cache = read, {}

    def get(self, ref):
        m = REF.match(ref or "")
        if not m or ".." in m.group(1).split("/"):
            return None
        path, n = m.group(1), int(m.group(2))
        if path not in self.cache:
            raw = self.read(path)
            self.cache[path] = raw.split(b"\n") if type(raw) is bytes else None
        rows = self.cache[path]
        return rows[n - 1] if rows is not None and n <= len(rows) else None


def maximal_paths(rg, branch):
    pairs = [(g["from"], g["to"]) for g in branch["edges"]]
    if "ai-gateway" in branch["entrypoints"]:
        pairs = [(g["from"], g["to"]) for g in rg["commonAdmissionEdges"]] + pairs
    out, found = {}, []
    for f, t in pairs:
        out.setdefault(f, []).append(t)

    def walk(p):
        nxt = [x for x in out.get(p[-1], []) if x not in p]
        if not nxt:
            found.append(p)
        for x in nxt:
            walk(p + [x])
    for ep in branch["entrypoints"]:
        walk([ep])
    return sorted(found)


def check_record(record, catalog, graph, schema, root=ROOT, read=None):
    """Return the refusals as (rule, message) pairs; an empty list passes. `read` (path -> bytes) defaults to the files
    under root."""
    bad = []
    fail = lambda rule, msg: bad.append((rule, msg))
    read = read or file_reader(root)
    lines = Lines(read)
    services = {s["id"]: s for s in catalog["services"]}
    externals = catalog["externalDependencies"]
    cat_deps = {(s["id"], d["id"]): d for s in catalog["services"] for d in s.get("dependencies", [])}
    deps_of = {s["id"]: {d["id"] for d in s.get("dependencies", [])} for s in catalog["services"]}
    rg = graph["runtimeRequestGraph"]
    cat_lines = read(CATALOG_PATH).decode("utf-8").split("\n")
    own_line = {}
    for i, line in enumerate(cat_lines):
        m = re.match(r"^\s+(external\.[a-z0-9-]+):\s(.*)$", line)
        if m and m.group(1) in externals and m.group(1) not in own_line:
            own_line[m.group(1)] = (i + 1, m.group(2))

    # SE-2 (header): the closed member set, also the schema's
    if not isinstance(record, dict) or tuple(record) != HEADER:
        fail("SE-2", "the header's members are not exactly %s" % (HEADER,))
        return bad
    if set(schema.get("properties", {})) != set(HEADER) or set(schema.get("required", [])) != set(HEADER):
        fail("SE-2", "the schema's closed member set differs from the header's")
    if record["schemaVersion"] != SCHEMA_VERSION or record["source"] != {"catalog": CATALOG_PATH, "catalogVersion": catalog["catalogVersion"],
                                                                        "graph": GRAPH_PATH}:
        fail("SE-2", "schemaVersion or source differs")
    edges = record["edges"] if isinstance(record["edges"], list) else []
    providers, kinds_map = record["externalProviders"], record["externalEndpointKinds"]

    # SE-1 coverage
    keys = [(e.get("consumer"), e.get("dependency")) for e in edges if isinstance(e, dict)]
    counts_k = Counter(keys)
    for k, n in counts_k.items():
        if n > 1:
            fail("SE-1", "duplicate entry %s" % key(*k))
        if k not in cat_deps:
            fail("SE-1", "orphan entry %s" % key(*k))
    for k in cat_deps:
        if k not in counts_k:
            fail("SE-1", "missing entry %s" % key(*k))
    if keys != [k for k in cat_deps if k in counts_k] and not any(r == "SE-1" for r, _ in bad):
        fail("SE-1", "the entries are not in the catalog's order")
    if set(providers) != set(externals):
        fail("SE-1", "externalProviders does not cover the 14 externals exactly")
    if set(kinds_map) != set(externals):
        fail("SE-1", "externalEndpointKinds does not cover the externals exactly")
    E = {(e["consumer"], e["dependency"]): e for e in edges if isinstance(e, dict) and (e.get("consumer"), e.get("dependency")) in cat_deps}
    gaps = {g.get("edge"): g for g in record["catalogGaps"] if isinstance(g, dict)}

    def protocols(c, d):
        e = E.get((c, d))
        return {f.get("protocol") for f in e["transport"]} if e and isinstance(e.get("transport"), list) else set()

    # SE-2 (endpoint kinds rows) and SE-10 (providers rows)
    for x, row in kinds_map.items():
        src = row.get("source", {}) if isinstance(row, dict) else {}
        if x in own_line and (src.get("ref") != "%s#L%d" % (CATALOG_PATH, own_line[x][0]) or (lines.get(src.get("ref")) or b"").decode()
                              .find(src.get("phrase", "\0")) < 0):
            fail("SE-2", "the externalEndpointKinds row of %s does not cite its own catalog line with its phrase" % x)
    for x, row in providers.items():
        src = row.get("source", {}) if isinstance(row, dict) else {}
        line = lines.get(src.get("ref"))
        parts = [p.strip() for p in str(src.get("phrase", "")).split("…") if p.strip()]
        if row.get("value") not in PROVIDER_VALUES:
            fail("SE-10", "%s: provider value %r" % (x, row.get("value")))
        if line is None or not parts or not all(p in line.decode("utf-8", "replace") for p in parts):
            fail("SE-10", "%s: the source line does not hold its phrase" % x)
        elif phrase_value(src.get("phrase", "")) != row.get("value"):
            fail("SE-10", "%s: the phrase does not state the value by the phrase map" % x)
        if x in own_line and phrase_value(own_line[x][1]) is not None and src.get("ref") != "%s#L%d" % (CATALOG_PATH, own_line[x][0]):
            fail("SE-10", "%s: its own catalog description states a value, and the row does not cite it (precedence 1)" % x)

    # SE-2 (header rows, closed members and enums; MET006 c2b D1, D4)
    for x, row in providers.items():
        if not isinstance(row, dict) or set(row) != {"value", "source"} or row.get("value") not in PROVIDER_VALUES:
            fail("SE-2", "%s: an externalProviders row outside its closed members or enum" % x)
    for x, row in kinds_map.items():
        if (not isinstance(row, dict) or set(row) != {"kinds", "source"} or not isinstance(row.get("kinds"), list)
                or not row["kinds"] or not set(row["kinds"]) <= {"EXTERNAL", "UNIX_SOCKET", "ARTIFACT_PATH"}):
            fail("SE-2", "%s: an externalEndpointKinds row outside its closed members or enum" % x)
    for h in record["handoffs"] if isinstance(record["handoffs"], list) else [None]:
        kind = h.get("kind") if isinstance(h, dict) else None
        obj = h.get("object") if isinstance(h, dict) else None
        if kind == "REQUEST":
            ok = set(h) == HANDOFF_MEMBERS["REQUEST"]
        elif kind == "CONTROLLER":
            ok = (set(h) == HANDOFF_MEMBERS["CONTROLLER"] and isinstance(obj, dict)
                  and set(obj) == OBJECT_MEMBERS.get(obj.get("kind"), set()))
        else:
            ok = False
        if not ok:
            fail("SE-2", "a handoff row is not exactly its closed members: %r" % (sorted(h) if isinstance(h, dict) else h,))
            fail("SE-13", "a handoff row is not exactly its closed members")
    for row in record["graphMapping"] if isinstance(record["graphMapping"], list) else [None]:
        if not isinstance(row, dict) or set(row) != {"branch", "from", "to", "edge"}:
            fail("SE-2", "a graphMapping row is not exactly its closed members")
    for row in record["catalogGaps"] if isinstance(record["catalogGaps"], list) else [None]:
        if not isinstance(row, dict) or set(row) != {"edge", "via", "missing", "source"}:
            fail("SE-2", "a catalogGaps row is not exactly its closed members")
    for row in record["repeatedCalls"] if isinstance(record["repeatedCalls"], list) else [None]:
        if not isinstance(row, dict) or set(row) != {"branch", "path", "class", "edges"} or row.get("class") not in CLASS_ORDER:
            fail("SE-2", "a repeatedCalls row is not exactly its closed members or class")

    request_edges = {(g["from"], g["to"]) for g in rg["commonAdmissionEdges"]} | {(g["from"], g["to"]) for b in rg["branches"] for g in b["edges"]}
    req_handoffs = [h for h in record["handoffs"] if isinstance(h, dict) and h.get("kind") == "REQUEST"]
    request_path = {k for k in request_edges if k in cat_deps}
    for h in req_handoffs:
        for side in ("write", "lease"):
            c, _, d = str(h.get(side, "")).partition("->")
            request_path.add((c, d))

    for (c, d), e in E.items():
        cd = cat_deps[(c, d)]
        mode, name = cd["mode"], key(c, d)
        # SE-2 entry shape
        if tuple(e) != ENTRY:
            fail("SE-2", "%s: members are not exactly the entry's" % name)
            continue
        if e["lifecyclePhase"] not in PHASES or not isinstance(e["requiredState"], str) or not KEBAB.match(e["requiredState"]):
            fail("SE-2", "%s: lifecyclePhase or requiredState" % name)
        t = e["timeout"] if isinstance(e["timeout"], dict) else {}
        if set(t) != TIMEOUT_KEYS[mode] or (mode == "SYNC" and t.get("deadline") != "PROPAGATED"):
            fail("SE-2", "%s: the timeout's members for %s" % (name, mode))
        for k2, v in t.items():
            if k2 not in ("deadline", "basis") and not (v == U or (is_number(v) and v > 0)):
                fail("SE-2", "%s: timeout %s" % (name, k2))
        forms = e["transport"] if isinstance(e["transport"], list) and e["transport"] else []
        if not forms:
            fail("SE-2", "%s: transport is empty" % name)
        callee_kind = services[d]["kind"] if d in services else ("external" if d in externals else None)
        for f in forms:
            ep = f.get("endpoint", {}) if isinstance(f, dict) else {}
            k = ep.get("kind")
            if f.get("protocol") not in PROTOCOLS:
                fail("SE-2", "%s: protocol %r" % (name, f.get("protocol")))
            # SE-3 TLS, per form
            if k in ("SERVICE_DNS", "EXTERNAL"):
                if f.get("tls") != {"required": True, "minVersion": "1.3"}:
                    fail("SE-3", "%s: a network form without TLS 1.3" % name)
            elif k in ("UNIX_SOCKET", "ARTIFACT_PATH"):
                if f.get("tls") != {"required": False}:
                    fail("SE-3", "%s: a local form's tls is not {required: false}" % name)
            elif k == "VIA":
                if "tls" in f:
                    fail("SE-3", "%s: a VIA form carries tls" % name)
            # SE-2 forms closed
            want = {"SERVICE_DNS": {"kind", "service", "port"}, "EXTERNAL": {"kind", "ref"}, "UNIX_SOCKET": {"kind", "path"},
                    "ARTIFACT_PATH": {"kind", "path"}, "VIA": {"kind", "via"}}.get(k)
            if want is None or set(ep) - {"digest"} != want or ("digest" in ep and (k != "ARTIFACT_PATH" or ep["digest"] != "REQUIRED")):
                fail("SE-2", "%s: endpoint %r" % (name, ep))
                continue
            if set(f) != ({"protocol", "endpoint"} if k == "VIA" else {"protocol", "endpoint", "tls"}):
                fail("SE-2", "%s: form members" % name)
            if k == "SERVICE_DNS" and (ep["service"] != d or ep["port"] not in ("https", "grpc")):
                fail("SE-2", "%s: SERVICE_DNS names another service or port" % name)
            if k == "EXTERNAL" and ep["ref"] != d:
                fail("SE-2", "%s: EXTERNAL names another external" % name)
            if k == "VIA":
                via, gap = ep["via"], gaps.get(name)
                if via == d:
                    fail("SE-2", "%s: via names the edge's own dependency" % name)
                elif via in deps_of[c]:
                    if f["protocol"] not in protocols(c, via):
                        fail("SE-2", "%s: the VIA protocol is not among its via entry's" % name)
                elif gap and gap.get("via") == via:
                    if f["protocol"] not in protocols(d, via):
                        fail("SE-2", "%s: the gap's VIA protocol is not the controller side's" % name)
                else:
                    fail("SE-3", "%s: via names no dependency of the consumer and no listed gap" % name)
        # SE-2 the callee-kind table
        fk = [f.get("endpoint", {}).get("kind") for f in forms if isinstance(f, dict)]
        if callee_kind in SERVICE_KINDS:
            ok = fk and all(k == "SERVICE_DNS" for k in fk)
        elif callee_kind == "controller":
            ok = fk == ["VIA"]
        elif callee_kind == "job":
            if "external.kubernetes-api" in deps_of[c]:
                ok = fk == ["VIA"] and forms[0]["endpoint"]["via"] == "external.kubernetes-api"
            else:
                ok = mode == "ARTIFACT" and fk == ["ARTIFACT_PATH"] and forms[0]["endpoint"].get("digest") == "REQUIRED"
        elif callee_kind == "worker":
            ok = fk == ["VIA"]
        elif callee_kind == "external":
            allowed = set(kinds_map.get(d, {}).get("kinds", []))
            ok = fk and set(fk) <= allowed
        else:
            ok = False
        if not ok:
            fail("SE-2", "%s: endpoint kinds %s against the callee-kind table (%s)" % (name, fk, callee_kind))
        # SE-4 retry (section 3.2, items 1-3)
        r = e["retry"] if isinstance(e["retry"], dict) else {}
        if set(r) - {"idempotency", "policy", "maxAttempts", "operationIdField", "operations", "backoff", "basis"}:
            fail("SE-2", "%s: retry members" % name)
        b = r.get("backoff", {})
        if (set(b) != {"initialSeconds", "maxSeconds", "jitter"} or b.get("jitter") not in ("FULL", "NONE", U)
                or not all(b.get(x) == U or (is_number(b.get(x)) and b.get(x) > 0) for x in ("initialSeconds", "maxSeconds"))):
            fail("SE-2", "%s: backoff" % name)
        units = []
        if "operations" in r:
            if {"idempotency", "policy", "maxAttempts", "operationIdField"} & set(r):
                fail("SE-4", "%s: entry-level retry fields beside operations" % name)
            ops = r["operations"] if isinstance(r["operations"], list) else []
            names = [o.get("class") for o in ops]
            if len(ops) < 2 or len(set(names)) != len(names) or not all(isinstance(n, str) and KEBAB.match(n) for n in names):
                fail("SE-4", "%s: operation classes must be distinct kebab-case tokens" % name)
            units = ops
            for o in ops:
                if not isinstance(o, dict) or not {"class", "idempotency", "policy", "maxAttempts"} <= set(o) \
                        or set(o) - {"class", "idempotency", "policy", "maxAttempts", "operationIdField"}:
                    fail("SE-2", "%s: an operations class is not exactly its closed members" % name)
        else:
            units = [r]
        for u in units:
            idem, pol, att = u.get("idempotency"), u.get("policy"), u.get("maxAttempts")
            if idem not in ("NATIVE", "RECEIPT_KEY", "NONE") or pol not in ("IDEMPOTENT_ONLY", "NONE") or not (att == U or (isinstance(att, int) and not isinstance(att, bool) and att >= 1)):
                fail("SE-2", "%s: retry idempotency, policy or maxAttempts outside its closed enum" % name)
                fail("SE-4", "%s: idempotency, policy or maxAttempts" % name)
                continue
            if pol == "IDEMPOTENT_ONLY" and idem != "NATIVE":
                fail("SE-4", "%s: IDEMPOTENT_ONLY without NATIVE" % name)
            if idem in ("RECEIPT_KEY", "NONE") and (pol != "NONE" or att != 1):
                fail("SE-4", "%s: %s requires policy NONE and maxAttempts 1" % (name, idem))
            if (idem == "RECEIPT_KEY") != bool(u.get("operationIdField")):
                fail("SE-4", "%s: operationIdField is required with RECEIPT_KEY and absent otherwise" % name)
        # SE-5 deadline
        if mode == "SYNC":
            atts = [u.get("maxAttempts") for u in units]
            att = max((a for a in atts if isinstance(a, int)), default=None) if all(isinstance(a, int) for a in atts) else None
            per, ceil, conn, bmax = t.get("attemptSeconds"), t.get("ceilingSeconds"), t.get("connectSeconds"), b.get("maxSeconds")
            if att is not None and all(is_number(v) for v in (per, ceil, bmax)) and att * per + (att - 1) * bmax > ceil:
                fail("SE-5", "%s: the attempts and backoff exceed ceilingSeconds" % name)
            for other in (per, ceil):
                if is_number(conn) and is_number(other) and conn > other:
                    fail("SE-5", "%s: connectSeconds exceeds attempt or ceiling" % name)
        # SE-6 basis
        for part, values, word in (("timeout", {k2: v for k2, v in t.items() if k2 not in ("deadline", "basis")}, False),
                                   ("retry", {"maxAttempts": max([u.get("maxAttempts") for u in units if isinstance(u.get("maxAttempts"), int)] or [0])}, True)):
            basis = (t if part == "timeout" else r).get("basis", {})
            nums = {k2: v for k2, v in values.items() if is_number(v) and (part == "timeout" or v > 1)}
            if basis == {"kind": U}:
                if part == "timeout" and nums:
                    fail("SE-6", "%s: a numeric timeout without a DOCUMENTED_BOUND basis" % name)
                if part == "retry" and nums:
                    fail("SE-6", "%s: a numeric maxAttempts above 1 without a DOCUMENTED_BOUND basis" % name)
                if part == "retry" and any(b.get(x) != U for x in ("initialSeconds", "maxSeconds", "jitter")):
                    fail("SE-6", "%s: a backoff value under an UNSPECIFIED retry basis" % name)
            elif isinstance(basis, dict) and basis.get("kind") == "DOCUMENTED_BOUND" and set(basis) == {"kind", "ref", "lineSha256"}:
                line = lines.get(basis["ref"])
                if line is None or hashlib.sha256(line).hexdigest() != basis["lineSha256"]:
                    fail("SE-6", "%s: the %s basis line is missing or its lineSha256 differs" % (name, part))
                else:
                    txt = line.decode("utf-8", "replace").lower()
                    for k2, v in nums.items():
                        n = v - 1 if word else v
                        if str(n) not in txt and WORDS.get(n, "\0") not in txt:
                            fail("SE-6", "%s: the %s basis line does not state %s" % (name, part, k2))
            else:
                if not (isinstance(basis, dict) and basis.get("kind") in (U, "DOCUMENTED_BOUND")):
                    fail("SE-2", "%s: the %s basis kind outside its closed enum" % (name, part))
                fail("SE-6", "%s: the %s basis" % (name, part))
        # SE-7 lifecycle
        if (c, d) in request_path and e["lifecyclePhase"] not in ("ADMISSION", "INVOCATION"):
            fail("SE-7", "%s: a request-path edge in %s" % (name, e["lifecyclePhase"]))
        if mode == "ARTIFACT" and e["lifecyclePhase"] == "INVOCATION":
            fail("SE-7", "%s: an ARTIFACT edge in INVOCATION" % name)
        if mode == "CONTROL" and (c, d) in request_path and graph.get("controlPlaneOnRuntimePath") is False:
            fail("SE-7", "%s: a CONTROL edge on the request path" % name)
        # SE-8 objectives
        o = e["objectives"] if isinstance(e["objectives"], dict) else {}
        if any(v not in (U, "REQUIRED") for v in o.values()) or e["capacityAndOverloadRule"] != U or e["sli"] != U:
            fail("SE-2", "%s: an objective, capacityAndOverloadRule or sli value outside its closed enum" % name)
        if tuple(o) != OBJECTIVES[mode] or any(v not in (U, "REQUIRED") for v in o.values()):
            fail("SE-8", "%s: objectives are not exactly the mode's" % name)
        if mode == "SYNC" and (o.get("deadlinePropagation") != "REQUIRED" or o.get("cancellation") != "REQUIRED"):
            fail("SE-8", "%s: SYNC deadlinePropagation and cancellation are REQUIRED" % name)
        if e["capacityAndOverloadRule"] != U or e["sli"] != U:
            fail("SE-8", "%s: capacityAndOverloadRule and sli are UNSPECIFIED at 287" % name)
        if callee_kind == "job" and fk == ["ARTIFACT_PATH"] and (
                o.get("integrity") != "REQUIRED" or forms[0].get("endpoint", {}).get("digest") != "REQUIRED"):
            fail("SE-8", "%s: a job handed an artifact requires integrity and its form's digest: REQUIRED" % name)
        ca = e["cache"]
        if not (isinstance(ca, dict) and ((ca.get("kind") == "NONE" and set(ca) == {"kind"}) or (
                ca.get("kind") == "BOUNDED_METADATA" and set(ca) == {"kind", "freshness", "revocation", "outage"}
                and all(isinstance(ca[x], str) and ca[x].strip() for x in ("freshness", "revocation", "outage"))))):
            fail("SE-2", "%s: cache outside its closed kinds or members" % name)
        for member in ("repeatedCallJustification", "degradation"):
            if not (e[member] is None or (isinstance(e[member], str) and e[member].strip())):
                fail("SE-2", "%s: %s is neither null nor a non-empty statement" % (name, member))
        ae0 = e["auditEvidence"]
        if not (ae0 is None or ae0 == "NOT_CARRIED" or (isinstance(ae0, dict) and set(ae0) == {"preservedBy"}
                                                       and isinstance(ae0["preservedBy"], str) and ae0["preservedBy"].strip())):
            fail("SE-2", "%s: auditEvidence outside its closed forms" % name)
        if not (isinstance(e["owner"], dict) and set(e["owner"]) == {"provider", "consumer", "escalation"}):
            fail("SE-2", "%s: owner is not exactly its closed members" % name)
        # SE-9 degradation and audit evidence
        if cd["failureMode"] == "FAIL_OPEN":
            pol = (cd.get("degradationPolicy") or {}).get("type", "")
            if not isinstance(e["degradation"], str) or not e["degradation"].strip() or pol not in e["degradation"]:
                fail("SE-9", "%s: a FAIL_OPEN edge without its named degradation" % name)
            ae = e["auditEvidence"]
            if not (ae == "NOT_CARRIED" or (isinstance(ae, dict) and set(ae) == {"preservedBy"} and isinstance(ae["preservedBy"], str)
                                             and ae["preservedBy"].strip())):
                fail("SE-9", "%s: a FAIL_OPEN edge without auditEvidence" % name)
        elif e["degradation"] is not None or e["auditEvidence"] is not None:
            fail("SE-9", "%s: a FAIL_CLOSED edge carries degradation or auditEvidence" % name)
        # SE-10 owner
        ow = e["owner"] if isinstance(e["owner"], dict) else {}
        cons = services[c]["ownerRepository"]
        if d in externals:
            want = {"provider": providers.get(d, {}).get("value"), "consumer": cons, "escalation": cons}
        else:
            prov = services[d]["ownerRepository"]
            want = {"provider": prov, "consumer": cons, "escalation": prov}
        if ow != want:
            fail("SE-10", "%s: owner differs from section 3.1's rules" % name)
        # SE-12 no mesh
        if MESH.search(json.dumps(e)) or re.search(r"infrastructure[- ]retr", json.dumps(e), re.I):
            fail("SE-12", "%s: names a mesh, a sidecar or an injected proxy, or delegates retries" % name)

    # SE-11 repeated calls
    rows = []
    for b in rg["branches"]:
        for p in maximal_paths(rg, b):
            nodes = set(p)
            calls = [k for k, e in E.items() if k[0] in nodes and e.get("lifecyclePhase") in ("ADMISSION", "INVOCATION") and k[1] in CLASSES]
            for cl in CLASS_ORDER:
                ce = sorted(key(*k) for k in calls if CLASSES[k[1]] == cl)
                if len(ce) >= 2:
                    rows.append({"branch": b["id"], "path": p, "class": cl, "edges": ce})
    for b in rg["branches"]:
        for p in maximal_paths(rg, b):
            for caller_edge, callee_edge in zip(zip(p, p[1:]), zip(p[1:], p[2:])):
                e1, e2 = E.get(caller_edge), E.get(callee_edge)
                if not (isinstance(e1, dict) and isinstance(e2, dict) and isinstance(e1.get("timeout"), dict)
                        and isinstance(e2.get("timeout"), dict)):
                    continue
                c1, c2 = e1["timeout"].get("ceilingSeconds"), e2["timeout"].get("ceilingSeconds")
                if is_number(c1) and is_number(c2) and not c2 < c1:
                    fail("SE-5", "%s: the callee's ceilingSeconds is not below its caller's (%s) along %s" % (
                        key(*callee_edge), key(*caller_edge), b["id"]))
    if record["repeatedCalls"] != rows:
        fail("SE-11", "repeatedCalls differs from the checker's sorted list (%d rows expected)" % len(rows))
    listed = {k for r in rows for k in r["edges"]}
    for (c, d), e in E.items():
        if tuple(e) != ENTRY:
            continue
        bounded = isinstance(e["cache"], dict) and e["cache"].get("kind") == "BOUNDED_METADATA"
        just = e["repeatedCallJustification"]
        if key(c, d) in listed and not bounded and not (isinstance(just, str) and just.strip()):
            fail("SE-11", "%s: a repeated call that is neither BOUNDED_METADATA nor justified" % key(c, d))
        if (key(c, d) not in listed or bounded) and just is not None:
            fail("SE-11", "%s: a stray repeatedCallJustification" % key(c, d))

    # SE-12 (header strings)
    if MESH.search(json.dumps({k: record[k] for k in HEADER if k != "edges"})):
        fail("SE-12", "the header names a mesh, a sidecar or an injected proxy")

    # SE-13 the graph and the handoffs
    gm = record["graphMapping"]
    graph_rows = [("common", g["from"], g["to"]) for g in rg["commonAdmissionEdges"]] + \
                 [(b["id"], g["from"], g["to"]) for b in rg["branches"] for g in b["edges"]]
    handoff_pairs = {(h.get("from"), h.get("to")) for h in req_handoffs}
    want_gm = [{"branch": br, "from": f, "to": t, "edge": key(f, t)} for br, f, t in graph_rows if (f, t) not in handoff_pairs]
    if gm != want_gm or any((r["from"], r["to"]) not in E for r in gm):
        fail("SE-13", "graphMapping does not map each request edge to its entry")
    for br, f, t in graph_rows:
        if (f, t) not in E and (f, t) not in handoff_pairs:
            fail("SE-13", "the request edge %s maps to no entry and no request handoff" % key(f, t))
    for h in req_handoffs:
        for side in ("write", "lease"):
            c, _, d = str(h.get(side, "")).partition("->")
            if (c, d) not in cat_deps or d != h.get("via"):
                fail("SE-13", "the request handoff's %s is not a catalog edge to its via" % side)
    ctl = [h for h in record["handoffs"] if isinstance(h, dict) and h.get("kind") == "CONTROLLER"]
    for (c, d), e in E.items():
        if services.get(d, {}).get("kind") != "controller" or tuple(e) != ENTRY:
            continue
        mine = [h for h in ctl if h.get("from") == c and h.get("to") == d]
        via = e["transport"][0]["endpoint"].get("via") if e["transport"] else None
        held = {s["name"] for s in services[d].get("stores", [])} & deps_of[d]
        if len(mine) != 1:
            fail("SE-13", "%s: not exactly one controller handoff" % key(c, d))
            continue
        h = mine[0]
        if h.get("via") != via or held != {via}:
            fail("SE-13", "%s: the handoff's via is not the entry's via and the controller's store holding the object" % key(c, d))
        if h.get("controllerSide") != key(d, via) or (d, via) not in cat_deps:
            fail("SE-13", "%s: controllerSide is not a catalog edge" % key(c, d))
        cs = h.get("consumerSide")
        g = gaps.get(key(c, d))
        if cs != key(c, via) or not ((c, via) in cat_deps or (g and g.get("missing") == cs)):
            fail("SE-13", "%s: consumerSide is neither a catalog edge nor a listed gap" % key(c, d))
    for name, g in gaps.items():
        c, _, d = name.partition("->")
        mc, _, mv = str(g.get("missing", "")).partition("->")
        if not any(h.get("from") == c and h.get("to") == d for h in ctl) or (mc, mv) in cat_deps or mc != c or mv != g.get("via"):
            fail("SE-13", "the catalogGaps row %s names no controller handoff, or the catalog has its missing edge" % name)
    if len(ctl) != sum(1 for k in E if services.get(k[1], {}).get("kind") == "controller"):
        fail("SE-13", "controller handoffs without an entry")

    # SE-14 counts
    forms_all = [f for e in E.values() if tuple(e) == ENTRY and isinstance(e["transport"], list) for f in e["transport"]]
    byid = Counter()
    for e in E.values():
        if tuple(e) != ENTRY or not isinstance(e["retry"], dict):
            continue
        if "operations" in e["retry"]:
            byid.update(o.get("idempotency") for o in e["retry"]["operations"])
        else:
            byid[e["retry"].get("idempotency")] += 1
    kinds = Counter(f.get("endpoint", {}).get("kind") for f in forms_all)
    want_counts = {"edges": len(E), "byLifecyclePhase": dict(sorted(Counter(e["lifecyclePhase"] for e in E.values()).items())),
                   "byProtocol": dict(sorted(Counter(f.get("protocol") for f in forms_all).items())),
                   "byEndpointKind": dict(sorted(kinds.items())), "byIdempotency": dict(sorted(byid.items())),
                   "networkForms": kinds["SERVICE_DNS"] + kinds["EXTERNAL"], "localForms": kinds["UNIX_SOCKET"] + kinds["ARTIFACT_PATH"],
                   "viaForms": kinds["VIA"],
                   "numericEdges": sum(1 for e in E.values() if isinstance(e.get("timeout"), dict)
                                       and any(is_number(v) for v in e["timeout"].values())),
                   "shapeOnlyEdges": sum(1 for k, e in E.items() if cat_deps[k]["mode"] == "SYNC" and tuple(e) == ENTRY and shape_only(e))}
    if record["counts"] != want_counts:
        fail("SE-14", "counts differ from the checker's: %s" % {k: v for k, v in want_counts.items() if record["counts"].get(k) != v})
    return bad


def check(root=ROOT, read=None):
    return check_record(*load(root, read), root=root, read=read)


def main(argv=None):
    root = Path((argv or sys.argv[1:] or [str(ROOT)])[0])
    refusals = check(root)
    record = load(root)[0]
    if refusals:
        for rule, msg in refusals:
            print("%s: %s" % (rule, msg))
        print("SERVICE EDGES REFUSED: %d" % len(refusals))
        return 1
    print("SERVICE EDGES OK: %d entries, %d handoffs, %d repeated-call rows, counts %s" % (
        len(record["edges"]), len(record["handoffs"]), len(record["repeatedCalls"]), json.dumps(record["counts"], sort_keys=True)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
