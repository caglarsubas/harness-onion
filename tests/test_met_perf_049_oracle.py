"""D5a oracle tests for MET-PERF-049 (slot 286): class rule v2.4, the ledger hunk side record,
MET-PERF-048's inert provisions, the countEffect demotion rows and identity model v4's clause (xi).

Owner decision D5a: a contract packet carries tests written outside the candidate, by someone who
is not its builder. These tests are black-box. Every expected value below comes from one of these
sources and from nothing else:

- CONTRACT_286 rev 6:
  - section 3.1, class rule v2.4: R1 (the member forms F1, F2 and F3, and the refused forms), R2
    (a digit move is cascade only on declared pairs: the catalog pair (n, n + steps[1]) and the
    context's countPairs; the collision residual stays cascade), W (the weights append form, the
    re-measure and the duplicate key) and the v2.4 context with bind_context's countPairs checks;
  - sections 3.6 and 4.3: the ledger hunk side record, the record.json entry's three keys and the
    equality checks;
  - section 3.9: P-048-1..4 and the T1 signal file (its path, its file rules and its outcomes);
  - section 3.11: the countEffect rows demoted (neutral) and demoted-outcome-explained (pending
    isolation);
  - sections 14 and 15: identity model v4's step clause (xi), one era-model replay reader lift in
    def _replay, required exactly when the old head holds that reader;
- architecture/chain-checkpoint/README.md at the candidate: the countEffect table, the signal
  file's HOME-relative path and the writing run's stated differences. It is read as text at test
  time, and its table was also read on paper for the literal expectation below;
- architecture/chain-checkpoint/vectors.json at the candidate: vectors 15-25 and 28-38;
- facts the operator states from the candidate (operator-stated): the entry points, argument
  shapes and return shapes of the reader (classify_v24, context_v24, bind_context,
  RULE_V24_SHA256, RULES_BY_SHA, COUNT_EFFECT, signal_check, SIGNAL_RELATIVE, SIGNAL_MAX), of the
  writer (ledger_hunks, check_ledger_hunks, LEDGER_HUNK_MEMBERS, ENTRY_KEYS, stated,
  signal_present) and of identity model v4 (check_xi).

Every case is built from plain data: bytes, dicts and files written under pytest's tmp_path. The
file loads exactly three repository modules by file path and reads the checkpoint README as text.
"""

import ast
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "architecture" / "chain-checkpoint" / "README.md"

_MODULES = {}


def _load(relative, name):
    """Load one repository module by its file path into a fresh module object, once."""
    module = _MODULES.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, ROOT / relative)
        assert spec is not None and spec.loader is not None, relative
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
        _MODULES[name] = module
    return module


def _reader():
    """The reader, ci/chain_checkpoint.py (operator-stated: standard library only)."""
    return _load("ci/chain_checkpoint.py", "met_perf_049_oracle_reader")


def _writer():
    """The writer, scripts/chain_checkpoint_writer.py (operator-stated: importing reads nothing)."""
    return _load("scripts/chain_checkpoint_writer.py", "met_perf_049_oracle_writer")


def _identity():
    """Identity model v4, scripts/chain_identity_v4.py (CONTRACT_286 section 15)."""
    return _load("scripts/chain_identity_v4.py", "met_perf_049_oracle_identity_v4")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------------------------
# The v2.4 context (CONTRACT_286 section 3.1; operator-stated shape of classify_v24's ctx).
# ---------------------------------------------------------------------------------------------

NEW_PACKET = "MET-PERF-049"
PREV_VALIDATOR = "scripts/validate_met_adopt_008.py"
PREV_TEST = "tests/test_met_adopt_008.py"
PRODUCTS = ["SYN-ALPHA-001", "SYN-BETA-002"]
BASELINE = 296
VOCABULARY = ["bridge", "cascade", "other", "record", "register"]
AUTHORITY_PATH = "architecture/ledger-rewrite-authority.json"
DIGEST_ZERO = "0" * 64

NEW_FILES = {
    "task-packets/MET-PERF-049.yaml": "5" * 64,
    "scripts/validate_met_perf_049.py": "6" * 64,
    "tests/test_met_perf_049.py": "7" * 64,
    "tests/test_syn_extra.py": "8" * 64,
    "architecture/syn-extra/record.json": "9" * 64,
}
NEW_TESTS = ["tests/test_met_perf_049.py", "tests/test_syn_extra.py"]


def _ctx(k=0, count_pairs=(), new_tests=(), products=None):
    """classify_v24's context (operator-stated): steps [1, 1 + K], the catalog pair first."""
    steps = [1, 1 + k]
    pairs = [[BASELINE, BASELINE + steps[1]]] + [list(pair) for pair in count_pairs]
    return {
        "prevValidator": PREV_VALIDATOR,
        "prevTest": PREV_TEST,
        "newPacket": NEW_PACKET,
        "products": list(PRODUCTS[:k] if products is None else products),
        "steps": steps,
        "pairs": pairs,
        "newTests": list(new_tests),
    }


def _context5(k=0, count_pairs=()):
    """A v2.4 hunk-class context: {newPacket, prevValidator, prevTest, steps, countPairs}."""
    return {
        "newPacket": NEW_PACKET,
        "prevValidator": PREV_VALIDATOR,
        "prevTest": PREV_TEST,
        "steps": [1, 1 + k],
        "countPairs": json.loads(json.dumps(count_pairs)),
    }


def _authority(k=0, products=None):
    """An authority dict: baselinePackets of size 296, productPackets of size K, newFiles."""
    product_ids = PRODUCTS[:k] if products is None else products
    return {
        "authorityPacket": NEW_PACKET,
        "baselinePackets": {"BASE-PACKET-%03d" % index: DIGEST_ZERO for index in range(BASELINE)},
        "productPackets": {packet: DIGEST_ZERO for packet in product_ids},
        "changedFiles": {
            PREV_VALIDATOR: {"beforeSha256": "1" * 64, "afterSha256": "2" * 64, "reverseHunks": []},
            PREV_TEST: {"beforeSha256": "3" * 64, "afterSha256": "4" * 64, "reverseHunks": []},
        },
        "newFiles": dict(NEW_FILES),
    }


def _bind(k=0, count_pairs=(), context=None):
    """bind_context over an authority carrying a v2.4 rule digest and context (operator-stated)."""
    reader = _reader()
    rec = _authority(k)
    rec["hunkClassRuleSha256"] = reader.RULE_V24_SHA256
    rec["hunkClassVocabulary"] = list(VOCABULARY)
    rec["hunkClassContext"] = _context5(k, count_pairs) if context is None else context
    return reader.bind_context(AUTHORITY_PATH, rec)


def _classify(path, prefix, old, new, suffix, ctx):
    """Class one reverse hunk: the forward edit put `new` where `old` was, between prefix and
    suffix; `after` is the edited file, `at` the offset of `new`, `insert` the bytes the undo puts
    back (operator-stated argument shape of classify_v24)."""
    after = prefix + new + suffix
    return _reader().classify_v24(path, after, len(prefix), new, old, ctx)


# ---------------------------------------------------------------------------------------------
# R2, digit moves (section 3.1 R2; vectors 15-17). n = 296: catalog pair (296, 297) at K = 0 and
# (296, 299) at K = 2.
# ---------------------------------------------------------------------------------------------

R2_PATH = "scripts/authority_map.py"
R2_PREFIX = b'"""A synthetic module whose count line moves."""\n\n'
R2_SUFFIX = b"\n# the end of the synthetic module\n"

R2_UNDECLARED = [
    ("plus-one-outside-pairs", 0, [[311, 312]], b"PACKET_COUNT = 305\n", b"PACKET_COUNT = 306\n"),
    ("catalog-pair-reversed", 0, [[311, 312]], b"PACKET_COUNT = 297\n", b"PACKET_COUNT = 296\n"),
    ("catalog-start-wrong-step", 0, [[311, 312]], b"PACKET_COUNT = 296\n", b"PACKET_COUNT = 298\n"),
    ("k0-catalog-move-at-k2", 2, [[305, 308]], b"PACKET_COUNT = 296\n", b"PACKET_COUNT = 297\n"),
    ("one-declared-one-not", 0, [[311, 312]], b"COUNTS = (296, 305)\n", b"COUNTS = (297, 306)\n"),
]

R2_DECLARED = [
    ("catalog-pair-k0", 0, [[311, 312]], b"PACKET_COUNT = 296\n", b"PACKET_COUNT = 297\n"),
    ("count-pair-k0", 0, [[311, 312]], b"PATH_COUNT = 311\n", b"PATH_COUNT = 312\n"),
    ("both-pairs-one-hunk", 0, [[311, 312]], b"COUNTS = (296, 311)\n", b"COUNTS = (297, 312)\n"),
    ("catalog-pair-k2", 2, [[305, 308]], b"PACKET_COUNT = 296\n", b"PACKET_COUNT = 299\n"),
    ("count-pair-k2", 2, [[305, 308]], b"PATH_COUNT = 305\n", b"PATH_COUNT = 308\n"),
]

R2_COLLISION = [
    ("timeout-equals-count-pair", 0, [[311, 312]], b"TIMEOUT_SECONDS = 311\n",
     b"TIMEOUT_SECONDS = 312\n"),
    ("retry-limit-equals-catalog-pair", 0, [], b"RETRY_LIMIT = 296\n", b"RETRY_LIMIT = 297\n"),
]


class TestRuleV24DigitMoves:
    """CONTRACT_286 section 3.1, R2 (VIS-285-RULE (a)); vectors 15, 16 and 17."""

    @pytest.mark.parametrize(
        "k, count_pairs, old, new",
        [case[1:] for case in R2_UNDECLARED],
        ids=[case[0] for case in R2_UNDECLARED],
    )
    def test_undeclared_digit_move_is_other(self, k, count_pairs, old, new):
        """Vector 15 (section 3.1 R2): a digit move whose (before, after) pair is neither the
        catalog pair (n, n + steps[1]) nor a countPairs pair is class other."""
        ctx = _ctx(k, count_pairs)
        assert _classify(R2_PATH, R2_PREFIX, old, new, R2_SUFFIX, ctx) == "other"

    @pytest.mark.parametrize(
        "k, count_pairs, old, new",
        [case[1:] for case in R2_DECLARED],
        ids=[case[0] for case in R2_DECLARED],
    )
    def test_declared_digit_pair_is_cascade(self, k, count_pairs, old, new):
        """Vector 16 (section 3.1 R2): a move along the catalog pair or a countPairs pair, every
        pair of the hunk declared, is class cascade."""
        ctx = _ctx(k, count_pairs)
        assert _classify(R2_PATH, R2_PREFIX, old, new, R2_SUFFIX, ctx) == "cascade"

    @pytest.mark.parametrize(
        "k, count_pairs, old, new",
        [case[1:] for case in R2_COLLISION],
        ids=[case[0] for case in R2_COLLISION],
    )
    def test_collision_residual_stays_cascade(self, k, count_pairs, old, new):
        """Vector 17 (section 3.1 R2, the stated limit): a real edit whose numbers equal a declared
        pair stays class cascade."""
        ctx = _ctx(k, count_pairs)
        assert _classify(R2_PATH, R2_PREFIX, old, new, R2_SUFFIX, ctx) == "cascade"


# ---------------------------------------------------------------------------------------------
# R1, member forms (section 3.1 R1; vectors 18-21). Each hunk is a pure insertion.
# ---------------------------------------------------------------------------------------------

R1_PATH = "scripts/validate_met_perf_046.py"
NEW_CHAIN = b"    successor.successor.successor.NEW_PACKET,\n"
PRODUCT_CHAIN = b"    *successor.successor.successor.PRODUCT_PACKETS,\n"
DEEPER_CHAIN = b"    successor.successor.successor.successor.NEW_PACKET,\n"

R1_FORMS = {
    "members": (
        b"MEMBERS = [\n    successor.NEW_PACKET,\n    successor.successor.NEW_PACKET,\n",
        b"]\n",
    ),
    "id-tuple": (b'PACKETS = ("MET-PERF-047", "MET-ADOPT-008"', b")\n"),
    "id-list": (b'PACKETS = ["MET-PERF-047", "MET-ADOPT-008"', b"]\n"),
}

R1_ACCEPTED = [
    ("F1-chain-new-k0", 0, "members", NEW_CHAIN),
    ("F2-chain-new-then-products-k1", 1, "members", NEW_CHAIN + PRODUCT_CHAIN),
    ("F2-chain-new-then-products-k2", 2, "members", NEW_CHAIN + PRODUCT_CHAIN),
    ("F3-ids-key-order-k1", 1, "id-tuple", b', "MET-PERF-049", "SYN-ALPHA-001"'),
    ("F3-ids-key-order-k2", 2, "id-tuple", b', "MET-PERF-049", "SYN-ALPHA-001", "SYN-BETA-002"'),
    ("F3-new-id-alone-k0", 0, "id-tuple", b', "MET-PERF-049"'),
    ("F3-id-list-key-order-k2", 2, "id-list",
     b', "MET-PERF-049", "SYN-ALPHA-001", "SYN-BETA-002"'),
]

R1_REFUSED = [
    ("F1-alone-k1", 1, "members", NEW_CHAIN),
    ("F1-alone-k2", 2, "members", NEW_CHAIN),
    ("F2-at-k0", 0, "members", NEW_CHAIN + PRODUCT_CHAIN),
    ("F2-products-first-k1", 1, "members", PRODUCT_CHAIN + NEW_CHAIN),
    ("two-new-chains-k0", 0, "members", NEW_CHAIN + DEEPER_CHAIN),
    ("mixed-chain-and-id-k0", 0, "members", NEW_CHAIN + b'    "MET-PERF-049",\n'),
    ("mixed-chains-and-id-k1", 1, "members", NEW_CHAIN + PRODUCT_CHAIN + b'    "SYN-ALPHA-001",\n'),
    ("F3-out-of-key-order-k2", 2, "id-tuple", b', "MET-PERF-049", "SYN-BETA-002", "SYN-ALPHA-001"'),
    ("F3-products-before-new-id-k2", 2, "id-tuple",
     b', "SYN-ALPHA-001", "SYN-BETA-002", "MET-PERF-049"'),
    ("F3-subset-k2", 2, "id-tuple", b', "MET-PERF-049", "SYN-ALPHA-001"'),
    ("F3-new-id-alone-k1", 1, "id-tuple", b', "MET-PERF-049"'),
    ("F3-quoted-unlike-the-line-k1", 1, "id-tuple", b", 'MET-PERF-049', 'SYN-ALPHA-001'"),
    ("F3-extra-id-k0", 0, "id-tuple", b', "MET-PERF-049", "SYN-ALPHA-001"'),
]


class TestRuleV24MemberForms:
    """CONTRACT_286 section 3.1, R1 (283-D4, MP049-C1-2); vectors 18, 19, 20 and 21."""

    @pytest.mark.parametrize(
        "k, form, inserted",
        [case[1:] for case in R1_ACCEPTED],
        ids=[case[0] for case in R1_ACCEPTED],
    )
    def test_accepted_member_form_is_cascade(self, k, form, inserted):
        """Vectors 18-20 (section 3.1 R1): F1 at K = 0, F2 at K >= 1, and F3 (the new id, then at
        K >= 1 the product ids in productPackets key order, quoted as the line's ids) are
        cascade."""
        prefix, suffix = R1_FORMS[form]
        assert _classify(R1_PATH, prefix, b"", inserted, suffix, _ctx(k)) == "cascade"

    @pytest.mark.parametrize(
        "k, form, inserted",
        [case[1:] for case in R1_REFUSED],
        ids=[case[0] for case in R1_REFUSED],
    )
    def test_refused_member_form_is_other(self, k, form, inserted):
        """Vector 21 (section 3.1 R1): F1 alone at K >= 1, F2 at K = 0, F3 out of key order or a
        subset, any other run and an insertion mixing chains and ids are class other."""
        prefix, suffix = R1_FORMS[form]
        assert _classify(R1_PATH, prefix, b"", inserted, suffix, _ctx(k)) == "other"


# ---------------------------------------------------------------------------------------------
# W, the weights append form (section 3.1 W, Q-286-3 (a); vectors 22-24).
# ---------------------------------------------------------------------------------------------

WEIGHTS_PATH = "ci/parallel_suite_weights.json"
W_OPEN = b"{\n"
W_ALPHA = b'  "tests/test_alpha.py": 1.5,\n'
W_OMEGA_LAST = b'  "tests/test_omega.py": 2.25'
W_CLOSE = b"\n}\n"

W_RECORD = [
    ("one-entry-inserted", W_OPEN + W_ALPHA, b"", b'  "tests/test_gamma.py": 0.75,\n',
     W_OMEGA_LAST + W_CLOSE, ["tests/test_gamma.py", "tests/test_delta.py"]),
    ("two-entries-appended", W_OPEN + W_ALPHA + W_OMEGA_LAST, b"",
     b',\n  "tests/test_gamma.py": 0.75,\n  "tests/test_delta.py": 0.5', W_CLOSE,
     ["tests/test_gamma.py", "tests/test_delta.py"]),
]

W_OTHER = [
    ("re-measure", W_OPEN, W_ALPHA, b'  "tests/test_alpha.py": 1.75,\n', W_OMEGA_LAST + W_CLOSE,
     ["tests/test_gamma.py", "tests/test_delta.py"]),
    ("re-measure-of-a-new-test-key", W_OPEN, W_ALPHA, b'  "tests/test_alpha.py": 1.75,\n',
     W_OMEGA_LAST + W_CLOSE, ["tests/test_alpha.py", "tests/test_gamma.py"]),
    ("duplicate-key-inserted", W_OPEN + W_ALPHA, b"", b'  "tests/test_alpha.py": 0.75,\n',
     W_OMEGA_LAST + W_CLOSE, ["tests/test_alpha.py", "tests/test_gamma.py"]),
    ("duplicate-key-appended", W_OPEN + W_ALPHA + W_OMEGA_LAST, b"",
     b',\n  "tests/test_omega.py": 0.5', W_CLOSE, ["tests/test_omega.py", "tests/test_gamma.py"]),
    ("key-not-a-new-test-file", W_OPEN + W_ALPHA, b"", b'  "tests/test_gamma.py": 0.75,\n',
     W_OMEGA_LAST + W_CLOSE, ["tests/test_delta.py"]),
]


class TestRuleV24WeightsForm:
    """CONTRACT_286 section 3.1, W (Q-286-3 (a), MP049-C1-15); vectors 22, 23 and 24."""

    @pytest.mark.parametrize(
        "prefix, old, new, suffix, new_tests",
        [case[1:] for case in W_RECORD],
        ids=[case[0] for case in W_RECORD],
    )
    def test_weights_append_of_new_test_files_is_record(self, prefix, old, new, suffix, new_tests):
        """Vector 22 (section 3.1 W): a hunk in ci/parallel_suite_weights.json that only inserts
        entries keyed by the step's own new test files, every existing entry byte-equal, is
        class record."""
        ctx = _ctx(0, [], new_tests)
        assert _classify(WEIGHTS_PATH, prefix, old, new, suffix, ctx) == "record"

    @pytest.mark.parametrize(
        "prefix, old, new, suffix, new_tests",
        [case[1:] for case in W_OTHER],
        ids=[case[0] for case in W_OTHER],
    )
    def test_weights_re_measure_or_duplicate_key_is_other(
        self, prefix, old, new, suffix, new_tests
    ):
        """Vectors 23 and 24 (section 3.1 W): a re-measure of an existing entry, an inserted entry
        repeating an existing key, and an entry whose key is not a new test file are class other."""
        ctx = _ctx(0, [], new_tests)
        assert _classify(WEIGHTS_PATH, prefix, old, new, suffix, ctx) == "other"

    def test_weights_form_belongs_to_the_weights_file_only(self):
        """Section 3.1 W: RECORDS gains the weights file for this form only, so the same insertion
        in another JSON file is not class record."""
        case = W_RECORD[0]
        ctx = _ctx(0, [], case[5])
        result = _classify("architecture/syn-weights.json", case[1], case[2], case[3], case[4], ctx)
        assert result != "record"


# ---------------------------------------------------------------------------------------------
# The v2.4 context and bind_context (section 3.1, the v2.4 context; section 2's correction;
# vector 25).
# ---------------------------------------------------------------------------------------------

BIND_ACCEPTED = [
    ("k0-no-count-pairs", 0, []),
    ("k0-two-count-pairs", 0, [[305, 306], [311, 312]]),
    ("k1-one-count-pair", 1, [[305, 307]]),
    ("k2-one-count-pair", 2, [[305, 308]]),
]

BIND_COUNT_PAIRS_FAULTS = [
    ("not-distinct", 0, [[305, 306], [305, 306]]),
    ("another-step-k0", 0, [[305, 307]]),
    ("another-step-k2", 2, [[305, 306]]),
    ("holds-the-catalog-pair-k0", 0, [[296, 297]]),
    ("holds-the-catalog-pair-k2", 2, [[296, 299]]),
    ("not-integers", 0, [["305", "306"]]),
    ("not-a-pair", 0, [[305, 306, 307]]),
    ("not-a-list", 0, {"305": 306}),
]


def _context_without_count_pairs():
    context = _context5(0, [])
    del context["countPairs"]
    return context


def _context_with_product_packets():
    context = _context5(0, [])
    context["productPackets"] = []
    return context


BIND_KEY_FAULTS = [
    ("four-keys", _context_without_count_pairs),
    ("six-keys-with-product-packets", _context_with_product_packets),
]


class TestRuleV24Context:
    """CONTRACT_286 section 3.1 (the v2.4 context), section 2 (the productPackets correction) and
    vector 25; the context's shape is operator-stated."""

    def test_rule_digest_is_held(self):
        """Section 3.1: RULE_V24_SHA256 is added and RULES_BY_SHA holds v2.2, v2.3 and v2.4."""
        reader = _reader()
        assert re.fullmatch(r"[0-9a-f]{64}", reader.RULE_V24_SHA256)
        assert reader.RULE_V24_SHA256 in reader.RULES_BY_SHA
        assert len(reader.RULES_BY_SHA) == 3

    @pytest.mark.parametrize("k, count_pairs, products", [
        (0, [], []),
        (0, [[305, 306]], []),
        (2, [[305, 308]], PRODUCTS),
    ], ids=["k0", "k0-count-pair", "k2-count-pair"])
    def test_context_v24_builds_the_classify_context(self, k, count_pairs, products):
        """Section 3.1 R1/R2/W and the operator-stated context_v24: the catalog pair
        (n, n + steps[1]) first, then countPairs; products from productPackets; newTests from
        newFiles' test paths; the five context members carried."""
        ctx = _reader().context_v24(_authority(k), _context5(k, count_pairs))
        assert set(ctx) == {
            "prevValidator", "prevTest", "newPacket", "products", "steps", "pairs", "newTests",
        }
        expected_pairs = [[BASELINE, BASELINE + 1 + k]] + count_pairs
        assert [[int(value) for value in pair] for pair in ctx["pairs"]] == expected_pairs
        assert list(ctx["products"]) == products
        assert sorted(ctx["newTests"]) == NEW_TESTS
        assert list(ctx["steps"]) == [1, 1 + k]
        assert ctx["newPacket"] == NEW_PACKET
        assert ctx["prevValidator"] == PREV_VALIDATOR
        assert ctx["prevTest"] == PREV_TEST

    def test_context_v24_keeps_product_packets_key_order(self):
        """Section 3.1 R1 (F3: the product ids in the key order of productPackets) and section 2
        (the product ids come from the authority's own productPackets)."""
        authority = _authority(2, ["SYN-BETA-002", "SYN-ALPHA-001"])
        ctx = _reader().context_v24(authority, _context5(2, []))
        assert list(ctx["products"]) == ["SYN-BETA-002", "SYN-ALPHA-001"]

    @pytest.mark.parametrize(
        "k, count_pairs",
        [case[1:] for case in BIND_ACCEPTED],
        ids=[case[0] for case in BIND_ACCEPTED],
    )
    def test_well_formed_count_pairs_bind(self, k, count_pairs):
        """Section 3.1, the v2.4 context: distinct integer pairs, each with b - a == steps[1],
        none the catalog pair, bind with no fault."""
        assert _bind(k, count_pairs) is None

    @pytest.mark.parametrize(
        "k, count_pairs",
        [case[1:] for case in BIND_COUNT_PAIRS_FAULTS],
        ids=[case[0] for case in BIND_COUNT_PAIRS_FAULTS],
    )
    def test_count_pairs_fault_is_a_binding_fault(self, k, count_pairs):
        """Vector 25 (section 3.1): a countPairs that is not a list of distinct integer pairs, that
        moves by another step, or that holds the catalog pair is a class A binding fault naming
        countPairs."""
        fault = _bind(k, count_pairs)
        assert isinstance(fault, str) and fault
        assert "countPairs" in fault

    @pytest.mark.parametrize(
        "make_context",
        [case[1] for case in BIND_KEY_FAULTS],
        ids=[case[0] for case in BIND_KEY_FAULTS],
    )
    def test_context_key_set_is_five_for_v24(self, make_context):
        """Section 3.1 (the context's keys against its rule's set, five for v2.4) and section 2
        (the context gains only countPairs, not productPackets): a binding fault."""
        assert _bind(0, context=make_context()) is not None


# ---------------------------------------------------------------------------------------------
# The ledger hunk side record (sections 3.6 and 4.3; vectors 28-35).
# ---------------------------------------------------------------------------------------------

LEDGER_PATH = "architecture/chain-checkpoint/record.json"
SIDE_PATH = "architecture/chain-checkpoint/ledger-hunks/286.json"
BASE_RAW = (
    b'{\n "layers": [\n  {"slot": 280},\n  {"slot": 281}\n ],\n "schemaVersion": "v1"\n}\n'
)
NEW_RAW = (
    b'{\n "checkpointSlot": 286,\n "layers": [\n  {"slot": 280},\n  {"slot": 281},\n'
    b'  {"slot": 282}\n ],\n "schemaVersion": "v1"\n}\n'
)
OTHER_BASE_RAW = b'{\n "layers": [],\n "schemaVersion": "v0"\n}\n'


def _encode(side):
    return json.dumps(side, indent=1, sort_keys=True).encode("utf-8") + b"\n"


def _side_args(side=None):
    """A consistent call: the side record from ledger_hunks, its digest named in newFiles and in
    the entry's reverseHunksRecord, the entry's before and after digests equal to the side's."""
    if side is None:
        side = _writer().ledger_hunks(BASE_RAW, NEW_RAW, AUTHORITY_PATH, 286)
    raw = _encode(side)
    digest = _sha(raw)
    entry = {
        "beforeSha256": side["beforeSha256"],
        "afterSha256": side["afterSha256"],
        "reverseHunksRecord": {"path": SIDE_PATH, "sha256": digest},
    }
    return {"entry": entry, "side_raw": raw, "named": digest, "authority": AUTHORITY_PATH,
            "live": NEW_RAW}


def _check(args):
    return _writer().check_ledger_hunks(
        args["entry"], args["side_raw"], args["named"], args["authority"], args["live"]
    )


def _side_of(args):
    return json.loads(args["side_raw"].decode("utf-8"))


def _with_side_raw(args, raw):
    """Replace the side record's bytes and keep the named digest and the entry's reference equal."""
    args["side_raw"] = raw
    args["named"] = _sha(raw)
    args["entry"]["reverseHunksRecord"]["sha256"] = args["named"]
    return args


def _f_missing(args):
    args["side_raw"] = None
    return args


def _f_unnamed(args):
    args["named"] = None
    return args


def _f_digest(args):
    args["named"] = "f" * 64
    args["entry"]["reverseHunksRecord"]["sha256"] = "f" * 64
    return args


def _f_extra_member(args):
    side = _side_of(args)
    side["extra"] = 1
    return _with_side_raw(args, _encode(side))


def _f_missing_member(args):
    side = _side_of(args)
    del side["reverseHunks"]
    return _with_side_raw(args, _encode(side))


def _f_hunks_not_list(args):
    side = _side_of(args)
    side["reverseHunks"] = {}
    return _with_side_raw(args, _encode(side))


def _f_not_json(args):
    return _with_side_raw(args, b"not json\n")


def _f_not_object(args):
    return _with_side_raw(args, b"[]\n")


def _f_other_authority(args):
    side = _side_of(args)
    side["authorityPath"] = "architecture/authority-map-authority.json"
    return _with_side_raw(args, _encode(side))


def _f_entry_extra_key(args):
    args["entry"]["reverseHunks"] = []
    return args


def _f_entry_missing_key(args):
    del args["entry"]["afterSha256"]
    return args


def _f_entry_inline_hunks(args):
    del args["entry"]["reverseHunksRecord"]
    args["entry"]["reverseHunks"] = []
    return args


def _f_reference_extra_key(args):
    args["entry"]["reverseHunksRecord"]["size"] = 1
    return args


def _f_reference_missing_key(args):
    del args["entry"]["reverseHunksRecord"]["sha256"]
    return args


def _f_side_path(args):
    side = _side_of(args)
    side["path"] = "architecture/chain-checkpoint/vectors.json"
    return _with_side_raw(args, _encode(side))


def _f_entry_before(args):
    args["entry"]["beforeSha256"] = "0" * 64
    return args


def _f_entry_after(args):
    args["entry"]["afterSha256"] = "0" * 64
    return args


def _f_entry_reference(args):
    args["entry"]["reverseHunksRecord"]["sha256"] = "e" * 64
    return args


SIDE_FAULTS = [
    ("v28-missing", "missing", _f_missing),
    ("v29-not-named", "named", _f_unnamed),
    ("v30-digest-differs", "digest", _f_digest),
    ("v31-extra-member", "malformed", _f_extra_member),
    ("v31-missing-member", "malformed", _f_missing_member),
    ("v31-hunks-not-a-list", "malformed", _f_hunks_not_list),
    ("v31-not-json", "malformed", _f_not_json),
    ("v31-not-an-object", "malformed", _f_not_object),
    ("v32-another-authority", "authority", _f_other_authority),
    ("v33-entry-extra-key", "key", _f_entry_extra_key),
    ("v33-entry-missing-key", "key", _f_entry_missing_key),
    ("v33-entry-inline-hunks", "key", _f_entry_inline_hunks),
    ("v33-reference-extra-key", "key", _f_reference_extra_key),
    ("v33-reference-missing-key", "key", _f_reference_missing_key),
    ("v34-side-path-differs", "differ", _f_side_path),
    ("v34-before-differs", "differ", _f_entry_before),
    ("v34-after-differs", "differ", _f_entry_after),
    ("v34-entry-reference-differs", "differ", _f_entry_reference),
]


class TestLedgerHunkSideRecord:
    """CONTRACT_286 sections 3.6 and 4.3 (Q-286-1 (a), MP049-C1-9) and vectors 28-35; the
    writer's functions and members are operator-stated."""

    def test_closed_member_sets(self):
        """Section 4.3: the side record is closed {authorityPath, path, beforeSha256, afterSha256,
        reverseHunks}; the record.json entry has exactly {beforeSha256, afterSha256,
        reverseHunksRecord}."""
        writer = _writer()
        assert set(writer.LEDGER_HUNK_MEMBERS) == {
            "authorityPath", "path", "beforeSha256", "afterSha256", "reverseHunks",
        }
        assert len(list(writer.LEDGER_HUNK_MEMBERS)) == 5
        assert set(writer.ENTRY_KEYS) == {"beforeSha256", "afterSha256", "reverseHunksRecord"}
        assert len(list(writer.ENTRY_KEYS)) == 3

    def test_built_side_record_passes_with_the_three_key_entry(self):
        """Section 4.3 (the side record, the entry, the equality checks): a side record built by
        ledger_hunks from a base and a new record names record.json, the authority and both
        digests, and passes check_ledger_hunks with a three-key entry."""
        side = _writer().ledger_hunks(BASE_RAW, NEW_RAW, AUTHORITY_PATH, 286)
        assert set(side) == {"authorityPath", "path", "beforeSha256", "afterSha256", "reverseHunks"}
        assert side["authorityPath"] == AUTHORITY_PATH
        assert side["path"] == LEDGER_PATH
        assert side["beforeSha256"] == _sha(BASE_RAW)
        assert side["afterSha256"] == _sha(NEW_RAW)
        assert isinstance(side["reverseHunks"], list) and side["reverseHunks"]
        args = _side_args(side)
        assert set(args["entry"]) == {"beforeSha256", "afterSha256", "reverseHunksRecord"}
        assert _check(args) is None

    @pytest.mark.parametrize(
        "keyword, fault_of",
        [case[1:] for case in SIDE_FAULTS],
        ids=[case[0] for case in SIDE_FAULTS],
    )
    def test_side_record_fault_is_refused(self, keyword, fault_of):
        """Vectors 28-34 (section 4.3, C2): missing; not named in newFiles; digest differs;
        malformed; another authorityPath; the entry's key set; the side record's path,
        beforeSha256 or afterSha256, or the entry's reference, differs. Each is refused with the
        vector's detail."""
        fault = _check(fault_of(_side_args()))
        assert isinstance(fault, str) and fault
        assert keyword in fault.lower()

    def test_hunks_not_reproducing_the_base_are_refused(self):
        """Vector 35 (section 4.3): hunks that apply to the live record but do not reproduce the
        base record byte-exactly are refused ("does not reproduce")."""
        side = _writer().ledger_hunks(OTHER_BASE_RAW, NEW_RAW, AUTHORITY_PATH, 286)
        side["beforeSha256"] = _sha(BASE_RAW)
        fault = _check(_side_args(side))
        assert isinstance(fault, str) and fault
        assert "reproduce" in fault.lower()


# ---------------------------------------------------------------------------------------------
# MET-PERF-048's provisions (section 3.9, P-048-1..4, Q-C286-1 T1; vectors 36-38).
# ---------------------------------------------------------------------------------------------

SIGNAL_FIELDS = {
    "ledgerSha256": "a" * 64,
    "g1ModuleSha256": "b" * 64,
    "head": "c" * 40,
    "bundleId": "bundle-v8",
}
G1_MODULE_NAME = "chain_checkpoint_g1.py"


def _head_of(*_args, **_kwargs):
    return "c" * 40


def _signal_layout(tmp_path):
    """A synthetic checkout holding a placeholder G1 module, and a HOME directory."""
    root = tmp_path / "checkout"
    (root / "ci").mkdir(parents=True)
    (root / "ci" / G1_MODULE_NAME).write_text("# a synthetic placeholder\n", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    return root, home, home / _reader().SIGNAL_RELATIVE


def _write_signal(path, raw=None, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(SIGNAL_FIELDS).encode("utf-8") if raw is None else raw)
    os.chmod(path, mode)


def _s_symlink(signal, tmp_path):
    target = tmp_path / "elsewhere.json"
    _write_signal(target)
    signal.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, signal)


def _s_group_write(signal, tmp_path):
    _write_signal(signal, mode=0o664)


def _s_world_write(signal, tmp_path):
    _write_signal(signal, mode=0o646)


def _s_oversize(signal, tmp_path):
    _write_signal(signal, raw=b"{" + b" " * 4095 + b"}")


def _s_not_root_owned(signal, tmp_path):
    _write_signal(signal)


def _s_hard_link(signal, tmp_path):
    _write_signal(signal)
    os.link(signal, tmp_path / "second-name.json")


def _s_directory(signal, tmp_path):
    signal.mkdir(parents=True)


SIGNAL_REFUSALS = [
    ("a-link", _s_symlink),
    ("group-write-bit", _s_group_write),
    ("world-write-bit", _s_world_write),
    ("over-4096-bytes", _s_oversize),
    ("not-owned-by-uid-0", _s_not_root_owned),
    ("nlink-2", _s_hard_link),
    ("not-a-regular-file", _s_directory),
]


def _p_file(signal, tmp_path):
    _write_signal(signal)


def _p_empty(signal, tmp_path):
    _write_signal(signal, raw=b"")


def _p_dangling_link(signal, tmp_path):
    signal.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(tmp_path / "no-such-target.json", signal)


SIGNAL_PRESENT_FORMS = [
    ("regular-file", _p_file),
    ("empty-file", _p_empty),
    ("link-to-a-file", _s_symlink),
    ("dangling-link", _p_dangling_link),
    ("group-writable-file", _s_group_write),
]


class TestMetPerf048Provisions:
    """CONTRACT_286 section 3.9 (P-048-1..4; Q-C286-1 T1 rules 1-4; MP049-C1-14), the README's
    mode-of-record paragraph and vectors 36-38; the functions and constants are operator-stated."""

    def test_signal_constants(self):
        """README (the mode of record) and section 3.9 (T1 rules 1 and 2): the HOME-relative path
        is .planeon/chain-checkpoint-g1-signal.json, stated in the README, and the file holds at
        most 4,096 bytes."""
        reader = _reader()
        relative = Path(reader.SIGNAL_RELATIVE).as_posix()
        assert relative == ".planeon/chain-checkpoint-g1-signal.json"
        assert "$HOME/" + relative in README_PATH.read_text(encoding="utf-8")
        assert reader.SIGNAL_MAX == 4096

    @pytest.mark.parametrize(
        "make_signal",
        [case[1] for case in SIGNAL_REFUSALS],
        ids=[case[0] for case in SIGNAL_REFUSALS],
    )
    def test_signal_file_failing_a_file_rule_is_refused(self, tmp_path, make_signal):
        """Vector 37 (section 3.9, T1 rule 2): a link, a group or world write bit, over 4,096
        bytes, an owner other than uid 0 (a file under tmp_path is not root-owned), nlink other
        than 1 or a non-regular file gives no fields and names the failed check."""
        root, home, signal = _signal_layout(tmp_path)
        make_signal(signal, tmp_path)
        fields, check = _reader().signal_check(root, str(home), _head_of)
        assert fields is None
        assert check

    @pytest.mark.parametrize("home_value", ["unset", "empty", "no-file"])
    def test_absent_signal_gives_no_fields_and_no_check(self, tmp_path, home_value):
        """Vector 36 and section 3.9 (T1 rule 4): an unset or empty HOME is an absent file; an
        absent file is shadow with no record, so no fields and no failed check."""
        root, home, signal = _signal_layout(tmp_path)
        assert not os.path.lexists(signal)
        value = {"unset": None, "empty": "", "no-file": str(home)}[home_value]
        fields, check = _reader().signal_check(root, value, _head_of)
        assert fields is None
        assert check is None

    @pytest.mark.parametrize(
        "make_signal",
        [case[1] for case in SIGNAL_PRESENT_FORMS],
        ids=[case[0] for case in SIGNAL_PRESENT_FORMS],
    )
    def test_signal_present_in_any_form(self, tmp_path, make_signal):
        """Vector 38 (section 3.9, P-048-4, condition (i)): the writer sees the signal file as
        present in any form."""
        _root, home, signal = _signal_layout(tmp_path)
        make_signal(signal, tmp_path)
        assert _writer().signal_present(str(home)) is True

    def test_signal_absent_is_not_present(self, tmp_path):
        """Vector 38 (section 3.9, P-048-4): with no file at the path the writer sees none."""
        _root, home, signal = _signal_layout(tmp_path)
        assert not os.path.lexists(signal)
        assert _writer().signal_present(str(home)) is False

    @pytest.mark.parametrize("workers", [8, 10, 12])
    def test_stated_differences_name_the_worker_count(self, workers):
        """Section 3.6 (MP049-C1-7, STATED formatted from parameters.workers), section 3.10 item 4
        and the README's two stated differences: stated(workers) gives two differences naming
        that worker count and no other."""
        stated = _writer().stated(workers)
        assert len(stated) == 2
        assert all(isinstance(item, str) for item in stated)
        counts = re.findall(r"(\d+)[ -]workers?\b", " ".join(stated))
        assert counts
        assert set(counts) == {str(workers)}


# ---------------------------------------------------------------------------------------------
# The countEffect table (section 3.11; the README's table, pinned equal to COUNT_EFFECT).
# ---------------------------------------------------------------------------------------------

DASH = "—"
README_COUNT_EFFECT = {
    "input": ("A", "restart"),
    "stale": ("A", "restart"),
    "outcome": ("B", "restart"),
    "corrupt": ("C", "restart"),
    "over-budget": ("C", "restart"),
    "over-cap": ("C", "restart"),
    "fault": ("C", "restart"),
    "skipped": ("C", "neutral"),
    "demoted": (DASH, "neutral"),
    "demoted-outcome-explained": (DASH, "pending isolation"),
    "agree": (DASH, "count"),
}


def _readme_count_effect_rows():
    lines = README_PATH.read_text(encoding="utf-8").splitlines()
    header = "| kind | class | countEffect | cause |"
    assert lines.count(header) == 1
    rows = {}
    for line in lines[lines.index(header) + 2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert cells[0] not in rows
        rows[cells[0]] = (cells[1], cells[2])
    return rows


def _count_effect_of(value):
    klass, effect = tuple(value)
    return (DASH if klass is None else klass, effect)


class TestCountEffectTable:
    """CONTRACT_286 section 3.11 (the demotion rows, MP049-C1-16), section 3.7 and C9; the
    README's countEffect table and the operator-stated COUNT_EFFECT."""

    def test_readme_rows(self):
        """README countEffect table: every existing row kept, with the demoted and
        demoted-outcome-explained rows of section 3.11 added."""
        assert _readme_count_effect_rows() == README_COUNT_EFFECT

    def test_count_effect_equals_the_readme_rows(self):
        """README ("COUNT_EFFECT holds the disagreement kinds"; agree is not among them) and
        section 3.7: the README's rows, agree aside, equal COUNT_EFFECT."""
        rows = _readme_count_effect_rows()
        rows.pop("agree")
        table = _reader().COUNT_EFFECT
        assert "agree" not in table
        assert {kind: _count_effect_of(value) for kind, value in table.items()} == rows

    def test_demotion_rows(self):
        """Section 3.11: demoted is neutral; demoted-outcome-explained is pending isolation."""
        table = _reader().COUNT_EFFECT
        assert _count_effect_of(table["demoted"]) == (DASH, "neutral")
        assert _count_effect_of(table["demoted-outcome-explained"]) == (DASH, "pending isolation")


# ---------------------------------------------------------------------------------------------
# Identity model v4, clause (xi) (sections 14 and 15).
# ---------------------------------------------------------------------------------------------

READER_CALL = "outcome = authority_map.check(regular_bytes, registry)"
LIFTED_CALL = "outcome = authority_map.check(reviewed_bytes, registry)"
NO_READER = "outcome = authority_map.load(registry)"
RETURN = "return outcome"
AUDIT_PLAIN = ("return authority_map.load(registry)",)
AUDIT_READER = ("return authority_map.check(regular_bytes, registry)",)
AUDIT_LIFTED = ("return authority_map.check(reviewed_bytes, registry)",)


def _xi_source(replay, audit=AUDIT_PLAIN):
    """A synthetic module: an optional top-level def _replay and a def _audit beside it."""
    lines = ["from scripts import authority_map", "", ""]
    if replay is not None:
        lines.append("def _replay(regular_bytes, reviewed_bytes, registry):")
        lines.extend("    " + line for line in replay)
        lines.extend(["", ""])
    lines.append("def _audit(regular_bytes, reviewed_bytes, registry):")
    lines.extend("    " + line for line in audit)
    return "\n".join(lines) + "\n"


def _xi(previous, current):
    return _identity().check_xi(ast.parse(previous), ast.parse(current))


XI_ZERO = [
    ("no-reader-no-replay", _xi_source(None), _xi_source(None)),
    ("unchanged-replay-without-reader", _xi_source([NO_READER, RETURN]),
     _xi_source([NO_READER, RETURN])),
]

XI_REFUSED = [
    ("reader-present-not-lifted", _xi_source([READER_CALL, RETURN]),
     _xi_source([READER_CALL, RETURN])),
    ("the-reverse", _xi_source([LIFTED_CALL, RETURN]), _xi_source([READER_CALL, RETURN])),
    ("second-occurrence-both-lifted", _xi_source([READER_CALL, READER_CALL, RETURN]),
     _xi_source([LIFTED_CALL, LIFTED_CALL, RETURN])),
    ("second-occurrence-one-lifted", _xi_source([READER_CALL, READER_CALL, RETURN]),
     _xi_source([LIFTED_CALL, READER_CALL, RETURN])),
    ("second-occurrence-added", _xi_source([READER_CALL, RETURN]),
     _xi_source([LIFTED_CALL, LIFTED_CALL, RETURN])),
    ("another-callee-attribute",
     _xi_source(["outcome = authority_map.verify(regular_bytes, registry)", RETURN]),
     _xi_source(["outcome = authority_map.verify(reviewed_bytes, registry)", RETURN])),
    ("another-callee-module", _xi_source([READER_CALL, RETURN]),
     _xi_source(["outcome = other_model.check(reviewed_bytes, registry)", RETURN])),
]


# A rename outside def _replay is not check_xi's to refuse: check_xi scopes def _replay (the operator
# statement), and v4's full check refuses the outside rename through its v3 delegation (CONTRACT_286
# section 15, C-I3; C-I4's full-check negative "rename outside _replay"). check_xi gives the _replay count.
# (Monitor correction MON-286-C3-SLIP, non-author.)
XI_OUTSIDE = [
    ("rename-outside-replay", _xi_source([NO_READER, RETURN], AUDIT_READER),
     _xi_source([NO_READER, RETURN], AUDIT_LIFTED), 0),
    ("rename-outside-replay-beside-the-lift", _xi_source([READER_CALL, RETURN], AUDIT_READER),
     _xi_source([LIFTED_CALL, RETURN], AUDIT_LIFTED), 1),
]


class TestIdentityClauseXi:
    """CONTRACT_286 section 15 (identity model v4, MON-286-IDENTITY-V4) and section 14 (form (xi):
    one era-model replay reader lift in def _replay, required exactly when the old head holds that
    reader); check_xi's shape is operator-stated."""

    def test_reader_lift_gives_one(self):
        """Section 15, clause (xi): <m>.check(regular_bytes, X) lifted to
        <m>.check(reviewed_bytes, X) in def _replay gives 1."""
        previous = _xi_source([READER_CALL, RETURN])
        current = _xi_source([LIFTED_CALL, RETURN])
        assert _xi(previous, current) == 1

    @pytest.mark.parametrize(
        "previous, current",
        [case[1:] for case in XI_ZERO],
        ids=[case[0] for case in XI_ZERO],
    )
    def test_no_reader_gives_zero(self, previous, current):
        """Section 15, clause (xi) (at the base v4 equals v3 plus xi 0): no reader and an
        unchanged _replay give 0."""
        assert _xi(previous, current) == 0

    @pytest.mark.parametrize(
        "previous, current",
        [case[1:] for case in XI_REFUSED],
        ids=[case[0] for case in XI_REFUSED],
    )
    def test_unlawful_step_raises_identity_step(self, previous, current):
        """Section 15, clause (xi) and section 14 (exactly one lift, required when the old head
        holds the reader): a reader present and not lifted, the reverse, a second occurrence, the
        another callee name each raise the identity step ValueError (a rename outside _replay:
        see XI_OUTSIDE)."""
        with pytest.raises(ValueError) as raised:
            _xi(previous, current)
        assert str(raised.value).startswith("identity step:")

    @pytest.mark.parametrize(
        "previous, current, count",
        [case[1:] for case in XI_OUTSIDE],
        ids=[case[0] for case in XI_OUTSIDE],
    )
    def test_rename_outside_replay_is_not_check_xis(self, previous, current, count):
        """Section 15, C-I3: check_xi scopes def _replay and gives its count; the rename outside
        _replay is refused by v4's v3 delegation (C-I4's full-check negative), not by check_xi."""
        assert _xi(previous, current) == count
