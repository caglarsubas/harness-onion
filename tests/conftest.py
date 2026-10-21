"""MET-PERF-040 (owner decision Q-PERF40-1 (a), 2026-10-16): test-local exact sharing of history projections.

Within one test, every loaded history layer's historical_bytes is memoised by its exact arguments (each one a str or
bytes value, compared by type and equality), so a repeated identical projection is computed once per test. Every
distinct input, each mutation included, still reaches the real projection, and a refusal is never memoised. The
validators' freshness rule is unchanged: each one still reads its authority fresh on every route (Q-PERF40-2 (a)).

The sharing is bound to one test:
- each wrapper is created for one test and bound to that test's own memo; it shares only while that memo is the active
  one, and at any other time (another test, a never-shared test, outside tests) it calls the real function;
- after the test, every wrapper is replaced by its real function in each module the test wrapped and in every validate_*
  module first imported during the test (which may have bound a wrapper at import);
- a function that is already a wrapper is never wrapped again.

Tests whose purpose is that freshness, or the identity of these functions, or a fully fresh closing validation, are
never shared. They are named in NEVER_SHARED by function name, so a later layer's tests of the same name are covered too.
This autouse fixture is set up before monkeypatch, so its teardown runs after monkeypatch's.
MET-PERF-042 C1 (owner Q-CC-2 (a), 2026-10-21): test-side YAML parse sharing. Within one test module, the test module's
own safe_load binding (only when it is scripts.safe_yaml's safe_load) parses each distinct argument once: the argument
(str or bytes, compared by type and value) is the key, so every caller still reads its bytes and changed bytes get a real
parse; every call returns a deep copy of the stored parse; a refusal is never memoised; the binding is restored after
each test, and the parses are dropped when the next test module starts. No validator, scripts/ module, historical_*
function or refusal path is touched. It is never installed in a NEVER_SHARED test, nor in a test that the static rule
finds patching safe_load, ROOT or the tree. The rule (_patches) is decided from the AST of the test function and of each
same-module fixture it names, nested functions and lambdas included: the test is excluded if it mentions safe_load or ROOT
as a string, stores to or deletes an attribute named safe_load or ROOT, uses safe_load other than as the callee of a call,
or calls setattr, delattr, setitem, delitem, chdir, syspath_prepend or setenv with Path, os, io, builtins, pathlib,
shutil or open among its arguments (by name, or as a dotted part of a string). A test whose source cannot be found is
excluded.
"""
import ast
import copy
import sys

import pytest

NEVER_SHARED = frozenset({
    "test_newest_authority_is_freshly_checked_on_every_route",
    "test_every_newer_authority_is_read_exactly_once_per_route",
    "test_history_routes_still_refuse_second_call_authority_drift",
    "test_each_projection_freshly_rechecks_complete_authority",
    "test_every_projection_rechecks_actual_authority_bytes",
    "test_schema_performance_authority_is_rechecked_through_every_history_route",
    "test_freshness_only_routes_read_full_authority_without_reparsing",
    "test_real_projection_refuses_authority_drift_even_with_warm_conversion",
    "test_warm_conversion_still_runs_fresh_interleaved_integrity",
    "test_warm_success_then_current_packet_map_drift_still_refuses",
    "test_each_protected_input_rechecked_not_cached",
    "test_every_input_pin_is_enforced",
    "test_performance_predecessor_and_exact_twenty_commands",
    "test_each_locked_input_is_checked_and_unknown_or_missing_files_refuse",
    "test_full_predecessor_suites_and_validators_remain_green",
    "test_identity_rule_holds_on_the_live_chain",
    "test_runtime_bindings_are_the_frozen_ones_around_a_fan_in_pass",
})
EXACT_TYPES = (str, bytes)
_ACTIVE = {"memo": None}          # the running shared test's memo, else None
_MARK = "_met_perf_040_exact_share"


def _is_wrapper(value):
    return callable(value) and getattr(value, _MARK, False) is True


def _shared(real, memo):
    def historical_bytes(*args, **kwargs):
        if _ACTIVE["memo"] is not memo or kwargs or not args or any(type(arg) not in EXACT_TYPES for arg in args):
            return real(*args, **kwargs)
        key = (real, tuple((type(arg), arg) for arg in args))
        if key not in memo:
            memo[key] = real(*args)
        return memo[key]

    historical_bytes.__wrapped__ = real
    setattr(historical_bytes, _MARK, True)
    return historical_bytes


def _layers():
    return [(name, module) for name, module in list(sys.modules.items())
            if module is not None and name.rpartition(".")[2].startswith("validate_")]


def _unwrap(value):
    while _is_wrapper(value):
        value = value.__wrapped__
    return value


@pytest.fixture(autouse=True)
def _exact_history_sharing(request):
    if getattr(request.node, "originalname", request.node.name) in NEVER_SHARED:
        yield
        return
    before, memo, wrapped = set(sys.modules), {}, []
    for _, module in _layers():
        real = vars(module).get("historical_bytes")
        if callable(real) and not _is_wrapper(real):
            module.historical_bytes = _shared(real, memo)
            wrapped.append(module)
    _ACTIVE["memo"] = memo
    try:
        yield
    finally:
        _ACTIVE["memo"] = None
        for module in wrapped:
            module.historical_bytes = _unwrap(vars(module).get("historical_bytes"))
        for name, module in _layers():
            if name not in before:
                for attribute, value in list(vars(module).items()):
                    if _is_wrapper(value):
                        setattr(module, attribute, _unwrap(value))


# MET-PERF-042 C1 (owner Q-CC-2 (a), 2026-10-21; see the module docstring): test-side YAML parse sharing.
_PARSE_MARK = "_met_perf_042_parse_share"
_PARSES = {"module": None, "memo": {}}   # the running test module's name and its parses, by exact argument
_PATCH_RULES = {}                        # (module file, class, test name) -> excluded, decided once from the AST
PATCH_NAMES = frozenset({"safe_load", "ROOT"})
TREE_NAMES = frozenset({"Path", "os", "io", "builtins", "pathlib", "shutil", "open"})
PATCH_CALLS = frozenset({"setattr", "delattr", "setitem", "delitem", "chdir", "syspath_prepend", "setenv"})


def _patches(function, helpers):
    """The static exclusion rule of the module docstring, over the test function and the same-module fixtures it names."""
    roots = [function] + [helpers[arg.arg] for arg in function.args.args if arg.arg in helpers]
    for root in roots:
        callees = {id(node.func) for node in ast.walk(root) if isinstance(node, ast.Call)}
        for node in ast.walk(root):
            if isinstance(node, ast.Constant) and type(node.value) is str and node.value in PATCH_NAMES:
                return True
            if isinstance(node, ast.Attribute) and node.attr in PATCH_NAMES and not isinstance(node.ctx, ast.Load):
                return True
            if isinstance(node, ast.Name) and node.id == "safe_load" and id(node) not in callees:
                return True
            callee = node.func if isinstance(node, ast.Call) else None
            name = callee.attr if isinstance(callee, ast.Attribute) else callee.id if isinstance(callee, ast.Name) else None
            if name in PATCH_CALLS:
                for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                    for part in ast.walk(argument):
                        if (isinstance(part, ast.Name) and part.id in TREE_NAMES) or (
                                isinstance(part, ast.Constant) and type(part.value) is str
                                and any(piece in TREE_NAMES for piece in part.value.split("."))):
                            return True
    return False


def _excluded(module, request):
    key = (getattr(module, "__file__", None), getattr(getattr(request, "cls", None), "__name__", None),
           getattr(request.node, "originalname", request.node.name))
    if key not in _PATCH_RULES:
        try:
            with open(key[0], "rb") as handle:
                tree = ast.parse(handle.read())
        except (OSError, TypeError, ValueError, SyntaxError):
            _PATCH_RULES[key] = True
        else:
            body = tree.body if key[1] is None else next(
                (node.body for node in tree.body if isinstance(node, ast.ClassDef) and node.name == key[1]), [])
            found = [node for node in body if isinstance(node, ast.FunctionDef) and node.name == key[2]]
            helpers = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
            _PATCH_RULES[key] = len(found) != 1 or _patches(found[0], helpers)
    return _PATCH_RULES[key]


def _parse_shared(real, memo):
    def safe_load(*args, **kwargs):
        if kwargs or len(args) != 1 or type(args[0]) not in EXACT_TYPES:
            return real(*args, **kwargs)
        key = (type(args[0]), args[0])
        if key not in memo:
            memo[key] = real(args[0])
        return copy.deepcopy(memo[key])

    safe_load.__wrapped__ = real
    setattr(safe_load, _PARSE_MARK, True)
    return safe_load


@pytest.fixture(autouse=True)
def _test_module_parse_sharing(request):
    module = getattr(request.node, "module", None)
    real = vars(module).get("safe_load") if module is not None else None
    source = sys.modules.get("scripts.safe_yaml")
    if (getattr(request.node, "originalname", request.node.name) in NEVER_SHARED or real is None
            or real is not getattr(source, "safe_load", None) or _excluded(module, request)):
        yield
        return
    if _PARSES["module"] != module.__name__:
        _PARSES["module"], _PARSES["memo"] = module.__name__, {}
    module.safe_load = _parse_shared(real, _PARSES["memo"])
    try:
        yield
    finally:
        if getattr(vars(module).get("safe_load"), _PARSE_MARK, False) is True:
            module.safe_load = real
