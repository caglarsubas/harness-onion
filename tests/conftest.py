"""MET-PERF-040 (owner decision Q-PERF40-1 (a), 2026-10-16): test-local exact sharing of history projections.

Within one test, every loaded history layer's historical_bytes is memoised by its exact arguments (each one a str or
bytes value, compared by type and equality), so a repeated identical projection is computed once per test. Every
distinct input, each mutation included, still reaches the real projection, and a refusal is never memoised. The
validators' freshness rule is unchanged: each one still reads its authority fresh on every route (Q-PERF40-2 (a)).

The sharing is bound to one test:
- each wrapper shares only while its own test is active; outside it, a wrapper is inert and calls the real function;
- after the test, every wrapper is replaced by its real function in each module the test wrapped and in every validate_*
  module first imported during the test (which may have bound a wrapper at import);
- a function that is already a wrapper is never wrapped again.

Tests whose purpose is that freshness, or the identity of these functions, or a fully fresh closing validation, are
never shared. They are named in NEVER_SHARED by function name, so a later layer's tests of the same name are covered too.
This autouse fixture is set up before monkeypatch, so its teardown runs after monkeypatch's.
"""
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
})
EXACT_TYPES = (str, bytes)
_ACTIVE = {"memo": None}          # the current test's memo while a shared test runs, else None
_MARK = "_met_perf_040_exact_share"


def _is_wrapper(value):
    return callable(value) and getattr(value, _MARK, False) is True


def _shared(real):
    def historical_bytes(*args, **kwargs):
        memo = _ACTIVE["memo"]
        if memo is None or kwargs or not args or any(type(arg) not in EXACT_TYPES for arg in args):
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
    before = set(sys.modules)
    wrapped = []
    for _, module in _layers():
        real = vars(module).get("historical_bytes")
        if callable(real) and not _is_wrapper(real):
            module.historical_bytes = _shared(real)
            wrapped.append(module)
    _ACTIVE["memo"] = {}
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
