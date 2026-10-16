"""MET-PERF-040 (owner decision Q-PERF40-1 (a), 2026-10-16): test-local exact sharing of history projections.

Within one test, every loaded history layer's historical_bytes is memoised by its exact arguments (each one a str or
bytes value, compared by equality), so a repeated identical projection is computed once per test. Every distinct
input, each mutation included, still reaches the real projection, and a refusal is never memoised. The validators are
unchanged: each one still reads its authority fresh on every route (Q-PERF40-2 (a)).

Tests whose purpose is that freshness, or the identity of these functions, are never shared. They are named in
NEVER_SHARED by function name, so a later layer's tests of the same name are covered too. The real functions are
restored after each test, after monkeypatch's own teardown (this autouse fixture is set up first, so it is torn down
last).
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
    "test_full_predecessor_suites_and_validators_remain_green",
})
EXACT_TYPES = (str, bytes)


def _shared(real):
    seen = {}

    def historical_bytes(*args, **kwargs):
        if kwargs or not args or any(type(arg) not in EXACT_TYPES for arg in args):
            return real(*args, **kwargs)
        key = tuple((type(arg), arg) for arg in args)
        if key not in seen:
            seen[key] = real(*args)
        return seen[key]

    historical_bytes.__wrapped__ = real
    return historical_bytes


@pytest.fixture(autouse=True)
def _exact_history_sharing(request):
    if getattr(request.node, "originalname", request.node.name) in NEVER_SHARED:
        yield
        return
    restore = []
    for name, module in list(sys.modules.items()):
        if module is None or not name.rpartition(".")[2].startswith("validate_"):
            continue
        real = vars(module).get("historical_bytes")
        if callable(real):
            module.historical_bytes = _shared(real)
            restore.append((module, real))
    try:
        yield
    finally:
        for module, real in restore:
            module.historical_bytes = real
