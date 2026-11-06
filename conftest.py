"""Source-only diagnostics and the chain checkpoint's shadow reader (MET-PERF-047): no selection, fixture or authority
changes; the reader only observes and records, never changes a session's outcome, and a missing or failing reader
prints one class-C line."""
from importlib.util import module_from_spec as _module_from_spec
from importlib.util import spec_from_file_location as _spec_from_file_location
from os import environ as _environ
from os import write as _write
from pathlib import Path as _Path
from time import monotonic as _monotonic

import pytest


def _load_diagnostics():
    # No sys.path edit, test-module import or mutable validator import. The
    # repository's exact source is separately pinned by packet acceptance.
    path = _Path(__file__).parent / "ci" / "pytest_diagnostics.py"
    spec = _spec_from_file_location("_planeon_met_perf_021_pytest_diagnostics", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("diagnostic module unavailable")
    module = _module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_DIAGNOSTICS = _load_diagnostics()
_STATE_KEY = "_planeon_met_perf_021_diagnostics"
_OUTERMOST = "PLANEON_PARALLEL_SUITE_SERIAL" not in _environ   # read once, before the parallel suite sets it
_READER = {}


def _checkpoint_line(text):
    try:
        _write(2, (text + "\n").encode())
    except Exception:
        pass


def _load_checkpoint_reader():
    # MET-PERF-047: loaded by path like the diagnostics, in the outermost session only; any failure is class C.
    path = _Path(__file__).parent / "ci" / "chain_checkpoint.py"
    spec = _spec_from_file_location("_planeon_met_perf_047_chain_checkpoint", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("chain checkpoint reader unavailable")
    module = _module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_CHECKPOINT, _CHECKPOINT_ERROR = None, None
if _OUTERMOST:
    try:
        _CHECKPOINT = _load_checkpoint_reader()
    except Exception as _exc:
        _CHECKPOINT_ERROR = _exc


def pytest_configure(config):
    manager = config.pluginmanager.getplugin("capturemanager")
    disable = manager.global_and_fixture_disabled if manager is not None else None
    write = _write

    def sink(data):
        if disable is None:
            raise RuntimeError("diagnostic capture boundary unavailable")
        # Pinned pytest 8.4.2 temporarily suspends BOTH global and fixture
        # capture here, restoring them in finally. FD2 is still the parent's
        # stderr pipe in nested pytest: this does not make nested output live.
        with disable():
            offset = 0
            while offset < len(data):
                amount = write(2, data[offset:])
                if type(amount) is not int or amount <= 0 or amount > len(data) - offset:
                    raise OSError("diagnostic sink unavailable")
                offset += amount
            return offset

    setattr(config, _STATE_KEY, _DIAGNOSTICS.Diagnostics(sink, _monotonic))


def _state(item):
    return getattr(item.config, _STATE_KEY)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    _state(item).start(item.nodeid, "setup")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    _state(item).start(item.nodeid, "call")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item):
    _state(item).start(item.nodeid, "teardown")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    # Outermost wrapper sees the finalized skip/xfail report without changing it.
    report = yield
    _state(item).end(item.nodeid, report.when, report.outcome, report.duration,
                     xfail=hasattr(report, "wasxfail"))
    return report


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    result = yield
    state = getattr(session.config, _STATE_KEY)
    session.exitstatus = state.finish(session.exitstatus)
    return result


def pytest_sessionstart(session):
    if not _OUTERMOST:
        return
    if _CHECKPOINT is None:
        if _CHECKPOINT_ERROR is not None:
            _checkpoint_line("chain-checkpoint shadow: class C, the reader did not load: %s" % type(_CHECKPOINT_ERROR).__name__)
        return
    try:
        reader = _CHECKPOINT.Reader()
        reader.start()
        _READER["reader"] = reader
    except Exception as exc:
        _checkpoint_line("chain-checkpoint shadow: class C, the reader raised at session start: %s" % type(exc).__name__)


def pytest_runtest_logreport(report):
    reader = _READER.get("reader")
    if reader is None:
        return
    try:
        reader.report(report.nodeid, report.when, report.outcome, report.duration)
    except Exception as exc:
        _READER.pop("reader", None)
        _checkpoint_line("chain-checkpoint shadow: class C, the reader raised on a report: %s" % type(exc).__name__)


def pytest_unconfigure(config):
    reader = _READER.pop("reader", None)
    if reader is None:
        return
    try:
        line, record = reader.finish()
        if line:
            _checkpoint_line(line)
            _checkpoint_line("chain-checkpoint shadow record: " + __import__("json").dumps(record, sort_keys=True))
    except Exception as exc:
        _checkpoint_line("chain-checkpoint shadow: class C, the reader raised at the end: %s" % type(exc).__name__)
