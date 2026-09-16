import cProfile as c
import faulthandler as f
import hashlib
import json
from pathlib import Path
import sys
import sysconfig as sc
import time as t
import unittest as u

IDS_SHA = '03ab92921cd44154d4658e7e0205ac6134a66cf905ab0baf360f52dc01369a94'
ROOT = Path.cwd()
STDLIB = Path(sc.get_path('stdlib'))
TIMING_ONLY = {
    'test_supervisor.PerformanceArithmeticTests.test_fixed_three_sample_workload',
    'test_supervisor.PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception',
    'test_supervisor.PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it',
}


def emit(event, **kw):
    print(json.dumps(dict(event=event, evidenceClass='WORKLOAD_DIAGNOSTIC_ONLY',
                          **kw), sort_keys=True, allow_nan=False), flush=True)


def busy():
    m = sys.monitoring
    return any(m.get_tool(i) is not None or m.get_events(i) for i in range(6))


def profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 12, 14):
        raise RuntimeError('CPython 3.12.14')
    p = c.Profile()
    d = {'call':p._pystart_callback, 'return':p._pyreturn_callback,
         'c_call':p._ccall_callback, 'c_return':p._creturn_callback,
         'c_exception':p._creturn_callback}
    def hook(frame, event, arg):
        d[event](frame.f_code, frame.f_lasti, arg, sys.monitoring.MISSING)
    return p, hook


def clocks():
    return t.perf_counter(), t.thread_time(), t.process_time()


def label(c):
    if isinstance(c, str):
        return ['BUILTIN', 0, c[:160]]
    p = Path(c.co_filename)
    for root, tag in ((ROOT, 'SUBJECT'), (STDLIB, 'STDLIB')):
        try:
            return [tag + '/' + str(p.relative_to(root)), c.co_firstlineno, c.co_name]
        except ValueError:
            pass
    return ['OTHER', c.co_firstlineno, c.co_name]


class Result(u.TextTestResult):
    def close(self):
        if self.h is not None and sys.getprofile() is self.h:
            sys.setprofile(None)
        f.cancel_dump_traceback_later()

    def startTest(self, test):
        self.p = self.h = None
        if sys.getprofile() is not None or busy():
            raise RuntimeError('ambient profiler')
        super().startTest(test)
        emit('case-start', testId=test.id())
        self.begin = clocks()
        try:
            f.dump_traceback_later(30, repeat=True, exit=False)
            if test.id() not in TIMING_ONLY:
                self.p, self.h = profile()
                sys.setprofile(self.h)
        except BaseException:
            self.close()
            raise

    def stopTest(self, test):
        try:
            wall, cpu, proc = (a-b for a, b in zip(clocks(), self.begin))
            owned = sys.getprofile() is self.h if self.h else None
            self.close()
            valid = owned is not False and sys.getprofile() is None and not busy()
            rows = self.p.getstats() if self.p and valid else []
            def top(key):
                return [dict(function=label(e.code), calls=e.callcount,
                             recursiveCalls=e.reccallcount, selfElapsed=e.inlinetime,
                             cumulativeElapsed=e.totaltime)
                        for e in sorted(rows, key=key, reverse=True)[:20]]
            emit('case-finish', testId=test.id(), wallSeconds=wall,
                 threadCpuSeconds=cpu, processCpuSeconds=proc,
                 hookOwnedAtFinish=owned, observationValid=valid, functionCount=len(rows),
                 topSelf=top(lambda e: e.inlinetime), topCumulative=top(lambda e: e.totaltime))
            if not valid:
                raise RuntimeError('interference')
        finally:
            self.close()
        super().stopTest(test)


def identities(s):
    for x in s:
        if isinstance(x, u.TestSuite):
            yield from identities(x)
        else:
            yield x.id()


def main():
    f.dump_traceback_later(30, repeat=True, exit=False)
    try:
        wall, _, cpu = clocks()
        s = u.defaultTestLoader.discover('tests/live_backend', 'test_*.py')
        ids = sorted(identities(s))
        digest = hashlib.sha256(json.dumps(ids, separators=(',', ':')).encode()).hexdigest()
        if len(ids) != 1397 or digest != IDS_SHA:
            raise ValueError('exact inventory required')
        emit('discovered', cases=len(ids), idsSha256=digest,
             wallSeconds=t.perf_counter()-wall, processCpuSeconds=t.process_time()-cpu)
        r = u.TextTestRunner(verbosity=2, resultclass=Result).run(s)
        emit('finished', cases=r.testsRun, failures=len(r.failures),
             errors=len(r.errors), skips=len(r.skipped))
        return 0 if r.wasSuccessful() and not r.skipped and r.testsRun == 1397 else 1
    finally:
        f.cancel_dump_traceback_later()


if __name__ == '__main__':
    raise SystemExit(main())
