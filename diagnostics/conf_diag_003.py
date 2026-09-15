"""CONF-DIAG-003 observer. No acceptance, source edits or test substitutions."""
import cProfile
import faulthandler
import hashlib
import json
from pathlib import Path
import sys
import sysconfig
import time
import unittest

EXPECTED_IDS = '03ab92921cd44154d4658e7e0205ac6134a66cf905ab0baf360f52dc01369a94'
ROOT = Path.cwd()
STDLIB = Path(sysconfig.get_path('stdlib'))
TIMING_ONLY = {
    'test_supervisor.PerformanceArithmeticTests.test_fixed_three_sample_workload',
    'test_supervisor.PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception',
    'test_supervisor.PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it',
}


def emit(event, **fields):
    print(json.dumps(dict(event=event, evidenceClass='WORKLOAD_DIAGNOSTIC_ONLY',
                          **fields), sort_keys=True, allow_nan=False), flush=True)


def label(code):
    if isinstance(code, str):
        return ['BUILTIN', 0, code[:160]]
    path = Path(code.co_filename)
    for root, tag in ((ROOT, 'SUBJECT'), (STDLIB, 'STDLIB')):
        try:
            return [tag + '/' + str(path.relative_to(root)), code.co_firstlineno, code.co_name]
        except ValueError:
            pass
    return ['OTHER', code.co_firstlineno, code.co_name]


class Result(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        self.case_id = test.id()
        emit('case-start', testId=self.case_id)
        faulthandler.dump_traceback_later(30, repeat=True, exit=False)
        self.wall = time.perf_counter()
        self.cpu = time.thread_time()
        self.process_cpu = time.process_time()
        self.profiler = None
        if self.case_id not in TIMING_ONLY:
            if sys.getprofile() is not None:
                raise RuntimeError('unexpected ambient profiler')
            self.profiler = cProfile.Profile()
            self.profiler.enable()

    def stopTest(self, test):
        cpu = time.thread_time() - self.cpu
        wall = time.perf_counter() - self.wall
        process_cpu = time.process_time() - self.process_cpu
        intact = sys.getprofile() is self.profiler if self.profiler else None
        if self.profiler:
            self.profiler.disable()
        rows = self.profiler.getstats() if self.profiler else []
        def top(key):
            return [dict(function=label(e.code), calls=e.callcount,
                         recursiveCalls=e.reccallcount, selfElapsed=e.inlinetime,
                         cumulativeElapsed=e.totaltime)
                    for e in sorted(rows, key=key, reverse=True)[:20]]
        emit('case-finish', testId=self.case_id, wallSeconds=wall,
             threadCpuSeconds=cpu, processCpuSeconds=process_cpu,
             profilerActiveAtFinish=intact, functionCount=len(rows),
             topSelf=top(lambda e: e.inlinetime),
             topCumulative=top(lambda e: e.totaltime))
        faulthandler.cancel_dump_traceback_later()
        super().stopTest(test)


def identities(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from identities(item)
        else:
            yield item.id()


def main():
    faulthandler.dump_traceback_later(30, repeat=True, exit=False)
    try:
        wall, cpu = time.perf_counter(), time.process_time()
        suite = unittest.defaultTestLoader.discover('tests/live_backend', 'test_*.py')
        ids = sorted(identities(suite))
        digest = hashlib.sha256(json.dumps(ids, separators=(',', ':')).encode()).hexdigest()
        if len(ids) != 1397 or len(set(ids)) != 1397 or digest != EXPECTED_IDS:
            raise ValueError('exact whole-backend inventory required')
        emit('discovered', cases=len(ids), idsSha256=digest,
             wallSeconds=time.perf_counter()-wall, processCpuSeconds=time.process_time()-cpu)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        emit('finished', cases=result.testsRun, failures=len(result.failures),
             errors=len(result.errors), skips=len(result.skipped))
        return 0 if result.wasSuccessful() and not result.skipped and result.testsRun == 1397 else 1
    finally:
        faulthandler.cancel_dump_traceback_later()


if __name__ == '__main__':
    raise SystemExit(main())
