# Read-only current-thread call counters; never changes product decisions.
import hashlib
import json
from pathlib import Path
import sys
import time
import unittest as u

IDS = '9e68c454cb4a1c3aaf5da3c71cae15d98c4f1875638b639a766a0f2de16f5d01'
ROOT = str(Path.cwd())
TARGETS = [('_KernelNativeReads._tick',329),('_KernelRootViews._reader_mounts',718),('_KernelPolicyView._reader_epoch',1286),('_Files.check',2310),('_ServerQualificationBinding.check',2534),('_KernelSelfInspection.__init__',2584),('_KernelSelfInspection._tick',2638),('_KernelSelfInspection._reader_tick',2656),('_KernelQualification.__init__',3045),('_KernelQualification.check_self',3099)]
CLASSES = {'KernelQualificationFactoryTests','NativeServerFactoryTests','NativeServerHTTPFactoryTests'}
KEYS = {(ROOT+'/src/harness_conformance/live_proxy_server.py',q,n):i for i,(q,n) in enumerate(TARGETS)}
W,C = time.perf_counter,time.thread_time
H = None

def emit(event,**fields):
    print(json.dumps(dict(event=event,evidenceClass='WORKLOAD_DIAGNOSTIC_ONLY',**fields),sort_keys=True,allow_nan=False),flush=True)

def busy():
    m=sys.monitoring
    return sys.gettrace() is not None or any(m.get_tool(i) is not None or m.get_events(i) for i in range(6))

def close():
    global H
    if H is not None and sys.getprofile() is H:
        sys.setprofile(None)
    H=None

class Result(u.TextTestResult):
    def startTest(self,test):
        global H
        if sys.getprofile() is not None or busy():
            raise RuntimeError('ambient')
        super().startTest(test)
        self.ident=test.id()
        self.sampled=self.ident.split('.')[1] in CLASSES
        self.start,self.cpu=W(),C()
        self.last=self.start
        self.calls=[0]*len(TARGETS)
        self.returns=[0]*len(TARGETS)
        self.events=0
        emit('case-start',testId=self.ident,sampled=self.sampled)
        if self.sampled:
            H=self.hook
            try:
                sys.setprofile(H)
            except BaseException:
                close()
                raise

    def hook(self,frame,event,arg):
        if event not in ('call','return'):
            return
        code=frame.f_code
        index=KEYS.get((code.co_filename,code.co_qualname,code.co_firstlineno))
        if index is not None:
            (self.calls if event=='call' else self.returns)[index]+=1
        self.events+=1
        if self.events%1024==0:
            now=W()
            if now-self.last>=2:
                self.last=now
                emit('progress',testId=self.ident,wall=now-self.start,threadCpu=C()-self.cpu,events=self.events,callEvents=self.calls,returnEvents=self.returns,hookOwned=sys.getprofile() is H)

    def stopTest(self,test):
        owned=sys.getprofile() is H if self.sampled else sys.getprofile() is None
        close()
        valid=owned and sys.getprofile() is None and not busy()
        emit('case-finish',testId=test.id(),wall=W()-self.start,threadCpu=C()-self.cpu,sampled=self.sampled,observationValid=valid,callEvents=self.calls if self.sampled else None,returnEvents=self.returns if self.sampled else None)
        if not valid:
            raise RuntimeError('observer interference')
        super().stopTest(test)

def identities(suite):
    for item in suite:
        if isinstance(item,u.TestSuite):
            yield from identities(item)
        else:
            yield item.id()

def main():
    if sys.implementation.name!='cpython' or sys.version_info[:3]!=(3,12,14):
        raise RuntimeError('interpreter')
    if sys.getprofile() is not None or busy():
        raise RuntimeError('ambient')
    try:
        suite=u.defaultTestLoader.discover('tests/live_backend','test_*.py')
        ids=sorted(identities(suite))
        digest=hashlib.sha256(json.dumps(ids,separators=(',',':')).encode()).hexdigest()
        sampled=[x for x in ids if x.split('.')[1] in CLASSES]
        if len(ids)!=1447 or digest!=IDS or len(sampled)!=41:
            raise ValueError('inventory')
        emit('discovered',cases=len(ids),idsSha256=digest,sampledCases=len(sampled),targets=TARGETS)
        result=u.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
        emit('finished',cases=result.testsRun,failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped))
        return 0 if result.wasSuccessful() and not result.skipped and result.testsRun==1447 else 1
    finally:
        close()

if __name__=='__main__':
    raise SystemExit(main())
