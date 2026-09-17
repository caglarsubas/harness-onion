"""External data-only design inventory; no repository imports or acceptance."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
META = ROOT.parent.parent / 'Harness-Engineering-met-enforce-001'
BASE = 'cdb71ae1f6d639cc9ccd78d9089203b08e5ee8d5'
TREE = '9e88deb2a95e75b9fe581dc3cca016fe6ec931fd'


def git(*args):
    return subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *args],
                          cwd=META, check=True, capture_output=True, timeout=30).stdout


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', BASE + '^{tree}').decode().strip() == TREE
assert git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE
assert not git('status', '--porcelain').strip()
inputs = [
    'AGENTS.md', 'architecture/repositories.yaml', 'architecture/taxonomy.yaml',
    'architecture/enforcement-integration-plan.json',
    'architecture/enforcement-integration-authority.json',
    'architecture/observation-enforcement-inputs/enforcement-matrix.json',
    'architecture/observation-enforcement-inputs/design-review.json',
    'docs/MASTER_DEVELOPMENT_PLAN.md',
    'docs/adr/0009-host-enforcement-ownership.md',
    'docs/alpha-2/ENFORCEMENT_INTEGRATION.md',
    'docs/alpha-2/ENFORCEMENT_FEASIBILITY.md',
    'docs/alpha-2/OBSERVATION_ENFORCEMENT_PUBLICATION.md',
    'docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md',
    'docs/alpha-2/OBSERVATION_ENFORCEMENT_DELTAS.md',
    'docs/alpha-2/PROXY_CONTRACT_READINESS.md',
    'docs/alpha-2/POLICY_OBSERVATION_READINESS.md',
    'docs/alpha-2/BROKER_HANDOFF_READINESS.md',
    'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
    'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md',
    'docs/repositories/10-mas-harness-operator.md',
    'task-packets/MET-ENFORCE-001.yaml', 'task-packets/CONF-FIX-009.yaml',
    'task-packets/CONF-FIX-010.yaml',
]
records = {}
for path in inputs:
    committed = git('show', BASE + ':' + path)
    assert (META / path).read_bytes() == committed, path
    records[path] = {'sha256': sha(committed), 'bytes': len(committed)}
closeout = ROOT.parent / 'enforcement-publication.BXRanS/closeout.json'
closeout_raw = closeout.read_bytes()
assert sha(closeout_raw) == '32504cc096f003c4d90bb8a44e266c164d4311ae9a1377881c6d2f960e7d2376'
accepted = json.loads(closeout_raw)
assert accepted['status'] == 'DONE_SOURCE_GATES' and accepted['main'] == BASE
scope = json.loads((ROOT / 'scope.json').read_bytes())
assert scope['baseMain'] == BASE and scope['baseTree'] == TREE
assert all(scope[key] is False for key in (
    'w01Complete', 'independentReviewCompleted', 'implementationReady',
    'runtimeContractChanged', 'packetPublished', 'repositoryFilesChanged',
    'productExecution', 'runnerActivated', 'nativeAcceptance', 'tenantAcceptance',
    'oldAttemptsReset', 'phaseComplete', 'requestActionCorrelationProven'))
assert scope['enforcementProofsOpen'] == ['E%02d' % i for i in range(1, 13)]
assert scope['reviewGaps'] == ['G%02d' % i for i in range(1, 10)]
assert scope['testSpecificationsNotExecuted'] == ['T%02d' % i for i in range(1, 9)]
files = ['README.md', 'HOST_INTERFACE_SPEC.md', 'REVIEW_BRIEF.md', 'scope.json', 'inventory.py']
result = {
    'designLabel': scope['designLabel'], 'status': 'DATA_INVENTORY_NOT_ACCEPTANCE',
    'baseMain': BASE, 'baseTree': TREE, 'repositoryFilesChanged': False,
    'independentReviewCompleted': False, 'implementationReady': False,
    'productExecution': False, 'nativeAcceptance': False,
    'closeoutSha256': sha(closeout_raw), 'inputs': records,
    'draftFiles': {p: sha((ROOT / p).read_bytes()) for p in files},
    'researchReferences': [
        'https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/',
        'https://kubernetes.io/docs/reference/access-authn-authz/authorization/',
        'https://kubernetes.io/docs/reference/access-authn-authz/webhook/',
        'https://systemd.io/CGROUP_DELEGATION/',
        'https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter',
        'https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter',
    ],
    'researchObservedOn': '2026-09-17', 'researchReferencesAreReleaseLocks': False,
}
print(json.dumps(result, sort_keys=True, indent=2))
