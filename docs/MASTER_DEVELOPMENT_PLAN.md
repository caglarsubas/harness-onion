# Harness-Onion — unified development roadmap

## Current checkpoint — MET-ADOPT-005 source preparation, October 26, 2026

Alpha2 OPEN. MET-GOV-004 (LANG-PLACEMENT-ADR-001) passed required verify and merged as main ee26624.
TECH-ORCHESTRATION-001 (the owner's TECH-D1, "PostgreSQL-native (Recommended)", and Q-TO-6; the lane monitor's
owner-delegated rulings MON-TECHORCH-1, MON-TECHORCH-2 and MON-TECHORCH-M1) records the H10 execution authority:
docs/adr/0011-h10-execution-authority.md makes the PostgreSQL executor (PostgreSQL leases and outbox) H10's qualified
baseline and Temporal an optional provider, and names the superseded older planning texts by path and line without
editing them. docs/harnesses/execution.orchestration.md takes the new planning-target block (its lines 16-20), and
docs/repositories/08-mas-harness-execution-plane.md one clause on line 103, with lines 101-102 unchanged. docs/DEVELOPMENT_STATUS.md gains one line citing the ADR. The provider
catalog is unchanged. The packet registers its own review series, MET-ADOPT-005/packet, in the brief registry; its two gate paths are docs/harnesses/execution.orchestration.md (GATE_HARNESS_DOCS) and the rider in architecture/review-record/briefs.json (GATE_REVIEW_PROCESS), both in the evolution surface record at this base, so the owner approves the merge per PR, bound to the head. Its
new layer checks the new H10 block and the rest of that document against the base, the R08 line and its unchanged
lines, ADR 0011's bytes, its superseded-texts table and each superseded fragment once, the superseded texts and the
provider catalog against the base, the status file and the registry's one rider. It is built under MET-PERF-042's
identity rule and step rule: every older chain validator changes only by the bump vocabulary, 267's layer by the bridge
vocabulary, and 267's test keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new
head's test keeps the full fan-in. MET-ADOPT-005 is the sole 268th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ADOPT-005 / TECH-ORCHESTRATION-001 | SOURCE_PREPARED | The H10 execution authority ADR 0011 (268th packet): the owner's TECH-D1 and Q-TO-6, PostgreSQL leases and outbox as H10's qualified baseline and Temporal an optional provider; the new H10 block and one R08 clause, the superseded planning texts named and not edited, the provider catalog unchanged; gate material (the H10 harness document and the registry rider), the owner's per-PR approval |
| Alpha2A | MET-GOV-004 / LANG-PLACEMENT-ADR-001 | VERIFY_PASSED_MERGED | Merged as main ee26624 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes, and nothing is installed. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical language-placement source checkpoint — MET-GOV-004 source preparation, October 26, 2026

Alpha2 OPEN. MET-LINUX-008 (LINUX-HOST-AUTH-001) passed required verify and merged as main 9184f5b.
LANG-PLACEMENT-ADR-001 (the owner's language policy LANG-D2 (a); the lane monitor's owner-delegated rulings, among them
MON-GOV4-C1 and MON-GOV4-ADOPTED) publishes the language-placement ADR: docs/adr/0010-language-placement.md states the
policy as one digest-bound line and renders four tables from architecture/language-placement.json, which records the
planned language of every catalogued repository and deployable at this base, the rows outside the catalogue and the
pending exceptions, each bound by digest to the source lines that state it. scripts/language_placement.py is the minimal
offline checker with its tests tests/test_language_placement.py, and tests/test_language_placement_oracle.py is the D5a
oracle (KEEP), bound by architecture/oracle-identity-language-placement.json. The adopted contract is c5: the ADR, the
data, the checker and its tests, and the oracle and its identity, with the ADR's CONTRACT r1 text errata (c3), the
checker's R5 locating each cited span by its content (c4, c4a) and the re-issued oracle (c5). docs/DEVELOPMENT_STATUS.md gains one line citing the ADR, and the new layer pins it with the adopted files. The exceptions stay
pending LANG-HOTPATH-DECISION-001; nothing is implemented, moved or rewritten in any repository. The packet registers its
own review series, MET-GOV-004/packet, in the brief registry; its one gate path is the rider in architecture/review-record/briefs.json (GATE_REVIEW_PROCESS in the evolution surface record at this base), so the owner approves the merge per PR, bound to the head. Its new layer checks the adopted files by their bytes,
the data's LANG-D2 (a) policy digest, the oracle identity against the oracle test's bytes, and the registry's one series.
It is built under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump
vocabulary, 266's layer by the bridge vocabulary, and 266's test keeps its 8 own routes and the adjacent one and one
payload mutation (C2), while the new head's test keeps the full fan-in. MET-GOV-004 is the sole 267th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-GOV-004 / LANG-PLACEMENT-ADR-001 | SOURCE_PREPARED | The language-placement ADR 0010 (267th packet): the owner's language policy LANG-D2 (a) as one digest-bound line, and the planned language of every catalogued repository and deployable as data in architecture/language-placement.json, bound to its source lines, with the minimal offline checker, its tests and the D5a oracle; exceptions pending LANG-HOTPATH-DECISION-001; gate material (the registry rider), the owner's per-PR approval |
| Alpha2A | MET-LINUX-008 / LINUX-HOST-AUTH-001 | VERIFY_PASSED_MERGED | Merged as main 9184f5b |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes, and nothing is installed. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical Linux host-authority source checkpoint — MET-LINUX-008 source preparation, October 25, 2026

Alpha2 OPEN. MET-ENFORCE-042 (DIGEST-CONTRACT-V2) passed required verify and merged as main f9882c1. LINUX-HOST-AUTH-001
(the lane monitor's owner-delegated rulings, among them MON-LHA-CR1-KEEP, MON-LHA-CR2-KEEP, MON-LHA-C8,
MON-LHA-ORACLE-KEEP, MON-LHA-C8-ADOPTED and MON-LHA-266-GO-1-3) publishes the Linux host-authority contract v1 for the
owner's per-run GCP Linux hosts. architecture/linux-host-authority/ holds the superseding host authority, the host recipe,
the launcher install steps and the key custody model, each with its closed schema, the drop-manifest schema, the vectors
and the README; scripts/linux_host_authority.py is the offline checker with its tests tests/test_linux_host_authority.py,
and tests/test_linux_host_authority_oracle.py is the D5a oracle (KEEP), bound by
architecture/linux-host-authority/oracle-identity.json. The contract was adopted as candidate c8 (MON-LHA-C8-ADOPTED)
after three in-tree CONTRACT rounds of the MET-LINUX-008/contract series, published with their identities and the status
record, which also pins the adoption's two own edits (the README and the checker's tests). DATA_CHECK_ONLY: no GCP
project, VM, key or spend exists or is created, and native AMD64 and ARM64 stay NOT_RUN_ENV_UNAVAILABLE. Both review
series were registered before this packet, so the brief registry does not change; no gate class at this base (the evolution surface record), so the lane monitor and the owner approve the PR. Its new layer checks the status
(ADOPTED at slot 266 with a passing allowed-paths derivation and no gate class), the adopted subject by its bytes with the
adoption's two edits, the rounds' records and identities and the oracle by digest, and the registry's two series. It is
built under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump vocabulary,
265's layer by the bridge vocabulary, and 265's test keeps its 8 own routes and the adjacent one and one payload mutation
(C2), while the new head's test keeps the full fan-in. MET-LINUX-008 is the sole 266th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-LINUX-008 / LINUX-HOST-AUTH-001 | SOURCE_PREPARED | The Linux host-authority contract v1 (266th packet): the owner's per-run GCP Linux hosts, their recipe, the launcher install steps and the key custody as data under architecture/linux-host-authority/, with the offline checker, its tests and the D5a oracle; adopted as candidate c8 after three in-tree CONTRACT rounds; DATA_CHECK_ONLY; no gate class, the lane monitor's and the owner's PR approval |
| Alpha2A | MET-ENFORCE-042 / DIGEST-CONTRACT-V2 | VERIFY_PASSED_MERGED | Merged as main f9882c1 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes, and nothing is installed. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical digest contract v2 source checkpoint — MET-ENFORCE-042 source preparation, October 25, 2026

Alpha2 OPEN. MET-LINUX-009 (LINUX-ROOT-ALIASES) passed required verify and merged as main a882761. DIGEST-CONTRACT-V2 (the
LPK-1 step S1, with W1 and S2; the lane monitor's owner-delegated rulings MON-I01S-1 to MON-I01S-14, MON-I01S-D1 to
MON-I01S-D3, MON-I01S-DESIGN-CLOSED, MON-I01S-C4-ADOPT, MON-I01S-ORACLE-KEEP and MON-I01S-MECH-GO) publishes the I01 digest
contract v2 beside the frozen v1. The v2 contract (architecture/policy-observation-digests-v2/, model
scripts/policy_observation_digests_v2.py) renders the sealed A2 set with admission semantics v4 (planeon-qual's fence
sha256:9b1ddc10...ca60) and takes workload profile v2 for its complete positive, with the vectors re-derived from v1's
(ids kept) and the model's own count 323. W1 is in the new layer's test: VPO's validate_messages and profile v2's validate
and precondition on the complete positive, with no skip, expected-failure mark or import guard. Edge record v11
(architecture/artifact-edges/operator-harness-engineering-v11.json and README-v11.md) keeps v10's 72 rows and registers
the contract's three data files and admission v4's and profile v2's vectors for HE-004-I01B4; nothing is installed and R10
keeps v1 until S3. The contract was adopted as candidate c4 (MON-I01S-C4-ADOPT) after three in-tree CONTRACT rounds of the
MET-ENFORCE-042/contract series, published under architecture/policy-observation-digests-v2/ with their identities, the
source index and the D5a oracle identity that binds tests/test_policy_observation_digests_v2_oracle.py (KEEP). The
non-chain pinned files (I01 v1, the frozen models and inputs, admission v2 to v4, profile v2, the edge records v1 to v10
and every legacy review record among them) stay byte-identical, and the chain validators and tests in the pin lists change
only by the chain-bump vocabulary, under the step rule (B-L1-3); the pins and the evolution-surface classes are recorded
in architecture/policy-observation-digests-v2/mechanics-pins.json (B-L1-4). The brief registry gains this packet's PACKET
and CONTRACT series (the registry rider), the packet's one gate path (GATE_REVIEW_PROCESS), so the owner approves the
merge per PR, bound to the head. Its new layer checks the adoption and the rounds, the model over its vectors from this
era's bytes, admission v4's rendering of the sealed values, B-I01S-1's binding, edge record v11, the pins and classes, the
registry's two new entries after the base's ten, and that the packet's gate paths are exactly the registry. It is built
under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump vocabulary, 264's
layer by the bridge vocabulary, and 264's test keeps its 8 own routes and the adjacent one and one payload mutation (C2),
while the new head's test keeps the full fan-in. MET-ENFORCE-042 is the sole 265th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-042 / DIGEST-CONTRACT-V2 | SOURCE_PREPARED | The I01 digest contract v2 (265th packet): the successor beside the frozen v1 under architecture/policy-observation-digests-v2/ with its model scripts/policy_observation_digests_v2.py, rendering the sealed A2 set with admission semantics v4 and taking workload profile v2 for its complete positive (W1), with edge record v11 for HE-004-I01B4; adopted as candidate c4 after three in-tree CONTRACT rounds; every non-chain pinned file byte-identical (I01 v1 among them), the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under the step rule (B-L1-3); nothing installed; gate material only through the registry rider, the owner's per-PR merge |
| Alpha2A | MET-LINUX-009 / LINUX-ROOT-ALIASES | VERIFY_PASSED_MERGED | Merged as main a882761 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes, and nothing is installed. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical root-alias source checkpoint — MET-LINUX-009 source preparation, October 24, 2026

Alpha2 OPEN. MET-LIVE-004 (LINUX-PROBE-KIT-ADMISSION) passed required verify and merged as main 675dacc. LINUX-ROOT-ALIASES
(the lane monitor's owner-delegated rulings, among them MON-RA2-NEXT, MON-RA-SERIES, MON-RA-R1-KEEP, MON-RA-R2-KEEP,
MON-RA-ORACLE-KEEP and MON-RA-SLOT-264) publishes the signed root-alias contract for the native runner kit.
ci/linux-runner/common.py gains version 4 inputs with a signed root-alias record (the record's validator,
validate_inputs() v4 and the system inventories over the record's aliases), ci/linux-runner/launcher.py loads the record
as an authority file, passes it into isolation and re-checks it there, and ci/linux-runner/prepare.py takes
--root-aliases for a v4 request only; v3 inputs and their inventories are unchanged, and v4 is opt-in through a signed
record. docs/linux-runner/BUILD_INPUTS.md and OPERATOR.md describe it, tests/linux_runner/test_root_aliases.py holds the
vectors, and tests/test_met_linux_009_oracle.py is the D5a oracle (KEEP), bound by
architecture/linux-root-aliases/oracle-identity.json. The contract was adopted as candidate c3 (MON-RA-R2-KEEP) after two
in-tree CONTRACT rounds of the MET-LINUX-009/contract series, published under architecture/linux-root-aliases/ with their
identities and the status record; the brief registry gains this packet's PACKET and CONTRACT series (the registry rider).
SOURCE_ONLY: no Linux host PASS, installation, signature or listener registration is claimed. The packet is gate material (GATE_CI, GATE_VERIFIER_DOCS and GATE_REVIEW_PROCESS), so the owner approves the merge per PR, bound to the head. Its new
layer checks the status (ADOPTED at slot 264 with a passing allowed-paths derivation), the adopted subject by its bytes,
the rounds' records and identities by digest, and the registry's two series. It is built under MET-PERF-042's identity
rule and step rule: every older chain validator changes only by the bump vocabulary, 263's layer by the bridge
vocabulary, and 263's test keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new head's
test keeps the full fan-in. MET-LINUX-009 is the sole 264th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-LINUX-009 / LINUX-ROOT-ALIASES | SOURCE_PREPARED | The signed root-alias contract for the native runner kit (264th packet): version 4 inputs with a signed root-alias record in ci/linux-runner/ (common.py, launcher.py and prepare.py), the two linux-runner docs, the vectors and the D5a oracle; adopted as candidate c3 after two in-tree CONTRACT rounds; v3 unchanged; gate material, the owner's per-PR merge approval |
| Alpha2A | MET-LIVE-004 / LINUX-PROBE-KIT-ADMISSION | VERIFY_PASSED_MERGED | Merged as main 675dacc |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
The ci/linux-runner/ kit files and the two linux-runner docs change (gate material); no R10 and no R12 file changes, and
nothing is installed. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical probe kit admission source checkpoint — MET-LIVE-004 source preparation, October 24, 2026

Alpha2 OPEN. MET-LIVE-003 (LINUX-PROBE-INTERFACE) passed required verify and merged as main 0ffa7db. LINUX-PROBE-KIT-ADMISSION (owner
decisions Q-PK-3 "Never, pinned (Recommended)", Q-PK-4 "Upstream v1.37.1 (Recommended)" and "As steps (Recommended)"; the
lane monitor's owner-delegated rulings Q-LPK1-1 to Q-LPK1-12, Q-LPK1-D1 to Q-LPK1-D5, MON-LPK1-ADOPT-REV4, MON-LPK1-B3,
MON-LPK1-SCHEMA-RUN, MON-LPK1-C3-ADOPT, MON-LPK1-ORACLE-R2 and MON-LPK1-B6-P1) publishes workload profile v2 and admission
semantics v4 as one combined contract. Profile v2 (architecture/proxy-profile-v2/, model scripts/proxy_profile_v2.py) is a
successor beside profile v1: the Pod's echo annotations, bounded emptyDir volumes mounted under /work/ and the pull policy
Never. Admission semantics v4 (architecture/admission-semantics-v4/, model scripts/admission_semantics_v4.py) requires
every image pulled Never (MC33), bounds every emptyDir (MC42 and A2-POD-EMPTYDIR), pins AlwaysPullImages off, and
re-renders the sealed A2 file with a new directory hash; nothing is installed. The contract was adopted as candidate c3
(MON-LPK1-C3-ADOPT) after two in-tree CONTRACT rounds of the MET-LIVE-004/contract series, published under
architecture/linux-probe-kit-admission/ with their identities, the source index and the two D5a oracle identities that
bind tests/test_admission_semantics_v4_oracle.py and tests/test_proxy_profile_v2_oracle.py (KEEP). The non-chain pinned
files (profile v1, admission v3 and v2, I01's records, the plans and the edge records among them) stay byte-identical,
and the chain validators and tests in the pin lists change only by the chain-bump vocabulary, under the step rule
(B-L1-3); the pins and the evolution-surface classes are recorded in
architecture/linux-probe-kit-admission/mechanics-pins.json (B-L1-4). No gate
path changes: the brief registry already holds this packet's PACKET and CONTRACT series, and the evolution surface record
classifies every new path as data. Its new layer checks the adoption and the rounds, both models over their vectors (v4's
141 cases, v3's 114 through the frozen v3 model, the sealed A2 file and its directory hash, and profile v2's 67 cases with
the cross-contract group), the pins and classes, the unchanged registry, and that the packet's changed files hold no gate
path. It is built under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump
vocabulary, 262's layer by the bridge vocabulary, and 262's test keeps its 8 own routes and the adjacent one and one
payload mutation (C2), while the new head's test keeps the full fan-in. MET-LIVE-004 is the sole 263rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-LIVE-004 / LINUX-PROBE-KIT-ADMISSION | SOURCE_PREPARED | Workload profile v2 and admission semantics v4 (263rd packet): one combined contract under architecture/proxy-profile-v2/ and architecture/admission-semantics-v4/, adopted as candidate c3 after two in-tree CONTRACT rounds; every non-chain pinned file byte-identical (profile v1 and admission v3 among them), the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under the step rule (B-L1-3); nothing installed; data, no gate path |
| Alpha2A | MET-LIVE-003 / LINUX-PROBE-INTERFACE | VERIFY_PASSED_MERGED | Merged as main 0ffa7db |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes; no linux-probe-kit/ file yet, and no kit install before the carried steps
land. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical probe interface source checkpoint — MET-LIVE-003 source preparation, October 24, 2026

Alpha2 OPEN. MET-GOV-003 (LINUX-PROBE-KIT-GATE) passed required verify and merged as main b8db30e. LINUX-PROBE-INTERFACE (owner
decisions Q-PK-6 "Neutral contract (Recommended)" and, on R12's acceptance rules, "Keep them in R12 (Recommended)"; the
lane monitor's owner-delegated rulings MON-LIVE003-ADOPT-C2 to MON-LIVE003-ADOPT-C6, MON-LIVE003-R1-PATH and
MON-LIVE003-ORACLE-KEEP) brings the neutral Linux probe interface contract into harness-onion as data, byte-identical: the
four v1/ handoff files under architecture/linux-probe-interface/ (the unit R12 vendors back), the closed binding record
binding.json (their digests, the source, the three review digests and the binding of LPK-0's NEUTRAL_INTERFACE_CONTRACT
placeholder to this packet), its vectors and replay script, its README and the standard-library reference model
scripts/linux_probe_interface.py. The adopted contract is candidate c6, after one light review by a separate agent (its
redacted history published as review-history-light-r1, which is not a review-round record and carries no merge authority)
and README-only errata with the slot re-sequence. The D5a oracle test tests/test_linux_probe_interface_oracle.py, written
from the README alone, is bound by its oracle identity architecture/linux-probe-interface/oracle-identity.json (KEEP). The
contract is form-only: a kit built from it shows the interface form, not acceptance, and R12 keeps its status and count
rules. No gate path changes: the brief registry already holds this packet's PACKET series, and the evolution surface record
classifies every new path as data. Its new layer checks the adoption, the handoff bytes, the binding's source and reviews
against the MANIFEST, the placeholder binding against LPK-0's merged record, the reference model over the binding and the
vectors' replay (one positive, 28 negatives and 15 validator vectors), the unchanged registry, and that the packet's
changed files hold no gate path. It is built under MET-PERF-042's identity rule and step rule: every older chain validator
changes only by the bump vocabulary, 261's layer by the bridge vocabulary, and 261's test keeps its 8 own routes and the
adjacent one and one payload mutation (C2), while the new head's test keeps the full fan-in. MET-LIVE-003 is the sole
262nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-LIVE-003 / LINUX-PROBE-INTERFACE | SOURCE_PREPARED | The neutral Linux probe interface (262nd packet): the Q-PK-6 contract as harness-onion data under architecture/linux-probe-interface/, its four v1/ handoff files byte-identical, with the closed binding record that binds LPK-0's NEUTRAL_INTERFACE_CONTRACT placeholder, the reference model, vectors and replay; form-only, R12 keeps its acceptance rules; data, no gate path |
| Alpha2A | MET-GOV-003 / LINUX-PROBE-KIT-GATE | VERIFY_PASSED_MERGED | Merged as main b8db30e |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes; no linux-probe-kit/ file yet. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical probe-kit gate source checkpoint — MET-GOV-003 source preparation, October 24, 2026

Alpha2 OPEN. MET-LIVE-002 (LINUX-PROBE-KIT-SCOPE) passed required verify and merged as main b821ed6. LINUX-PROBE-KIT-GATE (owner
decision Q-PK-1 "New data directory (Recommended)"; the lane monitor's owner-delegated rulings on the dossier's six
questions, all (a), and Q-G3-1 (a), Q-G3-CAP (a), MON-261-ORACLE-KEEP, MON-261-C1-KEEP, MON-261-C2-ADOPT,
MON-261-CAND and MON-261-R1-1, with the build rules B-G3-1 and B-G3-2) amends MET-GOV-001's evolution surface record to
version 3: one CONTRACT_AND_SOURCE prefix entry, linux-probe-kit/, appended after release/, so that the Linux probe kit's
top-level data directory, a sibling of ci/ (the record refuses a data entry inside a gate prefix), is data and kit PRs
need no record change. The schema and the model do not change, the derived gate list stays at 31 entries, and the
vectors re-pin only the record's digest; the README states the reading. The D5a oracle test
tests/test_evolution_surface_oracle.py was scoped to version 3 by an oracle agent (two added lines), and its oracle
identity architecture/review-record/oracle-identity-evolution-surface.json was re-issued in place with its own
candidateCommit, a local commit on the old base b516619 (MON-261-CAND). The adopted contract is candidate c3: c2, after
one design review with a delta round and one contract review by separate agents (kept with the lane's records), with one
README sentence corrected after packet review round 1 (MON-261-R1-1). The packet also carries the MET-LIVE-004 brief
registry entries: two entries in architecture/review-record/briefs.json (PACKET MET-LIVE-004/packet and CONTRACT
MET-LIVE-004/contract; eight entries in all), each pinning one of the two generic briefs in architecture/review-briefs/
by sha256. The
record, its vectors and README, the oracle identity and briefs.json are gate material, so the owner approves the merge per
PR, bound to the head. Its new layer checks the record's change from version 2, the unchanged model over version 3 (the
gate list, the replay and the kit prefix's resolution: linux-probe-kit/x is CONTRACT_AND_SOURCE, Linux-Probe-Kit/x falls
in no class, a kit-only PR is approved by the lane monitor or the owner), the registry, the oracle edit and its identity,
and that the packet's gate paths are exactly those five. It is built under MET-PERF-042's identity rule and step rule:
every older chain validator changes only by the bump vocabulary, 260's layer by the bridge vocabulary, and 260's test
keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new head's test keeps the full
fan-in. MET-GOV-003 is the sole 261st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-GOV-003 / LINUX-PROBE-KIT-GATE | SOURCE_PREPARED | The evolution surface record version 3 (261st packet): the Linux probe kit's top-level data directory linux-probe-kit/ joins CONTRACT_AND_SOURCE as one prefix entry after release/ (owner Q-PK-1), so kit PRs are data; the derived gate list stays at 31 and the vectors re-pin only the record's digest; the D5a oracle test is scoped to version 3 by an oracle agent and its oracle identity re-issued in place (Q-G3-1 (a)); with the MET-LIVE-004 brief registry entries (two entries in architecture/review-record/briefs.json); gate material, the owner's per-PR merge approval |
| Alpha2A | MET-LIVE-002 / LINUX-PROBE-KIT-SCOPE | VERIFY_PASSED_MERGED | Merged as main b821ed6 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes; no linux-probe-kit/ file yet. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical probe-kit scope source checkpoint — MET-LIVE-002 source preparation, October 23, 2026

Alpha2 OPEN. MET-GOV-002 (REVIEW-RECORD-V2) passed required verify and merged as main b516619. LINUX-PROBE-KIT-SCOPE (owner decisions
Q-PK-2 "Move them (Recommended)", Q-LPK0-3 "Server side, KAP stays (Recommended)", Q-LPK0-4 "Retain as history
(Recommended)" and the registry decision "Batch, carried by 260 (Recommended)"; the lane monitor's owner-delegated
rulings, among them Q-LPK0-CAP, Q-260-1 (a), MON-260-READ (a) and MON-260-RIDER-DIR (a)) publishes the probe-kit scope
amendment under architecture/probe-kit-scope/: a closed record (amendment.json) that moves the CAMPAIGN_PROXY server side,
its admission module, the UID ledger and cleanup, the native record inspector, the worker entry, the ten case recipes and
the unsigned receipt candidates from R12's CONF-LIVE-003/004/005 to the operator-side probe kit (LINUX-PROBE-KIT-001),
keeps the campaign client and receipt and evidence verification with R12, and leaves the KAP leg deferred and unowned. It
supersedes the moved clauses by quote, names the living catalogs and pins the files it leaves unchanged, with an inventory
from a declared search at 2043cc27; a standard-library reference model (scripts/probe_kit_scope.py), vectors, a replay
script and the kit's prose page (docs/linux-probe-kit/README.md) come with it, DATA_CHECK_ONLY. It was adopted (c11) after
three design and two contract review rounds by separate agents, published redacted as review-history-* (not review-round
records, with no merge authority); the D5a oracle tests, written outside the candidate, are
tests/test_probe_kit_scope_oracle.py, bound by an oracle identity. The packet also carries the review-record brief
registry batch: five entries in architecture/review-record/briefs.json (PACKET for MET-LIVE-002, MET-GOV-003, MET-LIVE-003
and MET-LINUX-008; CONTRACT for MET-LINUX-008), each pinning one of the two generic briefs in architecture/review-briefs/
by sha256. briefs.json is gate material, so the owner approves the merge per PR, bound to the head. The layer reads the
record's base bytes git-free (its test compares them with git show at 2043cc27). It is built under MET-PERF-042's
identity rule and step rule: every older chain validator changes only by the bump vocabulary, 259's layer by the bridge
vocabulary, and 259's test keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new head's
test keeps the full fan-in. MET-LIVE-002 is the sole 260th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-LIVE-002 / LINUX-PROBE-KIT-SCOPE | SOURCE_PREPARED | The probe-kit scope amendment (260th packet): the CAMPAIGN_PROXY server side, the worker entry, the ten case recipes and the unsigned receipt candidates move from R12's CONF-LIVE-003/004/005 to the operator-side probe kit (LINUX-PROBE-KIT-001), R12 keeps the client and receipt and evidence verification, and the KAP leg stays deferred and unowned (a closed record with its model and vectors, DATA_CHECK_ONLY); adopted after three design and two contract review rounds; with the review-record brief registry rider (five entries in architecture/review-record/briefs.json); gate material, the owner's per-PR merge approval |
| Alpha2A | MET-GOV-002 / REVIEW-RECORD-V2 | VERIFY_PASSED_MERGED | Merged as main b516619 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path, no R10 and no R12 file changes. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical review record v2 source checkpoint — MET-GOV-002 source preparation, October 22, 2026

Alpha2 OPEN. MET-ENFORCE-041 (DIGEST-CONTRACT) passed required verify and merged as main 2043cc2. REVIEW-RECORD-V2 (owner
decisions Q-RR2-1..5 "Accept all five (a) (Recommended)", Q-RR2-6 "Gate material (Recommended)", Q-RR2-CAP, D-3
"File-byte sha256 (Recommended)" and Q-RR2-NAMES "Load hashes locally (Recommended)"; the lane monitor's owner-delegated
rulings, among them Q-RR2-ID (a), Q-RR2-LEGACY (c), Q-RR2-FROZEN, Q-RR2-VOID (b) and Q-RR2-ADOPT-SHAPE (a)) publishes the
review record v2 contract under architecture/review-record/: two records per review round bound by the file-byte
sha256 (the reviewer's record and the lane's identity), a brief registry, the frozen list of the 169 review records and 2
oracle tests that predate v2 (derived at this packet's base by the lane that may read every file and copied in
unopened), oracle identities (D5a), four closed schemas, a standard-library reference model and checker
(scripts/review_record.py) and replayable vectors, with the in-suite pre-check tests/test_review_records_in_tree.py. It
amends MET-GOV-001's evolution surface record to version 2 (the GATE_REVIEW_PROCESS class: the derived gate-material list
grows from 27 to 31 entries). It was adopted after six independent contract review rounds by separate agents (round 6
PASS_FOR_ADOPTION, NOTEs only), recorded in the contract's own v2 form; the status and the six rounds with their
identities are in architecture/review-record/, and the D5a oracle tests, written outside the candidate, are
tests/test_review_record_oracle.py and MET-GOV-001's oracle file scoped to the record's version 2. The packet is gate material (Q-RR2-6), so the owner approves the merge per PR, bound to the head.
It is built under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump
vocabulary, 258's layer by the bridge vocabulary, and 258's test keeps its 8 own routes and the adjacent one and one
payload mutation (C2), while the new head's test keeps the full fan-in. MET-GOV-002 is the sole 259th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-GOV-002 / REVIEW-RECORD-V2 | SOURCE_PREPARED | Review record v2 (259th packet): two records per review round bound by digest, the brief registry, the frozen list, oracle identities, schemas, model and vectors; the evolution surface record v2 (gate list 27 -> 31); adopted after six independent contract review rounds; gate material, the owner's per-PR merge approval |
| Alpha2A | MET-ENFORCE-041 / DIGEST-CONTRACT | VERIFY_PASSED_MERGED | Merged as main 2043cc2 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path and no R10 file changes. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical I01 digest contract source checkpoint — MET-ENFORCE-041 source preparation, October 22, 2026

Alpha2 OPEN. MET-GOV-001 (EVOLUTION-SURFACE-001) passed required verify in 743 s and merged as main 30f41e6. DIGEST-CONTRACT (owner decisions
Q-HE4I1-2 (c)+(a) and Q-DIG-3 / Q-DIG-7 "Accept, check at T04"; the lane monitor's owner-delegated Q-I01B-1 to Q-I01B-5,
Q-DIG-1, 2, 4-6 and 8-18 and Q-CB-1 to Q-CB-16) publishes the I01 digest contract before HE-004-I01B ports it: how the
policy observer derives the I01 v1 answer's seven projection objects and four enforcement digests, as closed
definitions, a standard-library reference model (scripts/policy_observation_digests.py) and replayable vectors under
architecture/policy-observation-digests/, DATA_CHECK_ONLY, with named residuals for T04. Operator edge record v10 keeps
edge record v9's 68 rows unchanged and in order and registers the contract's three data files (providerPacket
MET-ENFORCE-041) and the proxy-contract vectors (at their last-change commit) for HE-004-I01B, each BYTE_IDENTICAL and
REGISTERED_BEFORE_USE. Candidate 4 was adopted by the lane monitor after three design and four contract review rounds by
separate agents (contract round 4 PASS_FOR_ADOPTION, NOTEs only); the status, the seven review records and the seven
redacted briefs are in architecture/policy-observation-digests/, and the D5a oracle tests, written outside the candidate,
are tests/test_policy_observation_digests_oracle.py. The I01 v1 wire (channel schema, vectors, readiness document) and
edge records v1 to v9 stay byte-identical. The layer test runs VPO's validate_messages and VPC's validate_profile on the
complete I01 positive with no skip, expected-failure mark or import guard (C1-1). It is built under MET-PERF-042's
identity rule and step rule: every older chain validator changes only by the bump vocabulary, 257's layer by the bridge
vocabulary, and 257's test keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new head's
test keeps the full fan-in. MET-ENFORCE-041 is the sole 258th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-041 / DIGEST-CONTRACT | SOURCE_PREPARED | The I01 digest contract (258th packet): how the policy observer derives the I01 v1 answer's seven projection objects and four enforcement digests (definitions, a standard-library reference model and replayable vectors, DATA_CHECK_ONLY), and operator edge record v10 registering the contract's three data files and the proxy-contract vectors for HE-004-I01B before use; adopted after three design and four contract review rounds; the layer test runs VPO's validate_messages on the complete I01 positive (C1-1); packet review; verify |
| Alpha2A | MET-GOV-001 / EVOLUTION-SURFACE-001 | VERIFY_PASSED_MERGED | Merged as main 30f41e6 (verify 743 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path and no R10 file changes. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical evolution surface source checkpoint — MET-GOV-001 source preparation, October 22, 2026

Alpha2 OPEN. MET-ENFORCE-040 (EDGE-V9) passed required verify in 726 s and merged as main 26a8aff. EVOLUTION-SURFACE-001
(owner decisions Q-ES-1..7, "Accept, but gate it (Recommended)", with Q-ES-6 (b); Q-ES-CAP (a), Q-ES-D1 (a) to Q-ES-D3
(a), Q-GOV-CAP and the owner's NOTE fold; packet id MON-ES-ID) publishes the evolution surface record v1: which roles may
propose, generate, test, approve and activate each artifact class, at the product level (the four planes' evolution
roles, the evolvable and the never-autonomous artifact classes) and at the programme level (Harness-Onion's own artifacts
by repository path, and its bridge records), with the derived gate-material list, a closed schema, a standard-library
reference model (scripts/evolution_surface.py) and replayable vectors. It was adopted after five independent contract
review rounds (the fifth PASS_FOR_ADOPTION) and the owner's fold of round 5's four NOTEs with no further round; the
status, the five review records and the round snapshots are in architecture/evolution-surface/. Nothing runs and nothing
is enforced: MAS-RA-005's admission gate and R09 consume the record later. The record is gate material (Q-ES-6 (b)): the
owner approves this packet's merge per PR, bound to the head. It is built under MET-PERF-042's identity rule and step
rule, as 256 was: every older chain validator changes only by the bump vocabulary, 256's layer by the bridge vocabulary,
and 256's test keeps its 8 own routes and the adjacent one and one payload mutation (C2), while the new head's test keeps
the full fan-in. MET-GOV-001 is the sole 257th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-GOV-001 / EVOLUTION-SURFACE-001 | SOURCE_PREPARED | Evolution surface record v1 (257th packet): who may propose, generate, test, approve and activate each artifact class at the product and programme levels, with the derived gate-material list, schema, model and vectors; adopted after five independent contract review rounds and the owner's NOTE fold; gate material, the owner's per-PR merge approval |
| Alpha2A | MET-ENFORCE-040 / EDGE-V9 | VERIFY_PASSED_MERGED | Merged as main 26a8aff (verify 726 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path and no R10 file changes. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical edge record v9 source checkpoint — MET-ENFORCE-040 source preparation, October 22, 2026

Alpha2 OPEN. MET-PERF-042 (CHAIN-COMPACTION-001) passed required verify in 987 s and merged as main 6835a6e. EDGE-V9 (owner
decisions Q-HE4I1-10 (a) and Q-I01A-1; the lane monitor's owner-delegated Q-EV9-1 to Q-EV9-5 and Q-EV9-1b) publishes
the operator -> harness-engineering edge record v9 before HE-004-I01's step U7 vendors the I01 wire: edge record v8's 66
rows unchanged and in order, plus 2 rows that register architecture/policy-observation-inputs/channel.schema.json and
vectors.json (MET-REPAIR-010's files, unchanged since) for HE-004-I01 under host-enforcement/contracts/i01-v1/, each
BYTE_IDENTICAL and REGISTERED_BEFORE_USE with its last-change commit and no providerPacket. Candidate 2 was adopted by the
lane monitor after two independent contract review rounds (the second PASS_FOR_ADOPTION); the status and review records
are in architecture/edge-record-v9/. Edge records v1 to v8 and the two provider files stay byte-identical. It is the
first packet built under MET-PERF-042's identity rule and step rule: every older chain validator changes only by the bump
vocabulary, 255's layer by the bridge vocabulary, and 255's test keeps its 8 own routes and the adjacent one and one
payload mutation (C2), while the new head's test keeps the full fan-in. MET-ENFORCE-040 is the sole 256th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-040 / EDGE-V9 | SOURCE_PREPARED | Operator edge record v9 (256th packet): edge record v8's 66 rows unchanged plus 2 that register the I01 wire's channel schema and vectors (architecture/policy-observation-inputs/, BYTE_IDENTICAL, REGISTERED_BEFORE_USE) for HE-004-I01 under host-enforcement/contracts/i01-v1/; adopted after two independent contract review rounds; the first packet built under MET-PERF-042's identity rule and step rule; packet review; verify |
| Alpha2A | MET-PERF-042 / CHAIN-COMPACTION-001 | VERIFY_PASSED_MERGED | Merged as main 6835a6e (verify 987 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path and no R10 file changes. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical chain compaction source checkpoint — MET-PERF-042 source preparation, October 21, 2026

Alpha2 OPEN. MET-ENFORCE-039 (I06-RBAC-V4) passed required verify in 956 s and merged as main 29c84b3. CHAIN-COMPACTION-001
(owner decision PA-D9 (D9a); plan revision 11) compacts the history chain's test scaffold where the cost report shows no
loss of a required check. In the 63 bridged scaffold test files only two tests change and every test name stays: the
route test keeps its 8 own routes and the adjacent one (2,079 route nodes leave the suite, each with an identical-input
twin in the head's full fan-in), and the payload test keeps one mutation plus a check of the layer's expected-payload
table against digests the test computes itself from the disk YAML. tests/conftest.py shares test-side YAML parses per
test module (owner Q-CC-2 (a)) and never shares the two new identity tests. The identity rule becomes a standing rule
(owner Q-CC-IDENTITY (a)): scripts/chain_identity.py checks the chain walk, the class rules, the step rule against the
bump and bridge vocabularies, the binding rule and the head's allow-list, over the era in the new layer and over the live
tree in its test, which also runs the runtime binding check. One inherited edit outside C2 (owner Q-CC-F1 (a)) widens
241's pinned never-shared set by the two identity tests. MET-PERF-042 is the sole 255th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-042 / CHAIN-COMPACTION-001 | SOURCE_PREPARED | Chain compaction (255th packet): in the 63 bridged scaffold test files the route test keeps its 8 own routes and the adjacent one, and the payload test keeps one mutation plus a check of the layer's expected-payload table against digests the test computes from the disk YAML (2,079 route nodes leave the suite, each with an identical-input twin in the head's full fan-in); test-side YAML parse sharing per test module in tests/conftest.py; the identity rule as a standing rule (scripts/chain_identity.py: the walk, class, step, binding and allow-list rules, and the runtime binding check in the layer's test); one inherited edit outside C2 (owner Q-CC-F1 (a)); M2, M3, packet review; verify |
| Alpha2A | MET-ENFORCE-039 / I06-RBAC-V4 | VERIFY_PASSED_MERGED | Merged as main 29c84b3 (verify 956 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
No ci/ path changes, no validator under scripts/ shares or caches, and no timeout, worker or deadline change. M2 (the
measured A/B: B1 0.819 and B4 0.661, owner-accepted) and M3 (the seeded-fault evidence: 352 cases, 0 FAIL) ran on the
lane monitor's word; their records are ab.json and seeded-faults.json. Phase-end effort
transition NOT_DUE. Prior checkpoints below are history only.

## Historical I06 backend profile v4 source checkpoint — MET-ENFORCE-039 source preparation, October 20, 2026

Alpha2 OPEN. MET-PERF-041 (the pytest-diagnostics caps) passed required verify in 869 s and merged as main 585364b. I06-RBAC-V4
publishes the I06 backend profile v4, a delta successor of I06 v3 that keeps v3's evidence rule (check_evidence is v3's
function object) and pins the policy observer's one closed ClusterRole and binding exactly: list and watch on the 19
(group, resource) pairs of HE-004C's 20 request specs and get on five non-resource URLs, with criteria RB00 to RB07
(owner Q-HE4-6 (a) and Q-RBAC-1 to Q-RBAC-8 (a); the monitor's Q-RBAC-9 (a), Q-RBAC-10 and Q-RBAC-11 (a)); and edge
record v8, v7's 62 rows plus 4 for HE-008 and HE-004-I01. It discharges I06 v3's and native-profile v5's carry of the
ClusterRole successor. MET-PERF-041 took slot 253 (owner Q-253-DIAG (a)), so the adopted status record's slot moved from
253 to 254 (the monitor's slot edit). MET-ENFORCE-039 is the sole 254th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-039 / I06-RBAC-V4 | SOURCE_PREPARED | I06 backend profile v4 (254th packet): a delta successor of I06 v3 that keeps v3's evidence rule (check_evidence is v3's function object) and pins the policy observer's one closed ClusterRole and binding exactly (list and watch on the 19 (group, resource) pairs of HE-004C's 20 request specs, get on five non-resource URLs; criteria RB00 to RB07, 151 checks), and edge record v8 (v7's 62 rows plus 4 for HE-008 and HE-004-I01); candidate 2 adopted by the monitor (owner-delegated) after contract review round 2, PASS; moved from slot 253 to 254 (owner Q-253-DIAG (a)); packet review; verify |
| Alpha2A | MET-PERF-041 | VERIFY_PASSED_MERGED | Merged as main 585364b (verify 869 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: I06 v1 to v3 and native-profile v1 to v5 (their models included) and edge records v1 to v7 stay
byte-identical; no R10 file changes, and no role code, cloud, runner, live/native/tenant or model-effort change.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical pytest-diagnostics caps source checkpoint — MET-PERF-041 source preparation, October 20, 2026

Alpha2 OPEN. MET-ENFORCE-038 (NATIVE-PROFILE-V5) passed required verify in 857 s and merged as main 27c5460. MET-ENFORCE-039's
dry run then failed closed at argv 63 on the pytest diagnostics stream: 16,306 tests passed, but the outer pytest's
diagnostics reached their 20 MiB cap. The owner put a small ci/ packet first (Q-253-DIAG (a)) and sized it under the
verifier's 32 MiB output ceiling (Q-DIAGCAP-SIZE (A)): MAX_PROCESS_BYTES 30 MiB, MAX_EVENTS 140,000, MAX_SCAN_LINES
derived as MAX_EVENTS + MAX_EVENTS // 10, MAX_SCAN_BYTES following, and 2 MiB reserved for all other output. The
worst case at constant maximum digits fits 22,874 tests, about 9 to 22 packets of headroom; CHAIN-COMPACTION-001 is the
structural follow-up. I06-RBAC-V4 (MET-ENFORCE-039) moves to slot 254. MET-PERF-041 is the sole 253rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-041 | SOURCE_PREPARED | Pytest-diagnostics caps (253rd packet) under the owner's verifier's 32 MiB output ceiling: MAX_PROCESS_BYTES 20 -> 30 MiB, MAX_EVENTS 100,000 -> 140,000, MAX_SCAN_LINES derived (154,000), MAX_SCAN_BYTES following, 2 MiB reserved for all other output (owner Q-253-DIAG (a), Q-DIAGCAP-SIZE (A)); three contract review rounds, PASS_FOR_BUILD; packet review; owner approval of the exact head (ci/); verify |
| Alpha2A | MET-ENFORCE-038 / NATIVE-PROFILE-V5 | VERIFY_PASSED_MERGED | Merged as main 27c5460 (verify 857 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
The record schema and every fail-closed rule are unchanged, and every earlier record stating the 20 MiB caps stays
byte-identical. The caps are a ci/ change, which needs the owner's approval of the exact head before verify. No role
code, cloud, runner, live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints
below are history only.

## Historical capture-only native-profile v5 source checkpoint — MET-ENFORCE-038 source preparation, October 19, 2026

Alpha2 OPEN. MET-LINUX-007 (LAB-RUNPLAN-001) passed required verify in 736 s and merged as main 35b733b. NATIVE-PROFILE-V5
publishes the capture-only native-profile v5: the P1, P5 and backend captures without the seven host, policy and boot
fields that HE-004D1 can only fill from the record, which become record-only with four named T04 proofs, while the
record contract stays native-profile v4's (owner Q-NPE-1 to Q-NPE-8 and Q-HE4D2-3 (a); the monitor's Q-NPE-9 (a) and
Q-NPE-10); and edge record v7, v6's 56 rows plus 6 for HE-004D2. It discharges W03-PLAN-AMEND-3's residual and dependency
name. MET-ENFORCE-038 is the sole 252nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-038 / NATIVE-PROFILE-V5 | SOURCE_PREPARED | Capture-only native-profile v5 (252nd packet): native-profile v4's P1, P5 and backend captures without the seven host, policy and boot fields, which become record-only with four named T04 proofs (T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS, T04-BOOT-ENTRY), the record contract staying native-profile v4's, 8 re-derived and 18 new vectors (284 checks), and edge record v7 (v6's 56 rows plus 6 for HE-004D2); candidate 4 adopted by the monitor (owner-delegated) after contract review round 4, PASS; packet review; verify |
| Alpha2 | MET-LINUX-007 / LAB-RUNPLAN-001 | VERIFY_PASSED_MERGED | Merged as main 35b733b (verify 736 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: native-profile v1 to v4, I06 v1 to v3 (their models included), the W02 notes errata and edge records v1
to v6 stay byte-identical; no R10 file changes, and no role code, cloud, runner, live/native/tenant or model-effort
change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical lab run-plan contract v1 source checkpoint — MET-LINUX-007 source preparation, October 19, 2026

Alpha2 OPEN. MET-ENFORCE-037 (W03-PLAN-AMEND-3) passed required verify in 916 s and merged as main f560209. LAB-RUNPLAN-001
publishes the lab run-plan contract v1: closed schemas for a qualification run plan on the owner's GCP compute, its lease
and its teardown-residual report, with positive and negative vectors and an offline checker, so each CONF-LINUX-001 or
W06 run plan reaches the owner in one form and is approved by its sha256 (owner VR-D1; the owner's 2026-10-15 decision on
Linux capacity; owner Q-RP-0..9 (a)). MET-LINUX-007 is the sole 251st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-LINUX-007 / LAB-RUNPLAN-001 | SOURCE_PREPARED | Lab run-plan contract v1 (251st packet): closed schemas for a qualification run plan on the owner's GCP compute, its lease and its teardown-residual report, with vectors and an offline checker; the owner approves each plan by its sha256 (owner VR-D1, Q-RP-0..9 (a)); contract review rounds, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-037 / W03-PLAN-AMEND-3 | VERIFY_PASSED_MERGED | Merged as main f560209 (verify 916 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: no cloud run, cost, credential or teardown; the artifact edge records and the repository registry stay
byte-identical (R12's edge comes later); no R10 file changes, and no role code, cloud, runner, live/native/tenant or
model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical W03 plan amendment 3 source checkpoint — MET-ENFORCE-037 source preparation, October 18, 2026

Alpha2 OPEN. MET-ENFORCE-036 (SECCOMP-OBSERVER-LISTENER packet 2) passed required verify in 720 s and merged as main a3b9e6e.
W03-PLAN-AMEND-3 records the policy observer's host-policy share and the broker's quiescent-freeze obligation that
HE-004D1's captures need (owner Q-HE4D1-8 and -9 (a); the NP-9 minimum from owner Q-HE4D1-D2 (a)), corrects HE-003's
amendment-1 share as owner Q-HE3-3 (a) directs, and records HE-004D1's scope and decisions (owner Q-HE4D1-1..12 (a)).
MET-ENFORCE-037 is the sole 250th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-037 / W03-PLAN-AMEND-3 | SOURCE_PREPARED | W03 obligation-register amendment 3 (250th packet): OBS-HOSTPOL-1 (the policy observer's host-policy share for HE-008 plus a T04 check) and NP-9 (the broker's quiescent freeze of the probe-worker leaf, HE-005) added, HE-003's share in amendment 1's SEC-4 and HI-7 rows corrected as owner decision Q-HE3-3 (a) directs (closed change kind SHARE_CORRECTED), and HE-004D1's packet scope with its decisions, hand-offs and residuals, applied after amendments 1 and 2; candidate 5 re-adopted by the monitor (owner-delegated) after contract review round 4, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-036 / SECCOMP-OBSERVER-LISTENER | VERIFY_PASSED_MERGED | Merged as main a3b9e6e (verify 720 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: plan v2, amendments 1 and 2, edge record v5 and every file the amendment cites stay byte-identical; no
edge record is published, no R10 file changes, and no role code, cloud, runner, live/native/tenant or model-effort change.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical compiled filter programs v3 source checkpoint — MET-ENFORCE-036 source preparation, October 18, 2026

Alpha2 OPEN. MET-ENFORCE-035 (SECCOMP-OBSERVER-LISTENER packet 1) passed required verify in 978 s and merged as main f4bb000.
SECCOMP-OBSERVER-LISTENER packet 2 publishes the compiled filter programs v3 beside the byte-identical v1 and v2: only
OBSERVER's two programs change, each the earlier program with exactly the bind/listen pair and the accept4 flag block
inserted, every v5 OBSERVER decision vector replays through the published bytes, and edge record v6 registers the two for
R10's HE-004-I01. MET-ENFORCE-036 is the sole 249th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-036 / SECCOMP-OBSERVER-LISTENER | SOURCE_PREPARED | Compiled filter programs v3 and edge record v6 (249th packet, packet 2 of 2): OBSERVER's two programs republished from seccomp allowlists v5 (x86_64 253 and aarch64 242 instructions, the earlier programs plus the bind/listen pair and the accept4 flag block), the other twelve proven byte-identical, and the two registered for R10's HE-004-I01 under contracts/seccomp-v5/ (lane monitor Q-P2-1..4 (a)); contract review round 2, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-035 / SECCOMP-OBSERVER-LISTENER | VERIFY_PASSED_MERGED | Merged as main f4bb000 (verify 978 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: HS53, seccomp v5, the earlier compiled programs and edge records v1 to v5 stay byte-identical; no filter
is installed, and no role code, cloud, runner, live/native/tenant or model-effort change. Phase-end effort transition
NOT_DUE. Prior checkpoints below are history only.

## Historical seccomp observer listener source checkpoint — MET-ENFORCE-035 source preparation, October 18, 2026

Alpha2 OPEN. MET-ENFORCE-034 (SELINUX-MATRIX-V6) passed required verify in 709 s and merged as main 422bd18.
SECCOMP-OBSERVER-LISTENER packet 1 publishes W01 amendment HS53 on top of the byte-identical HS43 text and the seccomp
allowlists v5 beside the byte-identical v4: the observer gets the I01 listener the W01 row lacked, the filter limits
accept4 to three flag values and leaves the TCP-listen boundary to SELinux, and the observer binds after its seal while
systemd clears only its stale path, as matrix v6 now permits. MET-ENFORCE-035 is the sole 248th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-035 / SECCOMP-OBSERVER-LISTENER | SOURCE_PREPARED | W01 amendment HS53 and seccomp allowlists v5 (248th packet, packet 1 of 2): OBSERVER's I01 AF_UNIX SOCK_SEQPACKET listener (bind, listen, accept4 with three flag values), the TCP-listen boundary on SELinux, the socket's directory and mode from the units, and systemd clearing only the observer's stale path under matrix v6's init_t grant (owner Q-SOL-2/4, SOL-SYSTEMD-CLEANS); contract review round 8, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-034 / SELINUX-MATRIX-V6 | VERIFY_PASSED_MERGED | Merged as main 422bd18 (verify 709 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: HS43, seccomp v4, matrices v5 and v6 and the compiled programs stay byte-identical; packet 2 republishes
OBSERVER's programs and the edge record; no filter is installed, and no role code, cloud, runner, live/native/tenant or
model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical SELinux matrix v6 source checkpoint — MET-ENFORCE-034 source preparation, October 18, 2026

Alpha2 OPEN. MET-ENFORCE-033 (NATIVE-PROFILE-V4) passed required verify in 924 s and merged as main 887cbe7. SELINUX-MATRIX-V6
publishes the SELinux matrix v6 beside the byte-identical v5: every planeon and qualk8s source is closed over the types it
may execute without a transition, enter or relabel to, context= mounts get their own filesystem table, the server reads
only its observer's and broker's /proc and the broker only the gate's, and systemd may only stat and unlink the four
planeon listener sockets. Its coupling with the merged native-profile v4 is re-checked. MET-ENFORCE-034 is the sole 247th
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-034 / SELINUX-MATRIX-V6 | SOURCE_PREPARED | SELinux matrix v6 (247th packet): v5 plus fail-closed source closures (qualk8s execute_no_trans, process transition and dyntransition, filesystem relabelto), the filesystem tables for context= mounts, entry closures, the /proc reader narrowing and systemd's narrowed cleanup of the four planeon listener sockets (owner Q-MX6-2/3/4/7, "Keep, T04 uses v5", SOL-SYSTEMD-CLEANS); contract review round 7, PASS; coupled to the merged native-profile v4; packet review; verify |
| Alpha2A | MET-ENFORCE-033 / NATIVE-PROFILE-V4 | VERIFY_PASSED_MERGED | Merged as main 887cbe7 (verify 924 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the earlier matrix records, HS43 and native-profile v4 stay byte-identical; T04 cluster runs keep using matrix v5
until a successor declares the helper types; no policy module is written or loaded, and no role code, cloud, runner,
live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical native-profile v4 source checkpoint — MET-ENFORCE-033 source preparation, October 17, 2026

Alpha2 OPEN. MET-MAS-004 (MAS-RA-004) passed required verify in 755 s and merged as main 75669de. NATIVE-PROFILE-V4 publishes
native-profile v4: v3 plus O-NATIVE-GATE-NOCAP, label-bound capture routes for the processes the observer cannot read
(the observed domain label, the measured entrypoint file and declared premises, each with a named T04 proof) and the
inspector obligation restated per role. The I06 v3 is bound to it, and operator edge record v5 registers the files
HE-004D1 and HE-004D2 consume. MET-ENFORCE-033 is the sole 246th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-033 / NATIVE-PROFILE-V4 | SOURCE_PREPARED | Native-profile v4 and I06 v3 (246th packet): v3 plus O-NATIVE-GATE-NOCAP (the effect gate holds no capability), the capture routes (the observer as capturer, evidence classes by role and recorded capability set, entrypoint label constants, single-file and interpreter closures) and the restated inspector obligation (the worker leaf only inside a frozen bracket), I06 bound to native-profile v4, and operator edge record v5 (v4's 45 rows plus 9 registered before use for HE-004D1 and HE-004D2); adopted by the monitor (owner-delegated) after contract review round 3, PASS; packet review; verify |
| Alpha2A | MET-MAS-004 / MAS-RA-004 | VERIFY_PASSED_MERGED | Merged as main 75669de (verify 755 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: native-profile v1 to v3, I06 v1 and v2, the W02 notes errata, matrix v5, seccomp v4, HS43 and edge
records v1 to v4 stay byte-identical; no capture route was exercised on a host, every declared premise stays a named T04
proof, and no role code, cloud, runner, live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical topology and coordination v1 source checkpoint — MET-MAS-004 source preparation, October 17, 2026

Alpha2 OPEN. MET-ENFORCE-032 (W03-PLAN-AMEND-2) passed required verify in 580 s and merged as main c69e55f. MAS-RA-004
publishes topology and coordination v1, the H10 coordination contract the MAS-RA research block ranks next: a declared
topology, a board that hands out work only as exclusive leased claims and merges it only after an independent verdict,
and a declared selection rule that compares a topology's eligible single-agent baseline with the reported threshold.
MET-MAS-004 is the sole 245th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-MAS-004 / MAS-RA-004 | SOURCE_PREPARED | Topology and coordination v1 (245th packet): a TopologySpec with its derived role-block vector, a coordinator board on exclusive leased claims with an independent verify-before-merge bound to a MAS-RA-001 ledger, a declared selection rule at 45/100 over eligible MAS-RA-002 baselines and the run-events v1 mapping with its gaps (owner MAS-RA-004 and Q-M4-1..11 (a)); contract review round 5, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-032 / W03-PLAN-AMEND-2 | VERIFY_PASSED_MERGED | Merged as main c69e55f (verify 580 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumer of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the MAS-RA-001, MAS-RA-002, MAS-RA-003 and MAS-RA-008 contracts and models and every harness document
stay byte-identical; nothing runs (no coordinator, board storage or executor), and no role code, cloud, runner,
live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical W03 obligation-register amendment 2 source checkpoint — MET-ENFORCE-032 source preparation, October 16, 2026

Alpha2 OPEN. MET-ENFORCE-031 (LICENCE-POLICY-AMEND, license-policy amendment LIC-HOST-A2) passed required verify in 592 s
and merged as main b0635f8. W03-PLAN-AMEND-2 records the policy observer's split (the monitor's owner-delegated Q-HE4-2 (a)),
I01 as a plan obligation (Q-HE4-1 (a)), the T04 audit-trace route for the observer's wrapper evidence and R10's adoption
of the I05 gate channel v4, and publishes the operator edge record v4 for HE-004B1 and HE-003A3. MET-ENFORCE-032 is the
sole 244th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-032 / W03-PLAN-AMEND-2 | SOURCE_PREPARED | W03 obligation-register amendment 2 (244th packet): plan v2's HE-004 refined into HE-004A, HE-004B1, HE-004C, HE-004D1 and HE-004D2 (closed change kind REFINED, plan v2's text byte for byte), the new packets HE-004-I01 and HE-003A3 with I01-1, OBS-RBAC-1, OBS-INV-1, I05-7 and I05-8, applied after amendment 1; operator edge record v4 (v3's 33 rows plus 12 registered before use); adopted by the monitor (owner-delegated) after contract review round 3, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-031 / LICENCE-POLICY-AMEND | VERIFY_PASSED_MERGED | Merged as main b0635f8 (verify 592 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: plan v2, amendment 1, edge record v3 and the 12 registered provider files stay byte-identical; no R10
file changes, the registered files are not used before the R10 consumer packets, and no role code, cloud, runner,
live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical license-policy amendment A2 source checkpoint — MET-ENFORCE-031 source preparation, October 16, 2026

Alpha2 OPEN. MET-ENFORCE-030 (I05-OBSERVED-WORKERS, the I05 gate channel v4) passed required verify in 816 s and merged as
main fd362f9. LICENCE-POLICY-AMEND resolves phoenix-sqlean's DENY_UNKNOWN_LICENSE (RA-LICENSE-001 note N-2) by making Zlib
default-allowed: license-policy amendment LIC-HOST-A2 is an overlay, and the base policy and A1 stay byte-identical.
MET-ENFORCE-031 is the sole 243rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-031 / LICENCE-POLICY-AMEND | SOURCE_PREPARED | License-policy amendment LIC-HOST-A2 (243rd packet): Zlib default-allowed globally as an overlay on the byte-identical base policy 0.3.0 and A1 (monitor LIC-ZLIB, L2-1 (a), L2-2 (a)); the layer replays every A1 and A2 vector itself (P2-F1), refuses non-era paths before reading (P2-F2), routes the A1 identity check (LR2-4) and pins safe_yaml (LR3-2); contract review round 3, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-030 / I05-OBSERVED-WORKERS | VERIFY_PASSED_MERGED | Merged as main fd362f9 (verify 816 s) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the base policy, A1, its classifier, safe_yaml and the research-adoption record stay byte-identical; no
artifact is released, no consumer is switched to A2, and no role code, cloud, runner, live/native/tenant or model-effort
change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical I05 gate channel v4 source checkpoint — MET-ENFORCE-030 source preparation, October 16, 2026

Alpha2 OPEN. MET-PERF-040 (PERF-040, chain-depth headroom) passed required verify in 566 s and merged as main 3cba117.
I05-OBSERVED-WORKERS answers the second half of owner decision Q-HE3D-2 (a): production BIND fails closed until the gate
has an allowed source for the worker it binds. The I05 gate channel v4 defines that source; R10 adopts it in its own
packet. MET-ENFORCE-030 is the sole 242nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-030 / I05-OBSERVED-WORKERS | SOURCE_PREPARED | I05 gate channel v4 (242nd packet): the gate observes the broker's probe-worker cgroup at every BIND (cgroup.procs, pidfd_open, stat starttime, cgroup.procs again, pidfd poll), every failure the existing WORKER_NOT_OBSERVED, the v3 wire byte-identical (owner Q-HE3D-2 (a), Q-I5-4 (a); monitor Q-I5-1..3 (a)); contract review round 5, PASS; packet review; verify |
| Alpha2A | MET-PERF-040 / PERF-040 | VERIFY_PASSED_MERGED | Merged as main 3cba117 (verify 566 s) |
| Alpha2A | LICENCE-POLICY-AMEND | WAITING_PACKET_PUBLICATION | LIC-HOST-A2 (Zlib) contract adopted (slot 243, parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the I05 v3 contract, its supplement and its model stay byte-identical; no gate is installed, nothing
reads /proc, no R10 file changes, and no role code, cloud, runner, live/native/tenant or model-effort change. Phase-end
effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical chain-depth headroom source checkpoint — MET-PERF-040 source preparation, October 16, 2026

Alpha2 OPEN. MET-ENFORCE-029 (PROGRAMS-REPUBLISH, compiled filter programs v2) passed required verify and merged as main
d2ef708, with 994 s of the 1200 s cap. The owner put PERF-040 first (PERF-040-FIRST): most test time went to fresh
authority reads that repeat an identical projection inside one test, and each packet's authority grew by the whole
lines its chain bump rewrites. MET-PERF-040 is the sole 241st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-040 / PERF-040 | SOURCE_PREPARED | Chain-depth headroom (241st packet): test-local exact sharing of history projections except 15 never-shared tests (Q-PERF40-1 (a)), canonical byte-minimal authority hunks (Q-PERF40-4 (a)), refreshed parallel-suite weights for all 127 test files at six workers (Q-PERF40-3 (a)) and the matrix v5 replay order (P2-1); no validator freshness change (Q-PERF40-2 (a)); source review; packet review; owner approval of the exact head (ci/ weights); verify |
| Alpha2A | MET-ENFORCE-029 / PROGRAMS-REPUBLISH | VERIFY_PASSED_MERGED | Merged as main d2ef708 |
| Alpha2A | I05-OBSERVED-WORKERS | WAITING_PACKET_PUBLICATION | I05 v4 contract adopted (slot 242, parallel lane), after PERF-040 |
| Alpha2A | LICENCE-POLICY-AMEND | WAITING_PACKET_PUBLICATION | LIC-HOST-A2 (Zlib) contract adopted (slot 243, parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
The worker count stays six. No validator's freshness rule changes: every route still reads its authority fresh. The
weights are a ci/ change, which needs the owner's approval of the exact head before verify. No role code, cloud,
runner, live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are
history only.

## Historical compiled filter programs v2 source checkpoint — MET-ENFORCE-029 source preparation, October 16, 2026

Alpha2 OPEN. MET-ENFORCE-028 (SELINUX-MATRIX-I04-KEYCERT, SELinux matrix v5) passed required verify and merged as main
5e83b25. PROGRAMS-REPUBLISH is the second step of the owner's writer-executable-check chain (Q-HE3A-1 (c) and
Q-HE3A-1b (a)): seccomp allowlists v4 (MET-ENFORCE-027) came first, and R10's HE-003A2 re-vendors the programs and adds
the check (Q-HE3D-3 (a)). The lane monitor's owner-delegated Q-PR-1..10 (a) fixed the form: a new directory, only
EFFECT_GATE re-emitted, edge record v3 as v2's 31 rows plus 2, and a status-only adoption.
MET-ENFORCE-029 is the sole 240th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-029 / PROGRAMS-REPUBLISH | SOURCE_PREPARED | Compiled filter programs v2 (240th packet): EFFECT_GATE's two programs republished from seccomp allowlists v4 (v3's programs with one six-instruction readlinkat block), an index of all fourteen and edge record v3 for R10's HE-003A2 (Q-PR-1..10 (a)); contract review round 1, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-028 / SELINUX-MATRIX-I04-KEYCERT | VERIFY_PASSED_MERGED | Merged as main 5e83b25 |
| Alpha2A | I05-OBSERVED-WORKERS | WAITING_PACKET_PUBLICATION | I05 successor taking observedWorkers from the worker cgroup (owner Q-HE3D-2 (a)); ready since MET-ENFORCE-028 merged (parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: MET-ENFORCE-025's programs and publisher, the v1, v2 and EDGE-2 edge records, seccomp allowlists v3 and
v4, the repository registry and the W03 plan v2 stay byte-identical; no filter is installed, no R10 file changes, and no
role code, cloud, runner, live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior
checkpoints below are history only.

## Historical SELinux matrix v5 source checkpoint — MET-ENFORCE-028 source preparation, October 15, 2026

Alpha2 OPEN. MET-PERF-039 (PERF-039, six parallel-suite workers) passed required verify and merged as main 9f251d5. The
lane monitor swapped slots 239 and 240 (2026-10-15): SELINUX-MATRIX-I04-KEYCERT is ready first and does not depend on
PROGRAMS-REPUBLISH. Owner decisions: Q-HE3D-2 (a), the gate's observedWorkers source; Q-MX-2 (b) and Q-MX-3 (b), the
observer takes the native profile's captures and the writer's and gate's /proc readers narrow; and the monitor's
owner-delegated Q-MX-1 (a), Q-MX-4 (a) and Q-MX-5 (a). MET-ENFORCE-028 is the sole 239th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-028 / SELINUX-MATRIX-I04-KEYCERT | SOURCE_PREPARED | SELinux matrix v5 (239th packet): the gate's I04 key and chain/CA types, no gate capability, the gate's worker-cgroup read (Q-HE3D-2 (a)) and the HS43 /proc narrowing (Q-MX-2 (b), Q-MX-3 (b)); four contract review rounds, PASS; packet review; verify |
| Alpha2A | MET-PERF-039 / PERF-039 | VERIFY_PASSED_MERGED | Merged as main 9f251d5 |
| Alpha2A | PROGRAMS-REPUBLISH | WAITING_PACKET_PUBLICATION | The seccomp programs and edge record v3 republished from v4 (primary lane, slot 240) |
| Alpha2A | I05-OBSERVED-WORKERS | BLOCKED | I05 successor taking observedWorkers from the worker cgroup (owner Q-HE3D-2 (a)), after MET-ENFORCE-028 merges (parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the SELinux matrices v3 and v4, HS43, the resolved W01 design and the native profile v3 stay
byte-identical; no policy module is written, compiled or loaded, and no role code, cloud, runner, live/native/tenant or
model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical pytest-headroom source checkpoint — MET-PERF-039 source preparation, October 15, 2026

Alpha2 OPEN. MET-ENFORCE-027 (SECCOMP-V3-READLINKAT, seccomp allowlists v4) passed required verify and merged as main
e751616. Under host load the outer pytest (argv 63) took 901.5 s against the parallel suite's 900 s worker deadline
(the 236th packet's dry run). Measured once each on main e7516160 with four, six and eight workers, it took 627.1 s,
361.0 s and 324.9 s; the four-worker run was slowed by host state, so six workers save about 21-29% under the same
conditions. Owner decision Q-PERF39-1 (a), 2026-10-15, via the lane monitor, confirmed twice: six workers, every
fail-closed rule kept, weights not refreshed (a later ci/ change). MET-PERF-039 is the sole 238th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-039 / PERF-039 | SOURCE_PREPARED | Six parallel-suite workers (238th packet; owner Q-PERF39-1 (a)); source review; packet review; transport approval; verify |
| Alpha2A | MET-ENFORCE-027 / SECCOMP-V3-READLINKAT | VERIFY_PASSED_MERGED | Merged as main e751616 |
| Alpha2A | SELINUX-MATRIX-I04-KEYCERT | WAITING_PACKET_PUBLICATION | The I04 key/cert type, the HS43 matrix obligations and the gate's worker-cgroup read (owner Q-HE3D-2 (a)), after PERF-039 (parallel lane) |
| Alpha2A | I05-OBSERVED-WORKERS | BLOCKED | I05 successor taking observedWorkers from the worker cgroup (owner Q-HE3D-2 (a)), after SELINUX-MATRIX-I04-KEYCERT (parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
A ci/ transport change: only the worker count changes (4 -> 6), with its one live test pin; the 900 s deadline, the
accounting, the parent nodes, the serial rule and the weights stay; every earlier record that states four workers stays
byte-identical. It needs the owner's transport approval on the exact head. No cloud, runner, live/native/tenant or
model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical seccomp-v4 source checkpoint — MET-ENFORCE-027 source preparation, October 15, 2026

Alpha2 OPEN. MET-ENFORCE-026 (HS-4.3-AMEND, amendment HS43 of the W01 host-interface specification) passed required
verify and merged as main 0879eb1. Its obligation O-SECCOMP-V3-READLINKAT asks for the effect gate's readlinkat rule.
Owner decisions: Q-HE3A-1 (c) and Q-HE3A-1b (a), 2026-10-13; HS43-START and the lane monitor's owner-delegated dirfd
direction (arg0 & 0x80000000) == 0, 2026-10-15; and SEC-RL-START, 2026-10-15, which starts SECCOMP-V3-READLINKAT as slot
237 (lane monitor). MET-ENFORCE-027 is the sole 237th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-027 / SECCOMP-V3-READLINKAT | SOURCE_PREPARED | Seccomp allowlists v4: the EFFECT_GATE readlinkat rule for obligation O-SECCOMP-V3-READLINKAT (237th packet); three contract review rounds, PASS; packet review; verify |
| Alpha2A | MET-ENFORCE-026 / HS-4.3-AMEND | VERIFY_PASSED_MERGED | Merged as main 0879eb1 |
| Alpha2A | PERF-039 | WAITING_PACKET_PUBLICATION | Pytest headroom under the 900 s parallel-suite worker deadline (parallel lane), after SECCOMP-V3-READLINKAT |
| Alpha2A | SELINUX-MATRIX-I04-KEYCERT | WAITING_PACKET_PUBLICATION | The I04 key/cert type plus the HS43 matrix obligations, after SECCOMP-V3-READLINKAT |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
DATA_CHECK_ONLY: the seccomp allowlists v1, v2 and v3 and the HS43 amendment stay byte-identical; only EFFECT_GATE's
filter digests change; no filter is installed, the compiled programs and the edge record are not republished (the
primary lane does that from v4), and no role code, matrix, profile, cloud, runner, live/native/tenant or model-effort
change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical host-interface-hs43 source checkpoint — MET-ENFORCE-026 source preparation, October 15, 2026

Alpha2 OPEN. MET-ADOPT-004 (RA-LICENSE-001, research adoption v3) passed required verify and merged as main 8665a9b.
Owner decisions (via the lane monitor): Q-HE2S-10 (a), 2026-10-13, the effect gate qualifies the broker by label,
cgroup, pidfd and SO_PEERCRED; Q-HE3A-1 (c) and Q-HE3A-1b (a), the gate checks the I07 writer's executable through its
/proc exe link once the seccomp chain lands; Q-HE2S-7 (a) and Q-HE2S-9 (a), the gate stays dumpable and holds no
capability; and, 2026-10-15, HS-4.3-AMEND as slot 236 with readlinkat only for a dirfd other than AT_FDCWD (adopted as a
non-negative dirfd, which also refuses -1), Q-HS43-1 (a) (pidfd/start kept), and the monitor's owner-delegated Q-HS43-2
(a) (a closed, model-checked list of overridden clauses) and Q-HS43-3 (a) (stated residuals with matrix obligations).
MET-ENFORCE-026 is the sole 236th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-026 / HS-4.3-AMEND | SOURCE_PREPARED | Amendment HS43 of the W01 host-interface specification (236th packet); four contract review rounds, PASS; packet review; verify |
| Alpha2A | MET-ADOPT-004 / RA-LICENSE-001 | VERIFY_PASSED_MERGED | Merged as main 8665a9b |
| Alpha2A | SECCOMP-V3-READLINKAT | WAITING_PACKET_PUBLICATION | The EFFECT_GATE readlinkat rule (obligation O-SECCOMP-V3-READLINKAT), parallel lane, next |
| Alpha2A | SELINUX-MATRIX-I04-KEYCERT | WAITING_PACKET_PUBLICATION | The I04 key/cert type plus the HS43 matrix obligations, after SECCOMP-V3-READLINKAT |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the new layer validator adds no argv and runs inside the outer pytest) and 32 MiB.
Specification only: the W02D effective text, the W01 inputs and every file whose clauses HS43 overrides stay
byte-identical; no allowlist, matrix, profile, filter, role code, cloud, runner, live/native/tenant or model-effort
change. Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical research-adoption-v3 source checkpoint — MET-ADOPT-004 source preparation, October 15, 2026

Alpha2 OPEN. MET-PERF-038 (load-tolerant deadlines for verifier bundle v4) passed required verify and merged as main
0d776f7. Owner decisions (via the lane monitor, 2026-10-14): Q-HO4-2 (a), a small data-only licence-clarification item
(RA-LICENSE-001) for litellm, pgvector, langfuse and phoenix; Q-HO4-3, the 29 planned baselines' recheck folded into it
("Fold into RA-LICENSE-001"); Q-HO4-4 (a), no re-rating; Q-RL-AB and Q-RL-C, the exact approved reads (with the user's
chat permission); Q-RL-LAYOUT, research adoption v3 (architecture/research-adoption-v3/) as a successor revision beside
the byte-identical 2026-09 record, its map and the v2 crosswalk. MET-ADOPT-004 is the sole 235th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ADOPT-004 / RA-LICENSE-001 | SOURCE_PREPARED | Licence clarification (litellm, pgvector, langfuse, phoenix) and the 29-baseline recheck (235th packet); review; verify |
| Alpha2A | MET-PERF-038 | VERIFY_PASSED_MERGED | Merged as main 0d776f7 |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest) and 32 MiB. Data only: the licence texts stay
operator-side and the records carry their git blob ids and SHA-256 digests; no policy, catalog, rating, cloud, runner
registration, live/native/tenant or model-effort change. Phase-end effort transition NOT_DUE. Prior checkpoints below are
history only.

## Historical load-deadlines source checkpoint — MET-PERF-038 source preparation, October 14, 2026

Alpha2 OPEN. MET-MAS-003 (MAS-RA-003) passed required verify and merged as main 5cf7fae, after two earlier verifies of it
failed on host load (the parallel suite's 600 s worker deadline killed a worker). Owner decisions (via the lane monitor,
2026-10-14): Q-PERF-DL, verifier bundle v4 (a load gate before the run and a 1200 s launcher cap, installed by the owner)
plus this packet; Q-ORDER-187, MET-MAS-003 first, this packet re-based as the 234th; Q-DL1 (a), the parallel-suite worker
deadline 600 -> 900 s and the nested predecessor bound 420 -> 600 s; Q-DL2 (a), every earlier record stating 420/900/15
stays byte-identical, with a successor limits record (architecture/load-deadlines/); Q-DL3 (a) as amended by Q-DL3-B (b),
the workflow timeout stays 15 min (the app verifier never runs in that job) and the Linux runner launcher's 900 s bound is
left alone. MET-PERF-038 is the sole 234th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-038 | SOURCE_PREPARED | Load-tolerant deadlines for bundle v4 (234th packet); transport approval; verify |
| Alpha2A | MET-MAS-003 / MAS-RA-003 | VERIFY_PASSED_MERGED | Merged as main 5cf7fae |
| Alpha2A | W03 | IN_PROGRESS | R10 enforcement packets (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 test source (parallel lane); W04-4b, W04-4c and W04-5 stopped pending a human author or a later decision |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PACKET_PUBLICATION | Consumers of MAS-RA-003, now merged |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest) and 32 MiB. The limits move to a 900 s parallel-suite
worker deadline and a 600 s nested predecessor bound under bundle v4's 1200 s cap; the 15 min workflow timeout and the
Linux runner launcher's 900 s bound stay. No cloud, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical MAS-RA-003 source checkpoint — MET-MAS-003 source preparation, October 14, 2026

Alpha2 OPEN. MET-ENFORCE-025 (the compiled seccomp programs, edge records v2 and W03-PLAN-AMEND-1) passed required verify
and merged as main 5da1265. Owner decisions (via the lane monitor, 2026-10-14): Q-233 (a), MAS-RA-003 as slot 233 in the
primary lane; Q-MAS3-A (a) an internal candidate with H15's, H16's and H10's documents unchanged; Q-MAS3-B (a) RunEvent as
the canonical envelope with a deterministic derivation from loop traces; Q-MAS3-C (a) payloads by reference only;
Q-MAS3-D (D-a) the OTel GenAI conventions pinned at semantic-conventions-genai commit 4e8a2812; Q-MAS3-E (a) exact integer
rationals; Q-MAS3-F (a), as corrected, the MAST paper's vocabulary cited by page. MET-MAS-003 publishes the contract after
three independent review rounds. MET-MAS-003 is the sole 233rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-MAS-003 / MAS-RA-003 | SOURCE_PREPARED | Run-event, OTel GenAI mapping and MAS metrics contract as the 233rd packet; verify |
| Alpha2A | MET-ENFORCE-025 | VERIFY_PASSED_MERGED | Merged as main 5da1265 |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000 to HE-002S merged; HE-003 split into A to D, HE-003A (effect gate channels) in build (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packet |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | MAS-RA-004, MAS-RA-006 | WAITING_PREREQUISITES | Consumers of MAS-RA-003 |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W03 source checkpoint — MET-ENFORCE-025 source preparation, October 14, 2026

Alpha2 OPEN. MET-MAS-006 (MAS-RA-008) passed required verify and merged as main 6e7bfb3. Owner decisions (via the lane
monitor, 2026-10-13): Q-HE2S-1 (a), a harness-onion meta packet publishes the compiled seccomp programs as data, its layer
recompiling them with the pinned v3 compiler; Q-HE2S-2 (a), all seven roles on both architectures, with edge registry
record v2, EDGE-2 (A13) and W03-PLAN-AMEND-1 (Q-HE2B-2 (a) and the amendment scope); slot 232, after MET-MAS-006.
MET-ENFORCE-025 publishes them after four independent review rounds. MET-ENFORCE-025 is the sole 232nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-025 | SOURCE_PREPARED | Compiled seccomp programs, edge records v2 and W03-PLAN-AMEND-1 as the 232nd packet; verify |
| Alpha2A | MET-MAS-006 / MAS-RA-008 | VERIFY_PASSED_MERGED | Merged as main 6e7bfb3 |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000 to HE-002C merged; HE-002S (the EFFECT_GATE process seal) reviewed, merges after this packet (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-003, MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packets |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical MAS-RA-008 source checkpoint — MET-MAS-006 source preparation, October 13, 2026

Alpha2 OPEN. MET-MAS-002 (MAS-RA-002) passed required verify and merged as main 82804a0. Owner decisions (via the lane
monitor, 2026-10-13): Q-231 (a), slot 231 is MAS-RA-008, built by the primary lane; Q-MAS8-A (a), an internal contract
candidate with H10's and H11's harness documents and the repository schemas unchanged; Q-MAS8-B (a), recursion depth at
most 1 with no override; Q-MAS8-C (a), a failing step retried at most once by default and at most 3 times, with its error
trace fed back, then a human hand-off, and artefact revision rounds a separate budget of at most 3; Q-MAS8-D (a), a
per-call capability-token reference bound by digest to H11's grant, with no key material. MET-MAS-006 publishes the
agent-loop kernel and tool-gateway contract candidate after ten independent review rounds. MET-MAS-006 is the sole 231st
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-MAS-006 / MAS-RA-008 | SOURCE_PREPARED | Agent-loop kernel and tool-gateway contract as the 231st packet; verify |
| Alpha2A | MET-MAS-002 / MAS-RA-002 | VERIFY_PASSED_MERGED | Merged as main 82804a0 |
| Alpha2A | MET-ENFORCE-025 | WAITING_PACKET_PUBLICATION | Compiled seccomp programs, edge registry record v2 and W03-PLAN-AMEND-1 (slot 232, after this packet) |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000 to HE-002C merged; HE-002S (the EFFECT_GATE process seal) merges after MET-ENFORCE-025 (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-003, MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packets |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical MAS-RA-002 source checkpoint — MET-MAS-002 source preparation, October 13, 2026

Alpha2 OPEN. MET-MAS-001 (MAS-RA-001) passed required verify and merged as main c0f535b. Owner decisions (via the lane
monitor, 2026-10-13): Q-230 (a), slot 230 is MAS-RA-002, built by the primary lane; Q-MAS2-A (a), an internal contract
candidate with H16's harness document and the repository schemas unchanged; Q-MAS2-B (a), a paired, task-clustered 95%
interval over k >= 3 repetitions per task against a versioned tolerance, in integer arithmetic; Q-MAS2-C (a), split
declarations digested before the first run and held-out scores refused as selection input; Q-MAS2-D (a), budget caps in
the configuration tuple, tokens and cost beside the score. MET-MAS-002 publishes the run manifest and configuration-level
evaluation record contract candidate after four independent review rounds. MET-MAS-002 is the sole 230th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-MAS-002 / MAS-RA-002 | SOURCE_PREPARED | Run manifest and evaluation record contract as the 230th packet; verify |
| Alpha2A | MET-MAS-001 / MAS-RA-001 | VERIFY_PASSED_MERGED | Merged as main c0f535b |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000 to HE-002B merged; HE-002C (durable journal) design passed, build next (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-003, MAS-RA-008, MAS-RA-009 | WAITING_PACKET_PUBLICATION | Proposed contract packets |
| Alpha2A | MAS-RA-005 | WAITING_PACKET_PUBLICATION | Ready when this packet merges (MAS-RA-001 and MAS-RA-002 both done) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical MAS-RA-001 source checkpoint — MET-MAS-001 source preparation, October 13, 2026

Alpha2 OPEN. MET-ADOPT-003 (MAS-RA-000) passed required verify and merged as main 8d10a9d. Owner decisions (via the lane
monitor, 2026-10-13): Q-229 (a), slot 229 is MAS-RA-001, built by the primary lane; Q-MAS1-A (a), a ledger's UNRESOLVED
maps to H16 WARN and stays its own value; Q-MAS1-B (a), an internal contract candidate with no change to H16's harness
document or the repository schemas; Q-MAS1-C (a), the producing context's identity and role are modelled and signing stays
with H16's signer. MET-MAS-001 publishes the verdict and evidence ledger contract candidate
planeon.internal.verdict-ledger/v1 (schema, check-kind registry, standard-library reference model and vectors) after five
independent review rounds. MET-MAS-001 is the sole 229th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-MAS-001 / MAS-RA-001 | SOURCE_PREPARED | Verdict and evidence ledger contract as the 229th packet; verify |
| Alpha2A | MET-ADOPT-003 / MAS-RA-000 | VERIFY_PASSED_MERGED | Merged as main 8d10a9d |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000 to HE-002 merged; HE-002B (I07 PolicyGate) prepared (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-002, MAS-RA-003, MAS-RA-008 | WAITING_PACKET_PUBLICATION | Proposed contract packets |
| Alpha2A | MAS-RA-009 | WAITING_PACKET_PUBLICATION | Ready when this packet merges (verify-before-admit on the shared board) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical MAS-RA-000 source checkpoint — MET-ADOPT-003 source preparation, October 13, 2026

Alpha2 OPEN. MET-ENFORCE-024 (W03-AMEND) passed required verify and merged as main 93d32e1. Owner decisions (via the lane
monitor, 2026-10-12): Q-RA1 (a), one unauthenticated read-only re-check of the 41 named repositories, and Q-RA2 (a),
research inputs referenced by sha256 only with the grounding embedded as derived data; handover decision HO-D3 assigns
slot 228 to MAS-RA-000. MET-ADOPT-003 publishes the research adoption v2 crosswalk (three syntheses, eight seed papers
read in full, eleven secondary papers, five standards, 47 codebase records with 41 repositories re-checked and 40 pinned
to a commit, the eight layers, the sixteen harnesses and the MAS-RA-001..010 acceptance IDs) beside the byte-identical research-adoption.json and harness paper map,
after four independent review rounds. MET-ADOPT-003 is the sole 228th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ADOPT-003 / MAS-RA-000 | SOURCE_PREPARED | Research adoption v2 crosswalk as the 228th packet; verify |
| Alpha2A | MET-ENFORCE-024 / W03-AMEND | VERIFY_PASSED_MERGED | Merged as main 93d32e1 |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000, HE-000B and HE-001 merged; HE-002 (I05 logic) in PR review (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | MAS-RA-001, MAS-RA-002, MAS-RA-003, MAS-RA-008 | WAITING_PACKET_PUBLICATION | Ready when this packet merges; proposed contract packets |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W03-AMEND source checkpoint — MET-ENFORCE-024 source preparation, October 11, 2026

Alpha2 OPEN. MET-PERF-037 (PERF-035-F) passed required verify under the owner's transport approval and merged as main
a2eab93. Owner decisions (via the lane monitor, 2026-10-11): the seven HE-002 questions Q-HE2-A to Q-HE2-G, all as
recommended, and slot 227 for W03-AMEND. MET-ENFORCE-024 publishes the W03 plan v2 beside the byte-identical v1 (the HE-002
split into HE-002, HE-002B and HE-002C, the I05 and I07 channel substrate in HE-003, the gate's single journal in HE-002C,
the new HE-002S), the operator -> harness-engineering buildArtifact edge registry record (HE-000's transport files and
HE-002's contract files) and the supplementary I05 v3 vectors that close AF2-I05-1. MET-ENFORCE-024 is the sole 227th
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-024 / W03-AMEND | SOURCE_PREPARED | W03 plan v2, edge record and supplementary vectors as the 227th packet; verify |
| Alpha2 | MET-PERF-037 / PERF-035-F | VERIFY_PASSED_MERGED | Owner transport approval; merged as main a2eab93 |
| Alpha2A | W03 | IN_PROGRESS | R10: HE-000, HE-000B and HE-001 merged; HE-002 (I05 logic) built locally, merges after this packet (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | R12 suite migration and test source (parallel lane) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-035-F source checkpoint — MET-PERF-037 source preparation, October 11, 2026

Alpha2 OPEN. MET-ENFORCE-023 (W02-CLEANUP) passed required verify (64/64, 459 s) and merged as main 6f813b7. Owner
decisions (via the lane monitor): Q-N1 = A (R12 CONF-CI-002 suite migration first, then W04-1 test source) and Q-N2
(slot 226 = PERF-035-F). MET-PERF-037 closes the MET-PERF-035 review's carried MINOR findings R3-01 and R3-02 in the
parallel suite, a pinned transport file, under the owner's transport approval. MET-PERF-037 is the sole 226th
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-037 / PERF-035-F | SOURCE_PREPARED | Parallel-suite follow-up as the 226th packet; owner transport approval, then verify |
| Alpha2A | MET-ENFORCE-023 / W02-CLEANUP | VERIFY_PASSED_MERGED | Verify 459 s |
| Alpha2A | W04 | IN_PROGRESS | R12 CONF-CI-002 suite migration (W04-1a), then W04-1 test source (parallel lane) |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane) |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after LIC-HOST and W05 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02-CLEANUP source checkpoint — MET-ENFORCE-023 source preparation, October 11, 2026

Alpha2 OPEN. MET-ENFORCE-022 (W04-0) passed required verify (64/64, 441 s) and merged as main 4cb4510. R12 adopted the
repository-aware verifier (CONF-CI-001, R12 #21) and R10 its bootstrap. Owner rule (via the lane monitor): slot 225 is
W02-CLEANUP. MET-ENFORCE-023 publishes the W02 notes errata for native-profile-v3 and I06 v2 and the PERF-032-F checks
(owner decisions Q-S = A, Q-F = A, round 6 final; independent review round 6, PASS_FOR_SOURCE_PUBLICATION).
DATA_CHECK_ONLY. MET-ENFORCE-023 is the sole 225th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-023 / W02-CLEANUP | SOURCE_PREPARED | W02 notes errata as the 225th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-022 / W04-0 | VERIFY_PASSED_MERGED | Verify 441 s |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after LIC-HOST and W05 |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests in R12 (parallel lane); W04-1 migrates R12's suites to the verifier contract |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W04-0 source checkpoint — MET-ENFORCE-022 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-021 (LIC-HOST) passed required verify (64/64, 490 s, the first run of the repository-aware v4
verifier) and merged as main a5a0625. Owner rule (via the lane monitor): slot 224 is W04-0. MET-ENFORCE-022 publishes the
independent enforcement test plan W04-0 (owner decisions D-R12, D-TOOL, D-MAP, D-OW, D-ID and D-OW-1 = A; independent
review round 4, PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-022 is the sole 224th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-022 / W04-0 | SOURCE_PREPARED | Enforcement test plan as the 224th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-021 / LIC-HOST | VERIFY_PASSED_MERGED | Verify 490 s (first v4 run) |
| Alpha2A | VERIFIER-EXT | INSTALLED | Repository-aware verifier v4 for harness-onion, R10 and R12; bootstrap PRs next |
| Alpha2A | W02-CLEANUP | IN_REVIEW | Errata for W02a-F2, W02g-F2 and PERF-032-F (parallel lane), after W04-0 |
| Alpha2A | W02-PROD | BLOCKED | Production backend profile and the I06 successor (primary lane), after LIC-HOST and W05 |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane) |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window register (parallel lane); W04-1 to W04-6 in R12 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical LIC-HOST source checkpoint — MET-ENFORCE-021 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-020 (W02d-V3) passed required verify (64/64, 408 s) and merged as main 5fab673. Owner rule
(via the lane monitor): slot 223 is LIC-HOST. MET-ENFORCE-021 publishes license-policy amendment LIC-HOST-A1 (owner
decisions Q-L, Q-L2, Q-L3) as a reviewed overlay on the byte-identical base policy (independent review round 4,
PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-021 is the sole 223rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-021 / LIC-HOST | SOURCE_PREPARED | License-policy amendment as the 223rd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-020 / W02d-V3 | VERIFY_PASSED_MERGED | Verify 408 s |
| Alpha2A | VERIFIER-EXT | IN_REVIEW | One repository-aware verifier for R10 and R12 (owner root bundle) |
| Alpha2A | W02a-F2, W02g-F2 | PLANNED | Production backend profile and the I06 successor |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane) |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02d-V3 source checkpoint — MET-ENFORCE-020 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-019 (W03-0) passed required verify (64/64, 503 s under Docker load) and merged as main 0e74704.
Owner decision (via the lane monitor): slot 222 is W02d-V3. MET-ENFORCE-020 publishes the W02d successor seccomp
allowlists v3: owner decision W02d-V3 adds three narrow NATIVE_STATIC rules for the Rust+musl native roles (independent
review round 2, PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-020 is the sole 222nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-020 / W02d-V3 | SOURCE_PREPARED | Seccomp allowlists v3 as the 222nd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-019 / W03-0 | VERIFY_PASSED_MERGED | Verify 503 s |
| Alpha2A | LIC-HOST, W02a-F2, W02g-F2 | IN_PROGRESS_OR_PLANNED | License-policy amendment (slot 223); production backend profile |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane); W04-0 review-PASS, slot 224 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W03-0 source checkpoint — MET-ENFORCE-019 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-018 (W01-AMEND) passed required verify (64/64, 490 s) and merged as main 195c4c9. Owner rule
(via the lane monitor): slot 221 goes to the first review-PASS contract packet. MET-ENFORCE-019 is W03-0: the W03 backend
distribution selection (an upstream v1.37.1 component set from sealed files) and the W03 plan (independent review round 5,
PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-019 is the sole 221st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-019 / W03-0 | SOURCE_PREPARED | Backend distribution selection and W03 plan as the 221st packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-018 / W01-AMEND | VERIFY_PASSED_MERGED | Verify 490 s |
| Alpha2A | LIC-HOST, W02d v3, W02a-F2, W02g-F2 | IN_PROGRESS_OR_PLANNED | License-policy amendment; steady-state seccomp rules; production backend profile |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane), from the W03-0 selection |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W01-AMEND source checkpoint — MET-ENFORCE-018 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-017 (W02d) passed required verify (64/64, 376 s, the first under the Interactive verifier
ProcessType) and merged as main b8ce77b. Owner decision (via the lane monitor): the parallel lane takes W01-AMEND, the
primary lane W03. MET-ENFORCE-018 publishes W01 amendment W02D (W02d's carried items; owner decisions W01-AMEND-QW1 to
QW4) and the W02d successor seccomp-allowlists-v2 (independent review round 4, PASS_FOR_SOURCE_PUBLICATION).
DATA_CHECK_ONLY. MET-ENFORCE-018 is the sole 220th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-018 / W01-AMEND | SOURCE_PREPARED | W01 amendment W02D and seccomp allowlists v2 as the 220th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-017 / W02d | VERIFY_PASSED_MERGED | Verify 376 s |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane) |
| Alpha2A | W04 | WAITING_W03_DISTRIBUTION | Independent enforcement tests and observation-window map (parallel lane, after W03 picks the distribution) |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02d source checkpoint — MET-ENFORCE-017 source preparation, October 10, 2026

Alpha2 OPEN. MET-SECTOR-002 (CATALOG-BANK) passed required verify (64/64, 415 s) and merged as main 984c953. Owner
decision (via the lane monitor): W02d takes slot 219. MET-ENFORCE-017 publishes the W02d per-role, per-architecture
seccomp allowlists for the seven roles at Linux v6.12 (independent review round 3, PASS_FOR_SOURCE_PUBLICATION), with the
reference compiler's filter digests. DATA_CHECK_ONLY. MET-ENFORCE-017 is the sole 219th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-017 / W02d | SOURCE_PREPARED | Seccomp allowlists as the 219th packet; verify from the owner's App |
| Alpha2 | MET-SECTOR-002 / CATALOG-BANK | VERIFY_PASSED_MERGED | Verify 415 s |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02a-F2, W02g-F2, W01 amendments from W02d | WAITING_EXACT_PACKETS | follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical CATALOG-BANK source checkpoint — MET-SECTOR-002 source preparation, October 9, 2026

Alpha2 OPEN. MET-PERF-036 (PERF-SEL) passed required verify (64/64, 399 s) and merged as main da81730. Owner rule
(via the lane monitor): slot 218 goes to the first contract packet that passes review. MET-SECTOR-002 is CATALOG-BANK:
the SECTOR-D1 catalog follow-ups as a reviewed overlay (independent review round 4, PASS_FOR_SOURCE_PUBLICATION). The
catalogs stay byte-identical, and banking-era consumers read them through `scripts/sector_catalog.py`. MET-SECTOR-002
is the sole 218th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-SECTOR-002 / CATALOG-BANK | SOURCE_PREPARED | Sector catalog overlay as the 218th packet; verify from the owner's App |
| Alpha2 | MET-PERF-036 / PERF-SEL | VERIFY_PASSED_MERGED | Verify 399 s |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-SEL source checkpoint — MET-PERF-036 source preparation, October 9, 2026

Alpha2 OPEN. MET-PERF-035 (PERF-035) passed required verify (64/64, 590 s) and merged as main
1d107e4. MET-PERF-036 is PERF-SEL (owner decision via the lane monitor): the two SELinux matrix
layer test files replay the matrix inside validate() (the v3 file once more for one weakening
case) instead of three to five times, and their weakening tests call the exact per-row conjunct
of the unchanged replay. No validator
refusal changes and nothing is cached. MET-PERF-036 is the sole 217th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-036 / PERF-SEL | SOURCE_PREPARED | SELinux replays inside validate() instead of three to five times per layer test file, as the 217th packet; verify from the owner's App |
| Alpha2 | MET-PERF-035 / PERF-035 | VERIFY_PASSED_MERGED | Verify 590 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-035 source checkpoint — MET-PERF-035 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-016 (W02e-F) passed required verify on a quiet re-run (64/64, 784 s; the first run
timed out at 902 s) and merged as main 58e6c25, past the 750 s PERF floor. Owner decisions (via the lane monitor):
MET-PERF-035 is the 216th packet. It runs the outer suite on 4 fail-closed worker processes inside the unchanged
acceptance argv and includes the reviewed suite-reuse cuts. Validators, authorities and freshness are unchanged.
MET-PERF-035 is the sole 216th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-035 / PERF-035 | SOURCE_PREPARED | Parallel suite and suite reuse as the 216th packet; owner transport approval (ci/) and verify from the owner's App |
| Alpha2A | MET-ENFORCE-016 / W02e-F | VERIFY_PASSED_MERGED | Verify 784 s (quiet re-run) |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02e-F source checkpoint — MET-ENFORCE-016 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-015 (W02-ADM-F) passed required verify (64/64, 731 s) and merged as main
4196dae. The owner put W02e-F ahead of the PERF packet, which is mandatory next because this
packet's verify is expected to cross the 750 s floor. MET-ENFORCE-016 is W02e-F. The adopted v3
SELinux matrix is frozen, so it publishes the successor `planeon.internal.selinux-matrix/v4`:
- one `/proc` assertion per planeon target with exactly that target's peers (K2);
- A66: no domain loads policy before the seal (K3);
- the cgroup2 labelling text corrected and S11 checked against the slice type (K4); the review
  brief's count (K6).

Review round 2 passed (PASS_FOR_SOURCE_PUBLICATION; one NOTE carried). Nothing is written or
loaded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-016 is the sole 215th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-016 / W02e-F | SOURCE_PREPARED | SELinux matrix v4 as the 215th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-015 / W02-ADM-F | VERIFY_PASSED_MERGED | Verify 731 s |
| Alpha2 | PERF-035 | NEXT_MANDATORY | The 216th packet; verify headroom below the 150 s floor |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02-ADM-F source checkpoint — MET-ENFORCE-015 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-014 (W02c-F) passed required verify (64/64, 692 s) and merged as
main f88e7f7. PERF-035 was not shipped; the owner lifted the PERF gate with a floor (a PERF
packet becomes mandatory once a verify leaves under 150 s of headroom). MET-ENFORCE-015 is
W02-ADM-F, which folds W02b-F2, W02f-F and W02c-F2 into one packet with three successor
contracts under one combined independent review:
- I05 v3 (`planeon.internal.effect-gate-frame/v3`): the upstream exchange is bounded, a finer
  failure injection pins the drain and deny failure paths, and the residual is stated exactly;
- POLICY-ADMISSION-SEMANTICS/v3: MC39-MC41, modelled env and volume defaults, new A1 and A2
  claim evidence; the sealed A2 manifest file is unchanged;
- I07 v3 (`planeon.internal.policy-write-frame/v3`): on the I05 v3 gate, four more response
  constraints, the write timeout as an abort, no cluster scope.

Review rounds 1 and 2 passed (PASS_FOR_SOURCE_PUBLICATION; findings carried, none blocking).
Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-015 is the sole
214th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-015 / W02-ADM-F | SOURCE_PREPARED | Three successor contracts as the 214th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-014 / W02c-F | VERIFY_PASSED_MERGED | Verify 692 s |
| Alpha2 | PERF-035 | PROFILING | Mandatory once a verify leaves under 150 s of headroom |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02e-F, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02c-F source checkpoint — MET-ENFORCE-014 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-013 (W02f) passed required verify (64/64, 789 s) and merged as main
c1a6784. MET-PERF-033 was dropped after its review. MET-ENFORCE-014 is the W02c-F part. The
adopted I07 v1 writer channel is frozen, so it publishes the successor
`planeon.internal.policy-write-frame/v2`:
- the I07 model extends the I05 v2 gate: maintenance follows its fence after every event, and a
  generation rebuilt after a restart never opens a maintenance;
- ValidatingAdmissionPolicy and its binding are sealed per W02f (ADMISSION_OBJECT_SEALED);
- a write's upstream outcome is its own event, an abort is recorded before the session or
  maintenance ends, a late outcome is never relayed, and lockstep is enforced;
- conditional response constraints, defined request digests and observed fields, and the
  317-character key bound.

It passed its independent review in round 1 (PASS_FOR_SOURCE_PUBLICATION; findings carried,
none blocking). Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-014
is the sole 213th specification. PERF-035 follows before further contract packets.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-014 / W02c-F | SOURCE_PREPARED | I07 policy writer channel v2 as the 213th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-013 / W02f | VERIFY_PASSED_MERGED | Verify 789 s |
| Alpha2 | PERF-035 | NEXT | Structural verify-time cut before further contract packets |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02e-F, W02a-F2, W02b-F2, W02g-F2, W02f-F, W02c-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02f source checkpoint — MET-ENFORCE-013 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-012 (W02g-F) passed required verify (64/64, 662 s) and merged as main
4f75ded. MET-ENFORCE-013 is the W02f part. It carries the W01 G05 amendment into its owning
contract as POLICY-ADMISSION-SEMANTICS/v2 and fixes the A2 allowlists:
- the v1 pre-commit sentence is pinned and met by no boundary; A1-A3 are named checks at named
  positions and A4 is explicitly weaker;
- owner decision: the A2 ValidatingAdmissionPolicy objects live in a sealed static admission
  manifest directory, run-independent, not written through I07;
- per-kind allowlists for Pod, immutable ConfigMap and ClusterIP Service from Kubernetes v1.37.1,
  manifest constraints, a Pod shape echo, the root-CA publisher's ConfigMap admitted exactly, and
  a guard that denies API writes of admission policies, bindings and webhook configurations.

It passed its independent review in round 2 (PASS_FOR_SOURCE_PUBLICATION; findings carried, none
blocking). Nothing is installed or compiled; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-013 is
the sole 212th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-013 / W02f | SOURCE_PREPARED | POLICY-ADMISSION-SEMANTICS/v2 and A2 allowlists as the 212th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-012 / W02g-F | VERIFY_PASSED_MERGED | Verify 662 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02c-F, W02e-F, W02a-F2, W02b-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02g-F source checkpoint — MET-ENFORCE-012 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-011 (W02b-F) passed required verify (64/64, 686 s) and merged as main
487eca6. MET-ENFORCE-012 is the W02g-F part. The adopted W02g I06 profile is frozen by later
layers, so it publishes the successor I06 backend profile v2, closing the findings carried to
W02g-F:
- a distribution evidence record names one W02a v3 record by its qualification digest, and W02a
  v3's check_record must accept that record; a test-only backend qualifies only in an explicit
  fixture call, so no production evidence exists until W03 adds a reviewed production profile;
- no resource rule of any kind on the loopback user system:apiserver;
- shared or nested backend cgroups refused through W02a's rules, and I06's own code distinctness
  rule kept because W02a allows shared backend code.

It passed its independent review in round 3 (PASS_FOR_SOURCE_PUBLICATION; notes carried, none
blocking). Nothing is observed or selected; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-012 is
the sole 211th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-012 / W02g-F | SOURCE_PREPARED | I06 backend profile v2 as the 211th packet; verify from the owner's App on a quiet host |
| Alpha2A | MET-ENFORCE-011 / W02b-F | VERIFY_PASSED_MERGED | Verify 686 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02c-F, W02e-F, W02a-F2, W02b-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02b-F source checkpoint — MET-ENFORCE-011 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-010 (W02a-F) passed required verify (64/64, 903 s under host load; a
quiet-host dry run of the same tree took 602 s) and merged as main a29c93c. MET-ENFORCE-011 is
the W02b-F part. The adopted v1 I05 channel is frozen, so it publishes the successor
`planeon.internal.effect-gate-frame/v2`, closing every finding carried to W02b-F:
- the I07 drain answered from the A3 fence in every state, including after an urgent close,
  a refused seal or a fatal channel failure;
- DELETE only with a UID from this execution's own CREATE 201; a manifest digest or identity
  belongs to one run across runs and generations;
- every denied action reported, also when a storage failure denied it;
- a failure marker on a separate failure domain and torn-record detection, so a restart after
  an unrecorded write failure is HELD (double-fault residual stated);
- the 408 agreement rows, pinned Kubernetes v1.37.1 sources and decode codes.

It passed its independent review in round 1 (PASS_FOR_SOURCE_PUBLICATION; notes carried, none
blocking). Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-011 is
the sole 210th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-011 / W02b-F | SOURCE_PREPARED | I05 broker-gate channel v2 as the 210th packet; verify from the owner's App on a quiet host |
| Alpha2A | MET-ENFORCE-010 / W02a-F | VERIFY_PASSED_MERGED | Verify 903 s under load; 602 s quiet-host dry run |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02c-F, W02e-F, W02g-F, W02a-F2 | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02a-F source checkpoint — MET-ENFORCE-010 source preparation, October 8, 2026

Alpha2 OPEN. MET-PERF-032 passed required verify (64/64, 564 s, down from 692 s) and merged as
main 51440c8. MET-ENFORCE-010 is the W02a-F part. The adopted v2 record is frozen, so it
publishes the successor `planeon.internal.native-qualification/v3`, closing every finding
carried to W02a-F:
- code identity: closures without another role's executable or the interpreter tree for
  native-only roles; observed running images; one file per inode;
- the slice census against the role captures and `nr_descendants`; the slice's own members;
  thread counts against `pids.current` and `pids.max`;
- the test-only fixture profile, unnested backend cgroups and backend identities bound to
  the W02g closure;
- W02e's label constants, the E1 effective-program census over the 22 other cgroup attach
  types of Linux v6.12, and the K1 boot-entry discriminator;
- migration against the complete v1 and v2 histories.

It passed its independent review in round 6 (PASS_FOR_SOURCE_PUBLICATION; findings carried, none
blocking). Nothing is observed or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-010
is the sole 209th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-010 / W02a-F | SOURCE_PREPARED | Native qualification record v3 as the 209th packet; verify from the owner's App |
| Alpha2 | MET-PERF-032 / PERF-032 | VERIFY_PASSED_MERGED | Verify 564 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-032 source checkpoint — MET-PERF-032 source preparation, October 7, 2026

Alpha2 OPEN. MET-SECTOR-001 passed required verify (64/64, 692 s) and merged as main
8f77c3f; SECTOR-D1 is recorded. Verify has grown 545, 554, 639 and 692 s over packets 204-207,
against the 900 s cap. MET-PERF-032 comes before the remaining W02 and banking packets. A
per-test profile of the 206-packet suite (Mac pytest 495 s) found the cost spread over the
history chain, with four repeats that the checks do not need:
- each layer's route test computed every route's input for every route (36 s, quadratic in
  the number of layers); each route now computes only its own;
- each native-profile status mutation replayed all contract vectors (14 s); it now stubs only
  that pure replay after a passing control, and the replay keeps its own full test;
- the credential-lifecycle inventory builder re-projected the same inputs per case (15 s); it
  now projects each exact input set once per module;
- the readiness validator compared every pair of 3,868 objects for uniqueItems (4.2 s, three
  runs per verify); `scripts/schema_unique.py` compares only items with an equal key and
  gives jsonschema's answer wherever jsonschema returns one, apart from inputs within one
  stack frame of the recursion limit.

No validator caches a projection or verdict, and every refusal is unchanged, with that same
uniqueItems caveat. MET-PERF-032 is the sole 208th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-032 / PERF-032 | SOURCE_PREPARED | Verify headroom as the 208th packet; verify from the owner's App |
| Alpha2 | MET-SECTOR-001 / SECTOR-D1 | VERIFY_PASSED_MERGED | Banking sector direction recorded |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical SECTOR-001 source checkpoint — MET-SECTOR-001 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-009 passed required verify (64/64, 639 s) and merged as main
2c14e51; W02e is ADOPTED_DATA_CONTRACT. MET-SECTOR-001 records owner decision SECTOR-D1:
banking replaces white goods as the first and only release sector from Alpha 2 through the
first enterprise release. It publishes:
- the decision record `planeon.internal.sector-direction/v1`, with a disposition for each of the
  28 published packets that name white goods, recomputed by its validator;
- nine unpublished proposals: successors IND-BANK-001 to IND-BANK-005 and CONF-BANK-001, and the
  banking inputs KN-BANK-001, CTRL-BANK-001 and DIST-BANK-001;
- CONF-A2-001 and CONF-WG-001 retargeted to banking with their IDs kept (each needs a revision
  amendment before dispatch), retained accepted edges, and exhaustive catalog follow-ups.

No published packet, catalog, pack, fixture or backlog snapshot changes, and nothing is built or
qualified. MET-SECTOR-001 is the sole 207th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-SECTOR-001 / SECTOR-D1 | SOURCE_PREPARED | Banking sector direction as the 207th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-009 / W02e | VERIFY_PASSED_MERGED | SELinux matrix, ADOPTED_DATA_CONTRACT |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-009 source checkpoint — MET-ENFORCE-009 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-008 passed required verify (64/64, 554 s) and merged as main
f4edb9a; W02c is ADOPTED_DATA_CONTRACT. MET-ENFORCE-009 is the W02e part. It publishes the
closed SELinux matrix `planeon.internal.selinux-matrix/v3`:
- 19 domains (roles, lifecycle, maintenance, confined `qualk8s_*` backend and Pod types,
  the admin login, systemd), 56 types, three booleans and three boot states;
- 100 deny assertions from W01, with per-source closures and cgroup2, bpffs and selinuxfs
  genfscon labelling;
- the corrected closure of W01 finding F2 and the W02a label-slot values;
- 1,716 access and 50 mutation checks on an executable evaluator.

Owner decision E1: the confined runtime may load BPF device programs, a trusted backend use
controlled by W03, T04 and a W02a-F census. It passed its third independent review
(PASS_FOR_SOURCE_PUBLICATION, 2 MINOR and 4 NOTE findings carried to W02e-F, W02a-F, W03 and
T04). No policy is written or loaded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-009 is the
sole 206th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-009 / W02e | SOURCE_PREPARED | SELinux matrix as the 206th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-008 / W02c | VERIFY_PASSED_MERGED | I07 policy-writer channel contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-008 source checkpoint — MET-ENFORCE-008 source preparation, October 7, 2026

Alpha2 OPEN. MET-PERF-031 passed required verify (64/64, 545 s, down from 786 s) and merged as
main f94229a. MET-ENFORCE-008 is the W02c part. It publishes the closed I07 policy-writer
channel contract `planeon.internal.policy-write-frame/v1`:
- MAINTENANCE_STATUS, WRITE_BEGIN, WRITE_OBJECT and WRITE_END on the I05 envelope rules;
- a closed policy-kind table derived from the W02g `planeon:policy-writer` grants, refusing
  effect kinds, policy kinds outside the closure and every other kind;
- a gate model that extends the unchanged W02b model: maintenance opens only when the A3 drain
  fence holds, never on a drain reply (W02b finding P1, write side);
- 180 executable vector checks, counterexamples 18 and 23 and the P1 probes included.

It passed its first independent review (PASS_FOR_SOURCE_PUBLICATION, 4 MINOR and 4 NOTE
findings carried to W02c-F, W02b-F, W02f and W03). Nothing is installed or forwarded; all
E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-008 is the sole 205th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-008 / W02c | SOURCE_PREPARED | I07 policy-writer channel contract as the 205th packet; verify from the owner's App |
| Alpha2A | MET-PERF-031 / PERF-031 | VERIFY_PASSED_MERGED | Test-local exact projection sharing; verify 545 s |
| Alpha2A | W02d-W02f, W02a-F, W02b-F, W02c-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-031 source checkpoint — MET-PERF-031 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-007 passed required verify (64/64, 786 s) and merged as main
b46446d; W02b is ADOPTED_DATA_CONTRACT. That left 114 s under the trusted 900 s cap, so
MET-PERF-031 comes before W02c. A per-test profile of the 203-packet suite found three
inherited mutation loops that re-project identical unchanged inputs through the whole
history chain on every validator call (162 s of 569 s of Mac pytest). Within those three
tests only, each projection is computed once per exact input and reused:
- every mutated input is still projected fresh and refused on its own;
- each test ends with a fully fresh validation;
- no validator under scripts/ shares projections.

In the full Mac dry run the two files drop
from 137 s to 46 s and from 62 s to 16 s. No validator, launcher, transport or acceptance semantics change.
MET-PERF-031 is the sole 204th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-031 / PERF-031 | SOURCE_PREPARED | Test-local exact projection sharing as the 204th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-007 / W02b | VERIFY_PASSED_MERGED | I05 broker-gate channel contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02c-W02f, W02a-F, W02b-F, W02g-F | WAITING_EXACT_PACKETS | I07 schema, seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-007 source checkpoint — MET-ENFORCE-007 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-006 passed required verify (64/64, 626 s) and merged as main
fe50b57; W02g is ADOPTED_DATA_CONTRACT. MET-ENFORCE-007 is the W02b part. It publishes the
closed I05 broker-gate channel contract `planeon.internal.effect-gate-frame/v1`:
- the lockstep, hash-chained frame envelope and ten closed frame variants;
- an executable gate model of connection stamping C1-C7, exact request rendering at A1, the
  durable journal, the A3 drain fence and A4 urgent invalidation;
- the ACTION_OUTCOME to I02 RESOURCE_RESULT mapping, with I02 unchanged;
- 161 executable vector checks, counterexamples 17, 18, 21 and 22 included.

It passed its third independent review (rounds 1 and 2 CHANGES_REQUIRED, round 3
PASS_FOR_SOURCE_PUBLICATION); minor findings are carried to W02b-F and W02c. Nothing is
installed or forwarded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-007 is the sole 203rd
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-007 / W02b | SOURCE_PREPARED | I05 broker-gate channel contract as the 203rd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-006 / W02g | VERIFY_PASSED_MERGED | I06 backend profile, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02c-W02f, W02a-F, W02b-F, W02g-F | WAITING_EXACT_PACKETS | I07 schema, seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-006 source checkpoint — MET-ENFORCE-006 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-005 passed required verify (63/63, 605 s) and merged as main
46bcc3e; W02a is ADOPTED_DATA_CONTRACT. MET-ENFORCE-006 is the W02g part. It publishes
the I06 backend profile for SEALED_SINGLE_NODE_CONTROL_PLANE_V1 on Kubernetes v1.37.1:
- distribution selection criteria, with the evidence bound to its W02a backend profile;
- an inventory of every upstream controller and in-process apiserver writer;
- an identity closure derived from the upstream golden RBAC fixtures;
- 141 executable vector checks and a DATA_CHECK_ONLY reference model.

It passed its second independent review (round 1 CHANGES_REQUIRED, round 2
PASS_FOR_SOURCE_PUBLICATION) and closes W01 finding F1. The I06 part of W02a finding P7
is closed and the rest is carried to W02a-F and W03. No distribution is selected and
nothing is installed or observed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-006 is
the sole 202nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-006 / W02g | SOURCE_PREPARED | I06 backend profile as the 202nd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-005 / W02a | VERIFY_PASSED_MERGED | v2 native qualification contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02b-W02f, W02a-F, W02g-F | WAITING_EXACT_PACKETS | I05/I07 schemas, seccomp, SELinux matrix, admission; W02a and W02g follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep 64 argv, 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-005 source checkpoint — MET-ENFORCE-005 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-004 passed required verify (62/62, 553 s) and merged as main
0ecc5f3; W01 is DESIGN_RESOLVED_REVIEWED. MET-ENFORCE-005 is the first W02 part (W02a). It
publishes the closed v2 native qualification contract: record, role, lifecycle and
backend captures, 162 executable vector checks and a DATA_CHECK_ONLY reference model.
It passed its third independent review (rounds 1 and 2 CHANGES_REQUIRED, round 3
PASS_FOR_SOURCE_PUBLICATION) and closes W01 finding F3. Owner decision D5 redefines
the worker capability rule. Nothing is installed or observed; all E01-E12 remain
OPEN_UNPROVEN. MET-ENFORCE-005 is the sole 201st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-005 / W02a | SOURCE_PREPARED | v2 native qualification contract as201st packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-004 / W01 | VERIFY_PASSED_MERGED | W01 gate resolutions, DESIGN_RESOLVED_REVIEWED |
| Alpha2A | W02b-W02g, W02a-F | WAITING_EXACT_PACKETS | I05/I07 schemas, seccomp, SELinux matrix, admission, identity closure; W02a follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep63argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-004 source checkpoint — MET-ENFORCE-004 source preparation, October 5, 2026

Alpha2 OPEN. MET-VERIFY-004 passed required verify from the dedicated verifier
account (61/61, 592 s); PR #153 merged as main d938151. MET-ENFORCE-004 starts
Alpha 2A item W01. Using the owner's four design decisions, it resolves G04, G05,
G06, G07 and G09 at design level: a sealed single-node qualification control
plane, a versioned admission-versus-commit amendment, a v2 native record with an
EFFECT_GATE role, reboot-only host maintenance, and connection stamping on
unchanged I04. A separate agent reviewed it independently and returned
PASS_FOR_SOURCE_PUBLICATION with every gate RESOLVED_DESIGN, so W01 is
DESIGN_RESOLVED_REVIEWED. This is not native enforcement, an adopted wire ABI or an
installed gate. All E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-004 is the sole
200th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-004 / W01 | SOURCE_PREPARED | W01 gate resolutions and independent review as200th packet; verify from the owner's App |
| Alpha2 verify | MET-VERIFY-004 | VERIFY_PASSED_MERGED | Dedicated verifier account contract |
| Alpha2A | W02 | WAITING_EXACT_PACKET | Wire schemas, v2 record, syscall allowlists, cgroup paths, carried review findings F1-F3 |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep62argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical VERIFY-004 source checkpoint — MET-VERIFY-004 source preparation, October 5, 2026

Alpha2 OPEN. MET-VERIFY-003 passed required verify through the owner's App after
the owner's exact-commit approval (60/60, 500.8 s); PR #152 merged as main 2f0ae59.
The verifier then moved to a dedicated macOS account with root-owned code, its own
keys and a root policy binding its activation key to that account; the GitHub CLI
login used by agents lost repository administration. MET-VERIFY-004 records this
in the verifier contract and is the first pull request verified by the new
account. MET-VERIFY-004 is the sole199th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-004 | SOURCE_PREPARED | Dedicated verifier account contract as199th packet; verify from the owner's App |
| Alpha2 verify | MET-VERIFY-003 | VERIFY_PASSED_MERGED | Isolated network canary; MET-VERIFY-002 review notes |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep61argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical003 source checkpoint — MET-VERIFY-003 source preparation, October 4, 2026

Alpha2 OPEN. MET-VERIFY-002 was the first transport change verified through the
owner's exact-commit approval: independent source review, root-owned approval,
then required verify through the owner's App (59/59, 476.2 s); PR #151 merged as
main c269c7d. Its review notes are applied here: the runner now also starts its
network canary with -I (observed by running the runner), the wrapper test accepts
only the three isolated calls as its interpreter calls, and the verifier contract no longer overstates what the
approval protects against. MET-VERIFY-003 is the sole198th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-003 | SOURCE_PREPARED | Isolated network canary as198th packet; owner exact-commit approval, then verify from the owner's App |
| Alpha2 verify | MET-VERIFY-002 | VERIFY_PASSED_MERGED | Isolated runner call; first owner-approved transport change |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep60argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical002 source checkpoint — MET-VERIFY-002 source preparation, October 4, 2026

Alpha2 OPEN. MET-LINUX-006 passed required verify through the owner's App (58/58,
434.6 s) and PR #150 merged as main 0cacd20. The offline wrapper now starts its
runner with python3 -I, so modules planted in the checkout's ci/ directory, PYTHON*
variables or user site-packages cannot shadow what the evidence-printing runner
imports. Pull requests that change the offline transport are verified only after
the owner approves their exact head commit through a root-owned approval record.
MET-VERIFY-002 is the sole197th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-002 | SOURCE_PREPARED | Isolated runner call as197th packet; owner exact-commit approval, then verify from the owner's App |
| Alpha2 Linux | MET-LINUX-006 | VERIFY_PASSED_MERGED | Complete suite passes on Linux as a non-root user; native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep59argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical006 source checkpoint — MET-LINUX-006 source preparation, October 4, 2026

Alpha2 OPEN. MET-PERF-030 passed required verify through the owner's App (57/57,
417.6 s) and PR #149 merged as main a5badfd. Of the six Linux-only failures from
the GCP run, reproduction in an Ubuntu 24.04 container showed one real defect
(the warm-snapshot fixture under macOS-only /private/tmp, also reused by
test_reuse.py); three kit tests failed only because that run used root, which the
kit correctly refuses; the predecessor test failed only because of the first.
MET-LINUX-006 is the sole196th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 Linux | MET-LINUX-006 | SOURCE_PREPARED | Portable fixture parent as196th packet; verify from the owner's App |
| Alpha2 performance | MET-PERF-030 | VERIFY_PASSED_MERGED | In-session predecessor proof; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep58argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical030 source checkpoint — MET-PERF-030 source preparation, October 4, 2026

Alpha2 OPEN. MET-PERF-029 passed required verify through the owner's App (56/56,
692.4 s, nested 314 s) and PR #148 merged as main f031cea. Half of each outer run
(326 s of 642 s) was the predecessor test re-running the suite the same session
already runs. An owner-approved GCP Linux speed test (deleted after) ran the suite
about 1.35x slower than the Mac, past the 900 s ceiling. The owner chose: prove, do
not re-run; keep the Mac verifier awake on AC power; use Linux verification only
when it is mandatory. MET-PERF-030 is the sole195th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 performance | MET-PERF-030 | SOURCE_PREPARED | In-session predecessor proof as195th packet; verify from the owner's App |
| Alpha2 performance | MET-PERF-029 | VERIFY_PASSED_MERGED | Linear authority rechecks; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory; six Linux-only test failures recorded |

Keep57argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical029 source checkpoint — MET-PERF-029 source preparation, October 4, 2026

Alpha2 OPEN. MET-VERIFY-001 passed its required verify through the owner's App
(55/55, 750.4 s in the trusted launcher, activation391) and PR #147 merged as
main 8172538 with no administrator exception. Its run showed suite time growing
about50s per packet because composed layers re-read every newer authority
quadratically. MET-PERF-029 is the sole194th specification: each route still
freshly reads every newer authority, now exactly once.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 performance | MET-PERF-029 | SOURCE_PREPARED | Linear authority rechecks as194th packet; verify from the owner's App |
| Alpha2 CI | MET-VERIFY-001 | VERIFY_PASSED_MERGED | Owner-operated required check; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep56argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. Phase-end effort
transition NOT_DUE. Prior checkpoints below are history only.

## Historical VERIFY-001 source checkpoint — MET-VERIFY-001 source preparation, October 3, 2026

Alpha2 OPEN. MET-LINUX-005 reached LOCAL_PASS_ONLY (54/54, 671.395 s,
activation390; independent terminal review confirmed) and PR #146 was merged as
main e4e0beb under a second consumed one-time administrator exception. The owner
then replaced the unavailable runner path: required verify is now reported only
by the owner's GitHub App from the installed trusted launcher on an
owner-operated host (docs/alpha-2/OWNER_OPERATED_VERIFIER.md). MET-VERIFY-001 is
the sole193rd specification and the first PR checked through that path.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 CI | MET-VERIFY-001 | SOURCE_PREPARED | Owner-operated required-check contract as193rd packet; verify from the owner's App |
| Alpha2 runner | MET-LINUX-005 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep55argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. A GCP Linux verifier is
a later, separately approved successor. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical005 source checkpoint — MET-LINUX-005 source preparation, October 3, 2026

Alpha2 OPEN. MET-PERF-028 reached LOCAL_PASS_ONLY (53/53, 600.586 s,
activation389; independent terminal review confirmed) and PR #145 was merged as
main f7af83e under a consumed one-time administrator exception; its required
verify did not run because no self-hosted runner exists. MET-LINUX-005 is the
sole192nd specification: it carries the reviewed MET-LINUX-004 nested-checkout
and system-alias runner-contract repair onto that main.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 runner | MET-LINUX-005 | SOURCE_PREPARED_AWAITING_REVIEW | Runner-contract repair as192nd packet; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-028 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; CI and exact-main NOT_RUN |
| Alpha2 runner | MET-LINUX-004 / PR144 | SUPERSEDED_SOURCE | LOCAL1/2/3 consumed and retained; not a predecessor |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

This packet grants LOCAL0/CI0/exact-main0. Keep54argv, both full suites,
420/750/900s/15min and32MiB. No cloud, root, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical028 source checkpoint — MET-PERF-028 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;028 is the
sole191st specification. Same-host measurement of frozen027 outside the trusted
launcher (no allowance consumed) showed the full predecessor suite at485.15s,
over the420s nested limit. Profiling attributed most of the heaviest tests to
per-call full SHA-256 of three large history authorities and about4s per
validate_reuse call to quadratic uniqueItems over3868 path-index objects.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-028 | SOURCE_PREPARED_AWAITING_REVIEW | Exact-bytes authority recheck reuse, linear uniqueItems and additive regressions; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-027 | FAILED_LOCAL_FROZEN | 750.277658s timeout;52/53 commands; nested420.012s timeout; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–026 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

Every authority call still freshly reads complete bytes through unchanged
custody checks; only a byte-identical read under the identical pin skips a
repeated digest. uniqueItems keeps the pinned verdict and message wherever the
pinned check completes; sortable arrays still use it unchanged. Ten lineage
allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical027 source checkpoint — MET-PERF-027 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;027 is the
sole191st specification. Two historical recipe readers reuse immutable decoded
recipe data only. Every call retains fresh full reads/hash checks, explicit
overridden-reader semantics, original failure ordering and fresh mutable views.
No function-level speedup or sufficient headroom has been measured.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-027 | SOURCE_PREPARED_AWAITING_REVIEW | Two recipe projections and additive regressions; final frozen-source review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-026 | FAILED_LOCAL_FROZEN | 750.261581s timeout;52/53 commands; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–025 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

026 nested5128passed/10skipped and7/7 commands completed; outer4981passed with
zero observed failures had no final report. Its51snapshot/42semantic regression
passes are partial observations, not acceptance. Final scan did not run. Nine
lineage allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

Data-only inspection reconciles111 exact owned paths,90 accepted-file inverses,
18 new-file pins and3 closure objects. All190 accepted packets and192 protected
files remain unchanged. The13 repository guides,191-entry index and412 ordered
predecessor edges agree;48 accepted test identity inventories are preserved.
New regression source declares18 functions/50 literal decorator cases;17 use a
two-module fixture. These are syntax observations, not collection or test results.
Independent preliminary core/test review found no concrete blocker. Final exact
commit/tree/history review is separate and remains required before any run.

## Historical026 source checkpoint — MET-PERF-026 source preparation, October 2, 2026

Alpha2 remains OPEN. Accepted main0314a684 has190 immutable YAML; this branch
adds026 only. The sole new optimization is lazy immutable decoding of one
pinned290177-byte historical snapshot. Each call still rereads and hashes the
file, checks the current record and returns a fresh map; other data preserves
the original parser and refusal order. No measured speedup or timing PASS.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | One snapshot decode projection and additive regressions; final exact-source review and every execution gate remain |
| Alpha2 readiness | MET-PERF-025 | FAILED_LOCAL_FROZEN | Outer750.224819s and nested420.016669s timeout,52/53 commands; cleanup independently confirmed |
| Alpha2 readiness | MET-PERF-019–024 | FAILED_LOCAL_FROZEN | All previous allowances/evidence preserved; no replay or transfer |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three attempts consumed; capacity/CI/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

025 outer3134passed calls/one failed enclosing call and nestedINCOMPLETE27873
records/zero observed failed phases are partial observations. The final scan
did not run. Prior019-025 and separatePR144 remain immutable; cumulative8
lineage allowances are consumed. This packet grants LOCAL0/CI0/exact-main0.
Keep53argv, both full suites and420/750/900s/15min limits. No cloud, root,
runner registration, live/native or tenant effects. Exact-source/helper review
and finite authority are required before a future full run. Phase-end effort
transition NOT_DUE; prior checkpoints below are history, not execution grants.

Data-only source inspection reconciles108 exact owned paths,89 accepted-file
inverses,16 new-file pins and3 closure objects. All190 accepted YAML and192
protected files are unchanged. The13 repository guides,191 current/indexed
packets and412 predecessor edges agree;48 accepted test identity inventories
are preserved. New snapshot regression source declares12 functions/51 literal
cases, not collected or executed tests. Preliminary independent core/test
review found no concrete blocker; final frozen-source/history review remains.

## Historical025 source checkpoint — MET-PERF-025 source preparation, October 2, 2026

Alpha2 remains open. Fresh remote main0314a684 retains190 immutable packet YAML;
this candidate adds only025 for191. Reuse the existing exact-byte-keyed immutable
canonical serializer at one CI-performance call site under an explicit narrow
amendment. Preserve interleaved fresh authority/projection/digest checks, every
inherited test, fixed parser semantics and existing256-entry bound. No changed
shared helper/parser, two-pass rewrite, cached verdict or new acceptance grant.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-025 | SOURCE_PREPARED_AWAITING_REVIEW | One canonical-byte delegation and additive regressions; independent review and finite full acceptance remain |
| Alpha2 readiness | MET-PERF-024 | FAILED_LOCAL_FROZEN | 750.259927s deadline,52/53, no final scan; diagnostic repairs narrowly exercised, cleanup confirmed |
| Alpha2 readiness | MET-PERF-019–023 | FAILED_LOCAL_FROZEN | Every prior allowance and evidence retained; no replay/reset/transfer |
| Alpha2 runner preparation | MET-LINUX-004 / PR144 | WAITING | Separate three LOCAL attempts consumed; CI/capacity/exact-main distinct |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed enforcement, fresh native AMD64 and integrated read-only evidence |

024 nested suite returned0 in385.898376s with COMPLETE30271records,0failed/drop
and10recorded skips; all seven nested commands passed. Outer4676 passed calls
and0observed failed phases are incomplete observations, not acceptance. Exact
failure/cleanup pins are in architecture/packet-schema-performance-inputs/prior-024-terminal.json.

Whole-run timing remains unresolved. Repeated YAML-to-canonical conversion is
a source-confirmed opportunity, not measured speedup. Fixed pinned parser
semantics are required; warm cache entries do not detect arbitrary runtime
parser replacement. Preserve53argv, both full suites,420/750/900s,15min and32MiB.
Cumulative7 and PR144 separate3 remain consumed. NewLOCAL0/CI0/exact-main0;
no helper/signing/activation, cloud, root-policy, runner or native/tenant effect.
Model/effort unchanged; phase-end transition NOT_DUE. Earlier checkpoints below
are retained history, not current implementation or execution authority.

Author data-only inspection reconciles106 owned paths,89 exact inverses and14
new-file pins plus the three closure objects; all190 accepted packets and192
protected files remain unchanged. The13 repository guides,191-entry index and
412 ordered predecessor edges agree. All48 changed accepted test modules retain
ordered identities. The additive semantic module declares15 test functions and
42 literal parameter cases, not collected or executed tests. Pre-freeze review
caught three AST fingerprints generated with system Python3.9; corrected hashes
are bound to pinned3.12.14. Import fixtures restore introduced aliases and observe
the actual loaded authority chain. Independent final review remains required.

## Historical024 source checkpoint — MET-PERF-024 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` retains 190 immutable packet YAML;
this unaccepted source adds only `MET-PERF-024`, for 191. Preserve the schema,
freshness, separate semantic-test ownership and historical reconstruction work.
Correct short explicit IDs for invalid-node fixtures without changing inputs,
and explicitly raise the existing nonzero failure payload without pytest
assertion rewriting. No recorder-limit or strict regression relaxation.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 readiness | MET-PERF-024 | SOURCE_PREPARED_AWAITING_REVIEW | Diagnostic corrections and static regression source prepared; independent review and separately authorized complete acceptance remain |
| Alpha 2 readiness | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 consumed; 750-second timeout, invalid diagnostic completion, no final scan |
| Alpha 2 readiness | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | All old allowances remain consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, target qualification and integrated read-only evidence |

Latest023 reached 52/53 commands. Its nested stdout reports 5,019 passed and10
declared skips, but return1 reflects INVALID_NODE and4,680 dropped diagnostic
records. Four outer failed call phases are retained, not a final complete
report. The negative fixture created a65,633-character real node ID; three exact
payload regressions conflict with pinned pytest assertion rewriting. The first
cause is source/log confirmed; the second is a reviewed source-grounded inference
without a retained final traceback. Actual cleanup and unchanged source/history
are independently confirmed. Preserve evidence in
`architecture/packet-schema-performance-inputs/prior-023-terminal.json`.

Whole-run timing is still unresolved. Keep all53 argv, both full suites, nested
420 / local750 / trusted900 seconds, workflow15minutes and32MiB output. This
source grants ZERO attempts; the old shared2/2 plus four separate1/1 allowances
remain consumed at cumulative6. No source/helper execution, CI, merge, cloud,
runner registration, privilege or native/tenant acceptance follows. Model-effort
transition remains NOT_DUE. Prior checkpoints below are historical records.

Author data-only inspection found 104 exact changed paths, 190 unchanged accepted
packets, 191 current entries, 192 protected files, 13 owner guides and 412 ordered
predecessor edges. All 48 changed accepted test modules retain ordered function
identities. The new diagnostic-repair module declares seven functions and 16
literal cases; these are source observations, not executed or collected tests.

## Historical023 source checkpoint — MET-PERF-023 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML;
this unaccepted candidate adds only `MET-PERF-023`, for 191. Move the four new
semantic test functions (14 static cases) into a separate owned module while
restoring the protected file's ten historical identities and bodies. Keep the
canonical owner/root fixes and all unaccepted schema/freshness/diagnostic work.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-023 | SOURCE_PREPARED_AWAITING_REVIEW | Exact historical identities restored and semantic coverage separated; independent review and separately authorized full acceptance remain |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | Shared 2/2 and three separate 1/1 exceptions consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only evidence |

The latest 022 LOCAL failed readiness command 2/53 after 16.4475 seconds without
timeout. Projected-byte checks did not replace separate raw AST identity checks:
adding four functions changed a protected ten-test inventory to fourteen. The
prior source review missed this exact-equality requirement. Preserve that review
as history, not acceptance; do not weaken the historical checks. Pytest and new
diagnostics never ran. Independent terminal review confirmed cleanup and unchanged
source/history. Retained pins are in
`architecture/packet-schema-performance-inputs/prior-022-terminal.json`.

Author data-only inspection confirms 102 owned changed paths, 190 unchanged
accepted packets, 191 current entries, 13 repository guides, 412 predecessor
edges and matching root unions. All 48 changed accepted test modules retain
their exact ordered identities. The protected module matches accepted bytes
apart from the catalog scalar; all four moved semantic functions preserve their
AST bodies and fourteen static cases. Seven new-module guard/selection cases
and one retained022-history case are additional source coverage, not executed
tests. Reversible bytes, locked inputs and old failure records remain intact.

This packet grants ZERO new executions. Source preparation is not qualification,
and earlier 020 pytest failure identities remain unresolved. Review exact raw
test inventories as well as reversible source bytes, current canonical owner/ID
sets, README ordering and all allowed-root unions. Keep all 53 argv, both full
suites, nested 420 / local 750 / trusted 900 seconds, workflow 15 minutes and
the 32 MiB output ceiling. No cloud, runner registration, privilege, CI, merge,
native or tenant-acceptance promotion. Model-effort transition remains NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical022 source checkpoint — MET-PERF-022 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML; this
unaccepted source candidate adds only `MET-PERF-022`, for 191. The correction makes the
canonical owner declaration and root tree agree with the packet catalog and
adds semantic consistency regression source. Earlier schema/freshness/diagnostic
work is carried as unaccepted source, not a completed performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-022 | SOURCE_PREPARED_AWAITING_REVIEW | Owner/index/tree corrections and regression source prepared; data-only relationships checked, independent review and acceptance still required |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 | FAILED_LOCAL_FROZEN | Shared 2/2 plus 020 exception 1/1 and 021 LOCAL 1/1 consumed; no replay or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only profile evidence remain unresolved |

The latest 021 LOCAL failed at readiness command 2: 2/53 commands, four errors,
29.908 seconds, no timeout. The guide named 020 in its canonical PR-packets section and
omitted `conftest.py` from its exact root tree. The earlier hash/inverse review
missed these semantic inconsistencies. Pytest, diagnostic hooks and the final
scan never ran. The frozen source and independent cleanup/result pins are kept
in `architecture/packet-schema-performance-inputs/prior-021-terminal.json`.

Author data-only inspection now reconciles all 13 guides, 191 physical packet
owners, 191 indexed entries, 412 predecessor edges and every declared root union.
It preserves all 190 accepted packet bytes and reproduces the two defects in
frozen 021 while finding neither in this candidate. This is not test execution,
an independent security verdict or a full readiness result.

Decision: repair the documents and test the parser-scoped relationships;
do not weaken validation, drop tests, increase deadlines or edit failed source.
This packet grants ZERO new executions. Independent exact-source/helper review
and explicit finite successor authority are prerequisites to any later full run.
All 53 command arrays, nested 420 / local 750 / trusted 900 seconds and the
15-minute workflow ceilings remain unchanged.
No signing, activation, CI, root-policy/cloud/runner or tenant-acceptance change.
Alpha 2 is open; model-effort transition NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical021 source checkpoint — MET-PERF-021 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` contains 190 immutable packets.
This unaccepted candidate adds only `MET-PERF-021` for 191. It carries forward
reviewed-but-unaccepted schema-lifecycle/fresh-authority work and adds bounded,
redacted per-test phase diagnostics. This is source preparation, not acceptance
or a measured performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-021 | ONGOING_SOURCE_PREPARATION | Test identity/phase/outcome diagnostics; independent review and static closure pending |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 | BLOCKED_FROZEN | Original 2/2 plus additional custody exception 1/1 consumed; no replay |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Existing three LOCAL allowances consumed; CI/capacity and accepted-base reconciliation remain separate |
| Alpha 2 qualification | Native Linux prerequisites / CONF-A2-001 | WAITING | Required source, installed-host and exact-target evidence remain unresolved |

The last020 exception reached execution but timed out: nested predecessor pytest
420.016s, outer750.444s,52/53 commands, no final summaries or final scan.
Two additional outer failure markers have no established test identity.
Independent terminal review confirmed cleanup and unchanged source/history.
Sanitized immutable pins are in
`architecture/packet-schema-performance-inputs/prior-020-terminal.json`;
the earlier019 record remains byte-for-byte historical data.

Root pytest diagnostics identify setup/call/teardown and outcomes as observed.
Nested `subprocess.run(capture_output=True)` remains unchanged: its events are
buffered until return or the420s inner timeout, not live streaming. No raw
parameter values, traceback locals, exception text or environment are added.
Byte/count limits and sink failures must be explicit; unmatched START means
unfinished/unknown. Mock-only tests alone cannot prove real capture integration.

This packet grants ZERO executions. No source rename, reviewed code, pipeline
availability or installed activation resets old budgets. A future full run needs
a separately reviewed exact source/helper and explicit finite successor allowance.
Keep all53 argv, tests/skips,420/750/900s limits,15-minute workflow and32MiB
outer output limit. No warm-source access, root-policy change, cloud spending,
runner registration, dispatch, merge or native/tenant promotion is included.

No phase-end effort change is due. Previous source-era checkpoints below are
retained history, not current grants or completion claims.

## Historical020 source checkpoint — MET-PERF-020 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 unchanged packets. This
candidate adds only MET-PERF-020, not failed MET-PERF-019 or unaccepted PR144. It owns
bounded nested-test diagnostics, fresh authority checks without redundant
runner-bridge JSON parsing, carried-forward schema-lifecycle parity tests and
an exact 191-to-190 source inverse. Performance remains unmeasured.

MET-PERF-019 commit `106ae3ec` is frozen, local and unaccepted. LOCAL1 consumed
the first attempt in the shared schema-performance repair lineage and timed
out at 750 seconds during outer pytest: 52/53 commands, last visible 33%, one F
without a final traceback, no completed nested/outer summary. Independent
cleanup/custody checks closed; no acceptance PASS. The sanitized immutable
failure record is [retained here](../architecture/packet-schema-performance-inputs/prior-local-failure.json).

Source preparation grants zero runs. The cumulative 019+020 LOCAL ceiling is two:
019 consumed one and 020 may receive at most one separately reviewed, exact-source,
finite allowance (packet ordinal 1, lineage ordinal 2), never a reset or automatic
retry. No CI/exact-main allowance is automatic. Keep nested 420 / local 750 /
trusted 900 seconds and workflow 15 minutes, full tests and all isolation/freshness
checks unchanged.
The diagnostics identify START and report an inner timeout immediately when
observed; an outer kill can still leave START only. They are not qualification.

PR144/MET-LINUX-004 remains draft with three consumed LOCAL attempts and no
allowance transfer. Required CI capacity/admission, green merge, exact-main,
native Linux and product/tenant qualification remain separate open gates.
No model/effort change is due.

| Phase / ID | Status | Remaining gate |
|---|---|---|
| Alpha 2 / MET-PERF-019 | FAILED_LOCAL_FROZEN | Retain source and consumed attempt; no replay |
| Alpha 2 / MET-PERF-020 | ONGOING_SOURCE_PREPARATION | Freeze and review exact source; no execution grant |
| Alpha 2 / MET-LINUX-004, PR144 | BLOCKED_ALLOWANCE_EXHAUSTED | Preserve three failed attempts and separate runner work |
| Alpha 2 / required CI and exact-main | WAITING | Independently admitted capacity, complete checks and merge |
| Alpha 2 / native Linux and CONF-A2-001 | WAITING_PREREQUISITES | Fresh native and integrated profile evidence |

The following 019 source-era checkpoint is
retained verbatim as history, not a current execution instruction or PASS.


## Historical 019 source checkpoint — October 1, 2026

Accepted source main is `0314a684ba637fb205856d5fb5e50206071e647a`, the PR #143
source merge under its one-time exception. This is **not** required CI PASS,
installed Linux evidence or a transferable exception. Alpha 2 remains open.
`MET-PERF-019` is a separate **ONGOING_SOURCE_PREPARATION** packet on this base:
one invocation-local task-schema validator, exact error/freshness regressions,
and a reversible 191-to-190 source-history bridge. All 190 accepted packet YAML
and historical authority bytes remain unchanged. Speedup is unmeasured.

Draft [PR #144](https://github.com/caglarsubas/harness-onion/pull/144),
`MET-LINUX-004` at `614a08cfaf34ab0c37788231e03a44972f16727e`, is an unaccepted
diagnostic subject, not this packet's predecessor. Its three LOCAL attempts are
consumed. LOCAL3 completed the nested suite (4,902 passes, ten inherited skips)
but timed out during outer pytest at the installed 900-second boundary; only
52/53 commands ran. Cleanup is retained; acceptance did not pass. No LOCAL4,
allowance transfer, test omission or timeout increase is permitted. On October 1,
its required verify remained queued with zero registered repository runners.

This source preparation grants zero new execution attempts. The proposed finite
maximum LOCAL2 / CI2 / LOCAL_EXACT_MAIN1 remains inactive until independent
exact-source review and a finite owner-delegated execution allowance are bound
before reservation. Installed signed packet activation follows the durable
reservation and precedes launch; the owner allowance JSON is not a signature.
Inherited local/main750s, nested420s, trusted900s and workflow15min ceilings stay
unchanged. The old private930s supervisor is not an inherited allowance.
An independently merged repair would require explicit reconciliation of PR144's
old base/inverse before further work there; it does not certify the excluded
Linux runner-kit changes. Required CI capacity/admission and native Linux
qualification remain separate unpassed gates.

The next paragraph is the retained pre-PR-143 source checkpoint, not current
dispatch, runner availability or completion status.

Current source baseline: `945de93f89c94f42f1d63bff7997e3d0fa704fc4` on accepted main, the merge of MET-UNIFY-005 PR #140. Alpha 2 remains **open**. `MET-RUNNER-001` is a source-only development-CI capacity exception candidate, not an installed runner or permission to provision one. As observed on September 29, 2026, [PR #141](https://github.com/caglarsubas/harness-onion/pull/141) and [draft PR #142](https://github.com/caglarsubas/harness-onion/pull/142) have queued self-hosted `verify` jobs and the repository has zero registered runners. Their source/CI/merge, Linux native and tenant-acceptance evidence remain separate. The [bounded exception](alpha-2/CI_CAPACITY_EXCEPTION.md) requires an independently authorized cost ceiling, a separately reviewed and installed exact-job pre-checkout admission boundary, queue serialization, a qualified Linux guest and verified teardown; this publication supplies none of those operational facts. The next source packet is MET-RUNNER-001, while native AMD64 qualification and the W01/Alpha-2 product gates remain waiting.

The next paragraph is the retained pre-PR-140 source checkpoint, not current dispatch or completion status.

Accepted source baseline: 7a353b253bb257aa0abe2148e7fa62d7570f0b5a (PR #138). The roadmap-publication successor is MET-UNIFY-005; its presence in this branch is source work, not merged acceptance. The unpublished MET-UNIFY-001 local candidate at `2cb0b949ee82` exhausted LOCAL-1 and LOCAL-2. The separate unpublished MET-UNIFY-002 candidate exhausted LOCAL-1/2/3; its last isolated suite exposed a stale inherited 204-file assertion after the current YAML corpus became 205. Unpublished MET-UNIFY-003 [PR #139](https://github.com/caglarsubas/harness-onion/pull/139) passed LOCAL-1, then consumed CI-1 on a GitHub API failure before runner registration and CI-2 on a 15-minute cancellation; its runner was retired with zero registrations remaining. The CI log has a failure marker about 420 seconds after the nested predecessor test began, but cancellation prevented a final traceback; pytest was still active when the job stopped. Unpublished MET-UNIFY-004 local commit `8dbfdac` failed LOCAL-1 on a status-document packet-ID check and LOCAL-2/3 at the unchanged 750-second ceiling during outer pytest; no 004 CI or PR was started. These four candidates and their receipts remain historical evidence, none is a merged predecessor or the live 189th packet, and no allowance transfers to MET-UNIFY-005. Current development phase: **Alpha 2, open**. This page is the single current roadmap and progress entry point. The [indexed source crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md), [accepted source index](../architecture/unified-roadmap-source-index.json), and [exact preceding master](history/master-development-plan-7a353b2.md) retain the implementation detail and history.

## Product goal and first enterprise release

Build an Apache-2.0, modular harness platform that guides an enterprise from business understanding and reliable data to governed agents, evidence and acceptance. The platform must operate on tenant-owned Linux Kubernetes, K3s on existing VMs and OpenShift, including a physically disconnected environment. The same contracts can support operator-hosted SaaS or tenant public cloud on **pre-authorized existing capacity**. macOS is for development; Linux AMD64 and ARM64 need separate native qualification.

The architecture has **four planes, sixteen harnesses and thirteen repositories**. The model is a swappable core dependency, not a fifth harness plane; the administrative control plane is not H17. Every harness has one accountable repository owner. Harnesses in one repository may still have separate processes, images, configuration, permissions, stores, lifecycle and failure scope. The 28 canonical service records are a service inventory, not a count of all images, providers or privileged host components.

Require **at least one qualified baseline for every released harness capability** at the first enterprise release. All sixteen harnesses remain targeted in the Alpha-4 capability floor. A release deferment must identify the source requirement, affected capability, owner, phase and accepted disposition; it cannot silently shrink scope. Qualification binds exact provider/adapter version, capability, integration mode, deployment environment and independent evidence. Multiple alternatives can qualify. Progress toward three or four meaningful options per harness over subsequent waves; these are role-specific compatibility relationships, not 64 mandatory first-release technologies.

No cloud-account creation, billable provisioning, hosted-runner dependency, paid API, API-key requirement, runtime package/model download, external telemetry default, online license check or mutable artifact reference may enter the platform. Existing capacity and locally pinned open-source dependencies are required. The separately governed MET-RUNNER-001 exception concerns one externally operated development-CI guest only; it does not change this product rule or grant a VM, runner or CI PASS. An authorized, already-licensed on-premises external target may be attached only with demonstrated zero incremental charge; the platform cannot redistribute its proprietary code or manage its lifecycle.

The five original warm-start repositories remain untouched and reference-only under the existing source-reuse policy. No product implementation task may open, mount, execute or copy from them. Public endpoint attachment is not source-copy authority. A later import would need separately approved path-level legal and packet authority.

## Guided establishment and deployment

The common industry journey has eight ordered gates:

1. Deployment sovereignty and tenant isolation.
2. Business outcome, owner, workflow and measurable KPI.
3. Risk, regulation, classification and autonomy.
4. Domain vocabulary and canonical entities.
5. Data ownership, quality, completeness, freshness, provenance and access.
6. Integrations, protocols, credentials, tools and side effects.
7. Retrieval, memory, model, ML and orchestration requirements.
8. SLO, recovery, observability, evaluation and tenant acceptance.

The first sector pack is banking: owner decision SECTOR-D1 ([sector direction](alpha-2/SECTOR_DIRECTION.md), October 7, 2026) replaces white goods from Alpha 2 through the first enterprise release, and the white-goods pack and its published packets remain historical source. Sector overlays append to the common journey; tenant-specific answers determine applicable controls, technology and readiness. A mandatory predecessor finding that is OPEN, FAIL or STALE blocks dependent approval. Production control waivers document exceptions but never replace fresh required PASS evidence.

The UI and file workflow share the same schema and deterministic compiler:

**Questionnaire or YAML → TenantDemand → locked profile → reviewed change plan → signed minimal bundle → HarnessInstallation → observed status and evidence.**

The compiler produces exactly six outputs: profile.json, bom.json, install-plan.json, evidence-plan.json, explanation.md and profile.sha256. An active exclusive provider group requires one explicit accepted selector; a recommendation never chooses silently. Bundle composition includes only selected modules and their dependency closure. The current 87-record provider/module catalog is PLANNED: 59 packet-owned implementation dispositions, 23 tenant-supplied external records and five non-installable CONTRACT_ONLY entries. Missing release digests prevent installation or qualification.

| Integration mode | Platform responsibility |
|---|---|
| Built-in, platform managed | Install and manage a qualified provider only inside authorized existing infrastructure. |
| Built-in, externally operated | Manage the approved adapter and binding; preserve tenant ownership of the existing service. |
| Tenant custom adapter | Supply contracts, SDK, isolated artifact admission and independent conformance; tenant engineering owns the integration. |

Custom adapters are separate signed workers/services. They cannot shadow a core provider, run inside the administrative control plane, grant permissions, waive controls or certify tenant acceptance.

## Ownership and dependency policy

| R | Repository | Harnesses or cross-harness responsibility |
|---|---|---|
| R00 | harness-onion / Harness-Engineering | Architecture, planning, taxonomy, packets and release coordination |
| R01 | mas-harness-contracts | Public APIs, events, guidance rules, compiler, compatibility vectors |
| R02 | mas-harness-sdks | Python/TypeScript clients and adapter developer interfaces |
| R03 | mas-harness-industry-packs | Sector journeys, quality/regulatory guidance and fixtures |
| R04 | mas-harness-control-plane | Next.js setup, authenticated tenant overview, plane/harness detail pages |
| R05 | mas-harness-runtime-plane | H3 AI Gateway; H4 Experience & Interaction |
| R06 | mas-harness-model-plane | H2 Model & Inference within the runtime plane |
| R07 | mas-harness-knowledge-plane | H5 Domain; H6 Data Integration; H7 Retrieval; H8 Memory |
| R08 | mas-harness-execution-plane | H9 Protocol; H10 Orchestration; H11 Tools/Sandbox; H12 ML/Decision |
| R09 | mas-harness-trust-plane | H13 Security; H14 Governance; H15 Observability; H16 Assurance |
| R10 | mas-harness-operator | H1 Infrastructure & Runtime, including separately governed host modules |
| R11 | mas-harness-distribution | Minimal OCI assembly, locks, SBOM/license closure and air-gap transfer |
| R12 | mas-harness-conformance-labs | Independent compatibility, native, security, lifecycle and acceptance-candidate evidence |

The [repository graph](../architecture/repositories.yaml), [taxonomy](../architecture/taxonomy.yaml), [service catalog](../architecture/services.yaml), [provider catalog](../architecture/providers.yaml) and [runtime dependency graph](../architecture/dependency-graph.yaml) remain their machine authorities. Arrows mean consumer → provider. Keep contract-source, build-artifact, release-set and runtime-integration edges separate; unconditional graphs stay acyclic. The sole assurance callback exception never permits a source/build cycle.

Release contracts and compatibility vectors first, then SDKs/packs, affected services/operator, exact distribution set and independent conformance. Each cross-repository feature has one parent outcome and separate exact owner packets. A packet is one branch/PR with allowed paths, accepted predecessor versions/digests, direct-argv isolated acceptance, finite attempts and rollback. Repository merge is not harness qualification. R01 owns public contracts; R09 owns authoritative provider registry/promotion; R04 presents their management projection; R10 reconciles the verified installation; R11 packages; R12 qualifies.

The browser reads authenticated control-plane projections and never fans out to all planes. The control plane is outside the synchronous agent request path. The runtime gateway calls the selected model route or task orchestration; it does not retrieve data, assemble context or execute tools. Every service owns its durable state and migrations; no service writes another service’s database schema.

## Provider and research direction

The [provider adoption source](alpha-2/PROVIDER_ADOPTION_ROADMAP.md) retains the `MET-ADOPT-001` policy and its detailed alternatives. It is a historical/detail authority for those decisions, not a second current progress roadmap.

The [sixteen-row research map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) and [adoption ledger](../architecture/research-adoption.json) identify papers, OSS upstreams, owner repositories, proposed packets and qualification gates. They are planning research, not evidence that a provider is installed. At least one qualified provider for each released capability is required; an internal module alone does not satisfy an OSS adoption claim. Preserve later alternatives in the [traceability crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md).

Initial directions include Ollama, llama.cpp and vLLM for H2; LiteLLM’s reviewed open-source compatibility surface for H3; AG-UI/CopilotKit for H4; RDFLib/pySHACL, Trino/Great Expectations/OpenLineage, LlamaIndex/pgvector and a governed memory candidate for H5–H8; MCP/A2A, a separately decided Temporal transition, Wasmtime/gVisor/Kata and local ML/optimization libraries for H9–H12; OPA/Presidio, MLflow integration, OpenTelemetry/Prometheus and Inspect for H13–H16. Milvus external attachment is a later retrieval option before any managed-installation proposal. Ollama attachment to the existing endpoint and managed installation require separate qualification. Framework fake-surface tests do not qualify pinned upstream packages.

Before building another general-purpose router, serving, workflow, retrieval or evaluation engine, publish a measured build-versus-integrate ADR. Failed upstream qualification leaves that option unqualified; it is not permission for unreviewed bespoke replacement. The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal successor, migration, history replay and single side-effect authority. H12’s competing prose API paths are **INTERFACE_NOT_PUBLISHED** until R01 releases a versioned decision contract and compatibility vectors. Closed-schema consumers require old/new vectors even for additive fields and retain the one-minor migration window.

Jev-style typed semantic judgment is an **optional proposal** across selected existing harnesses, not a fifth plane or H17. The official hosted proprietary Jev model is outside the shipped air-gapped, zero-bill baseline. Laya and SemIF require their own open-weight, license, backend, tokenizer, calibration, domain/language, abstention and independent qualification review; neither is currently selectable. Semantic scores may advise classification, route choice, retrieval relevance, memory proposals, decision features or evaluation. Deterministic policy, budgets, side effects and promotion retain authority. The proposed SEM packet IDs remain unpublished.

After the first enterprise release, consider E1 governed evidence-to-improvement, E2 optional behavior/taste distillation and E3 separately approved reinforcement-learning research. Operational evidence, user memory and eligible training data remain distinct; no trace becomes training input or promoted runtime behavior automatically.

## Phase roadmap and current position

The following is a **source-status checkpoint**, not proof of installed runtime or tenant acceptance. PR #138 placed MET-ENFORCE-003 on accepted source main. Its old “ongoing publication” headers are historical. Alpha 2 is still open.

The [item-level backlog](../architecture/unified-roadmap-backlog.json) records phase, owner, status, predecessors, blocker and planned evidence reference for every published packet and proposal; the [requirement dispositions](../architecture/unified-requirement-dispositions.json) join indexed source sections to ownership and unresolved delivery mappings. All accepted source sections now have reviewed delivery and acceptance-plan dispositions; 38 explicit unresolved markers retain actual future design, packet, native-qualification or provider obligations. They do not count as implementation or acceptance, and the affected work cannot advance until its exact owner packet closes them.

| Phase | ID or workstream | Current status | Deliverable / blocking fact |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundation; installed-foundation and production-overview evidence are separate carryovers |
| Alpha 2 preparation | MET-ENFORCE-003 | MERGED_SOURCE_RECORDED | PR #138 on accepted main; reviewed W01 candidate remains a design, not a native enforcement proof |
| Alpha 2 preparation | MET-UNIFY-001 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished failed local candidate; two LOCAL attempts consumed, no PR/CI/merge or budget transfer |
| Alpha 2 preparation | MET-UNIFY-002 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished candidate; three LOCAL attempts consumed, stale 204-file assertion retained |
| Alpha 2 preparation | MET-UNIFY-003 | BLOCKED_CI_ALLOWANCE_EXHAUSTED | PR #139 unmerged; LOCAL PASS, CI-1 transport failure and CI-2 15-minute cancellation; no runner remains |
| Alpha 2 preparation | MET-UNIFY-004 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Local commit only; LOCAL-1 status-check failure and LOCAL-2/3 750-second timeouts; no PR, CI or merge |
| Alpha 2 preparation | MET-UNIFY-005 | MERGED_SOURCE_RECORDED | PR #140 on exact accepted main `945de93`; source history only, not Linux or tenant qualification |
| Alpha 2 CI capacity | MET-RUNNER-001 / PR #143 | MERGED_SOURCE_EXCEPTION | Source on `0314a684`; one-time merge exception consumed, not required CI PASS, installed runner or native qualification |
| Alpha 2 validation | MET-PERF-019 | FAILED_LOCAL_FROZEN | Unaccepted source and consumed LOCAL1 retained; no replay or transferred allowance |
| Alpha 2 validation | MET-PERF-020 | FAILED_LOCAL_FROZEN | Shared allowance and additional custody exception consumed; failure records retained without replay |
| Alpha 2 validation | MET-PERF-021 | FAILED_LOCAL_FROZEN | LOCAL1/1 failed readiness before pytest; source, evidence and cleanup retained |
| Alpha 2 validation | MET-PERF-022 | FAILED_LOCAL_FROZEN | LOCAL 1/1 failed historical test identity checks before pytest; source and evidence retained |
| Alpha 2 validation | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 timed out with invalid diagnostics; exact failure and cleanup records retained |
| Alpha 2 validation | MET-PERF-024 | FAILED_LOCAL_FROZEN | Diagnostic fixes narrowly exercised; whole run timed out at52/53, cleanup confirmed |
| Alpha 2 validation | MET-PERF-025 | FAILED_LOCAL_FROZEN | Nested and outer deadlines exhausted;52/53 commands and independently confirmed cleanup |
| Alpha 2 validation | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | Snapshot decode source prepared; final independent review and full execution gates remain |
| Alpha 2 runner repair | MET-LINUX-004 / PR #144 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | All three LOCAL attempts consumed; preserve frozen source/results, separately queued CI and unpassed Linux gates |
| Alpha 2 CI capacity | MET-UNIFY-008 / PR #141 | BLOCKED_SELF_HOSTED_CI | Source PR open; `verify` queued with no registered runner |
| Alpha 2 CI capacity | MET-LINUX-003 / PR #142 | BLOCKED_SELF_HOSTED_CI | Draft source PR open; `verify` queued on the same labels; queue must be serialized before one-job admission |
| Alpha 2A | W01 / MET-ENFORCE-004 | DESIGN_RESOLVED_REVIEWED | G04–G07/G09 resolved at design level and independently reviewed; E01–E12 remain OPEN_UNPROVEN |
| Alpha 2A | W02 (W02a MET-ENFORCE-005, W02g MET-ENFORCE-006, W02b MET-ENFORCE-007, W02c MET-ENFORCE-008, W02e MET-ENFORCE-009, W02a-F MET-ENFORCE-010, W02b-F MET-ENFORCE-011, W02g-F MET-ENFORCE-012, W02f MET-ENFORCE-013, W02c-F MET-ENFORCE-014, W02-ADM-F MET-ENFORCE-015, W02e-F MET-ENFORCE-016) / W03–W07 | W02a, W02g, W02b, W02c, W02e, W02a-F, W02b-F, W02g-F, W02f, W02c-F, W02-ADM-F and W02e-F VERIFY_PASSED_MERGED; others WAITING_EXACT_PACKETS | W02a v2 record contract, W02g I06 backend profile, W02b I05 channel, W02c I07 writer and W02e SELinux matrix contracts reviewed; remaining W02 parts and W03–W07 are labels, not executable YAML |
| Alpha 2A | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Zero product attempts; requires separately reviewed safe design and bounded packet authority (NON_DISPATCHABLE_RETAINED_HISTORY by MET-LIVE-002) |
| Alpha 2A | CONF-LIVE-004/005/006 | WAITING_PREREQUISITES | Native probes, package handoff and trusted campaign integration (CONF-LIVE-004: not dispatchable as written; moved scope to LINUX-PROBE-KIT-001; narrowed R12 successor pending) (CONF-LIVE-005: not dispatchable as written; moved scope to LINUX-PROBE-KIT-001; narrowed R12 successor pending) (CONF-LIVE-006: paths and commands unchanged; consumes the kit's artifacts by digest) |
| Alpha 2A | CONF-LINUX-001 native AMD64 | NOT_RUN_ENV_UNAVAILABLE | Fresh real-Linux PASS gates runtime coding of CTRL-INTEGRATE-001, MODEL-001, EXEC-001 and RUN-001; ARM64 separate |
| Alpha 2B | Seven EXT proposal IDs | WAITING_PACKET_PUBLICATION | Contract-first provider/adapter/binding qualification, registry, UI, packaging and mode-aware reconciliation |
| Alpha 2B onward | Sixteen OSS adoption proposal IDs | WAITING_PACKET_PUBLICATION | Owner-specific actual pinned upstream integrations and qualification |
| Alpha 2B onward | JEV/Laya/SemIF SEM proposals | WAITING_PACKET_PUBLICATION | Optional local semantic contracts, adapters and independent evidence |
| Alpha 2 sector | MET-SECTOR-001 / SECTOR-D1 | VERIFY_PASSED_MERGED | Banking replaces white goods through the first enterprise release; dispositions for 28 published packets; no catalog, pack or packet change |
| Alpha 2 sector | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, banking inputs for retained packets and journey certification |
| Alpha 2 acceptance | CONF-A2-001 | WAITING | Integrated cited read-only banking profile (ID kept; revision amendment before dispatch), installed foundations and real overview |
| Alpha 3 | Governed action / CONF-A3-001 | WAITING | Approval, memory, sandbox, tools, decision service and full interaction |
| Alpha 4 | Enterprise campaigns / CONF-WG-001 | WAITING | Qualified baseline per released capability, disconnected install, lifecycle/security and independent banking tenant acceptance |
| Post-release | E1–E3 and provider expansion | DEFERRED | Governed improvement research and additional meaningful provider options |

Historical no-go and exhausted work stays closed: PLAN-CANON-001 is a recorded no-go; CONF-PERF-005 is unauthorized; CONF-FIX-007/008 retain prior outcomes; CONF-FIX-009 consumed its local allowance. No old attempt allowance transfers to a successor.

### Counted near-term checklist

These checkboxes count only the named deliverable at the stated evidence level. They are not a platform-completion percentage or permission to dispatch.

- [x] Phase 0 / Alpha 1 · MET-P0-002 · Record the five-source, license and provenance foundation in historical source evidence.
- [x] Alpha 2 · MET-ENFORCE-003 · Merge the reviewed host-interface source candidate as PR #138 on accepted main.
- [x] Alpha 2 · MET-UNIFY-005 · Publish this unified roadmap with exact historical inverse, independent review, declared offline acceptance, required CI and exact-main evidence at `945de93`.
- [ ] Alpha 2 · MET-RUNNER-001 · Publish the source-only bounded development-CI admission contract with exact 189-packet history, isolated acceptance, required CI and exact-main evidence.
- [ ] Alpha 2 · MET-PERF-028 · Complete exact-bytes authority recheck reuse and linear uniqueItems, independent review and separately authorized full LOCAL/CI/exact-main; preserve failed019–027/PR144 and unresolved timing/native Linux gates.
- [ ] Alpha 2 · MET-LINUX-005 · Complete the runner-contract repair on accepted 028 main, independent review and separately authorized full LOCAL/CI/exact-main; preserve PR144 attempts and unresolved native Linux gates.
- [x] Alpha 2 · MET-VERIFY-001 · Publish the owner-operated required verify contract and pass its own required verify through the owner's App; exact-main and native Linux remain separate.
- [x] Alpha 2 · MET-PERF-029 · Make history-chain authority rechecks linear with unchanged freshness and refusal semantics; pass required verify through the owner's App.
- [x] Alpha 2 · MET-PERF-030 · Prove the predecessor suite from the same packet session instead of re-running it; pass required verify through the owner's App.
- [x] Alpha 2 · MET-LINUX-006 · Make the complete suite pass on Linux as a non-root user; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-002 · Start the offline runner in isolated mode and admit transport changes only with the owner's exact-commit approval; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-003 · Start the network canary in isolated mode and apply the MET-VERIFY-002 review notes; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-004 · Record the dedicated verifier account in the verifier contract; pass required verify through the owner's App from that account.
- [x] Alpha 2A · W01 / MET-ENFORCE-004 · Resolve G04–G07/G09 and adopt a versioned host interface only after the required independent review; pass required verify through the owner's App.
- [x] Alpha 2A · W02a / MET-ENFORCE-005 · Publish the independently reviewed v2 native qualification contract; pass required verify through the owner's App.
- [x] Alpha 2A · W02g / MET-ENFORCE-006 · Publish the independently reviewed I06 backend profile (selection criteria, writer inventory, identity closure incl. W01 F1); pass required verify through the owner's App.
- [x] Alpha 2A · W02b / MET-ENFORCE-007 · Publish the independently reviewed I05 broker-gate channel wire contract; pass required verify through the owner's App.
- [x] Alpha 2A · PERF-031 / MET-PERF-031 · Cut required-verify time with test-local exact projection sharing in three mutation loops; pass required verify through the owner's App.
- [x] Alpha 2A · W02c / MET-ENFORCE-008 · Publish the independently reviewed I07 policy-writer channel contract and closed policy-kind table; pass required verify through the owner's App.
- [x] Alpha 2A · W02e / MET-ENFORCE-009 · Publish the independently reviewed SELinux domain, type, boolean and permission matrix with the F2 closure; pass required verify through the owner's App.
- [x] Alpha 2 · MET-SECTOR-001 · Record owner decision SECTOR-D1 (banking replaces white goods through the first enterprise release) with packet dispositions and successor proposals; pass required verify through the owner's App.
- [x] Alpha 2 · PERF-032 / MET-PERF-032 · Cut required-verify time by removing four repeated computations with unchanged refusals (apart from inputs within one stack frame of the recursion limit); pass required verify through the owner's App.
- [x] Alpha 2A · W02a-F / MET-ENFORCE-010 · Publish the independently reviewed native qualification record v3 closing the findings carried to W02a-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02b-F / MET-ENFORCE-011 · Publish the independently reviewed I05 broker-gate channel v2 closing the findings carried to W02b-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02g-F / MET-ENFORCE-012 · Publish the independently reviewed I06 backend profile v2 closing the findings carried to W02g-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02f / MET-ENFORCE-013 · Publish the independently reviewed POLICY-ADMISSION-SEMANTICS/v2 and A2 admission allowlists; pass required verify through the owner's App.
- [x] Alpha 2A · W02c-F / MET-ENFORCE-014 · Publish the independently reviewed I07 policy writer channel v2 closing the findings carried to W02c-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02-ADM-F / MET-ENFORCE-015 · Publish the independently reviewed I05 v3, POLICY-ADMISSION-SEMANTICS/v3 and I07 v3 successor contracts closing W02b-F2, W02f-F and W02c-F2; pass required verify through the owner's App.
- [x] Alpha 2A · W02e-F / MET-ENFORCE-016 · Publish the independently reviewed SELinux matrix v4 closing K2, K3, K4 and K6; pass required verify through the owner's App.
- [x] Alpha 2 · PERF-035 / MET-PERF-035 · Run the outer suite on fail-closed workers inside the unchanged argv, with suite reuse (validators and freshness unchanged); pass required verify through the owner's App.
- [x] Alpha 2 · PERF-SEL / MET-PERF-036 · Replay the SELinux matrices inside validate() instead of three to five times per layer test file, with per-row weakening conjuncts (no validator refusal changes, nothing cached); pass required verify through the owner's App.
- [x] Alpha 2 · CATALOG-BANK / MET-SECTOR-002 · Publish the SECTOR-D1 catalog follow-ups as a reviewed overlay with the catalogs byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · W02d / MET-ENFORCE-017 · Publish the per-role, per-architecture seccomp allowlists and filter digests as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W01-AMEND / MET-ENFORCE-018 · Publish W01 amendment W02D and the W02d successor seccomp-allowlists-v2 as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W03-0 / MET-ENFORCE-019 · Publish the W03 backend distribution selection and the W03 plan as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W02d-V3 / MET-ENFORCE-020 · Publish the W02d successor seccomp-allowlists-v3 (Rust+musl NATIVE_STATIC rules) as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · LIC-HOST / MET-ENFORCE-021 · Publish license-policy amendment LIC-HOST-A1 as a reviewed overlay on the byte-identical base policy; pass required verify through the owner's App.
- [x] Alpha 2A · W04-0 / MET-ENFORCE-022 · Publish the independent enforcement test plan W04-0 (TG-01..TG-08 against E01-E12) and the observation-window register schema as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W02-CLEANUP / MET-ENFORCE-023 · Publish the W02 notes errata (native-profile-v3, I06 v2) and the PERF-032-F checks as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2 · PERF-035-F / MET-PERF-037 · Close the parallel suite's carried review findings R3-01 and R3-02 with every refusal unchanged; owner transport approval; pass required verify through the owner's App.
- [x] Alpha 2A · W03-AMEND / MET-ENFORCE-024 · Publish the W03 plan v2 (the owner's HE-002 decisions), the operator -> harness-engineering buildArtifact edge record and the I05 v3 supplementary vectors after four independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-000 / MET-ADOPT-003 · Publish the research adoption v2 crosswalk (the October 2026 MAS-harness corpus, the eight layers, the sixteen harnesses and the MAS-RA-001..010 acceptance IDs) after four independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-001 / MET-MAS-001 · Publish the verdict and evidence ledger contract candidate (schema, check-kind registry, reference model and vectors; UNRESOLVED maps to H16 WARN) after five independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-002 / MET-MAS-002 · Publish the run manifest and configuration-level evaluation record contract candidate (schemas, reference model and vectors; a paired task-clustered distribution gate) after four independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-008 / MET-MAS-006 · Publish the agent-loop kernel and tool-gateway contract candidate (schemas, reference model and vectors; bounded retries, revision rounds and deterministic-gate interleaving) after ten independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · W03 / MET-ENFORCE-025 · Publish the compiled seccomp filter programs, the edge registry records v2 (operator, EDGE-2) and W03-PLAN-AMEND-1 after four independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-003 / MET-MAS-003 · Publish the run-event, OpenTelemetry GenAI mapping and MAS metrics contract candidate after three independent review rounds; pass required verify through the owner's App.
- [x] Alpha 2A · MET-PERF-038 · Raise the parallel-suite worker deadline (900 s) and the nested predecessor bound (600 s) under verifier bundle v4's 1200 s cap, fail-closed, with a successor limits record; pass required verify through the owner's App after the owner's transport approval.
- [x] Alpha 2A · RA-LICENSE-001 / MET-ADOPT-004 · Record the licence clarification of litellm, pgvector, langfuse and phoenix at pinned commits (digests only) and the 29 planned baselines' recheck as research adoption v3 after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · HS-4.3-AMEND / MET-ENFORCE-026 · Publish amendment HS43 of the W01 host-interface specification (the gate's broker and writer qualification, its capability and readlinkat cells, the BIND digest, a closed list of overridden clauses, two residuals and eight obligations) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · SECCOMP-V3-READLINKAT / MET-ENFORCE-027 · Publish seccomp allowlists v4 (the EFFECT_GATE readlinkat rule with a non-negative dirfd for HS43 obligation O-SECCOMP-V3-READLINKAT; only the gate's digests change) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · PERF-039 / MET-PERF-039 · Raise the parallel suite's worker count from 4 to 6 (owner Q-PERF39-1 (a)) with every fail-closed rule kept, after independent review and the owner's transport approval; pass required verify through the owner's App.
- [x] Alpha 2A · SELINUX-MATRIX-I04-KEYCERT / MET-ENFORCE-028 · Publish SELinux matrix v5 (the gate's I04 key and chain/CA types, no gate capability, the gate's worker-cgroup read, the HS43 /proc narrowing) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · PROGRAMS-REPUBLISH / MET-ENFORCE-029 · Publish compiled filter programs v2 (EFFECT_GATE's two programs republished from seccomp allowlists v4 with the readlinkat block, an index of all fourteen) and edge record v3 for R10's HE-003A2 after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · PERF-040 / MET-PERF-040 · Give back verify headroom lost to the history chain's depth: test-local exact sharing (15 never-shared tests), canonical byte-minimal authority hunks, refreshed weights at six workers and the matrix v5 replay order; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · I05-OBSERVED-WORKERS / MET-ENFORCE-030 · Publish the I05 gate channel v4 (the gate observes the probe-worker cgroup at every BIND, pidfd-confirmed, the v3 wire unchanged) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · LICENCE-POLICY-AMEND / MET-ENFORCE-031 · Publish license-policy amendment LIC-HOST-A2 (Zlib default-allowed globally; the base policy and A1 byte-identical) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · W03-PLAN-AMEND-2 / MET-ENFORCE-032 · Publish W03 obligation-register amendment 2 (HE-004 refined into its parts; HE-004-I01 and HE-003A3 with their obligations) and the operator edge record v4 after independent review; plan v2, amendment 1 and edge record v3 byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · MAS-RA-004 / MET-MAS-004 · Publish topology and coordination v1 (TopologySpec and role-block vector, the coordinator board with verify-before-merge, the declared selection rule, the run-events v1 mapping) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · NATIVE-PROFILE-V4 / MET-ENFORCE-033 · Publish native-profile v4 and I06 v3 (O-NATIVE-GATE-NOCAP, the capture routes, the restated inspector obligation, I06 bound to native-profile v4) and operator edge record v5 after independent review; earlier contracts byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · SELINUX-MATRIX-V6 / MET-ENFORCE-034 · Publish the SELinux matrix v6 (fail-closed source closures, the filesystem tables, entry closures, the /proc reader narrowing, systemd's listener-socket cleanup) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · SECCOMP-OBSERVER-LISTENER / MET-ENFORCE-035 · Publish W01 amendment HS53 and the seccomp allowlists v5 (OBSERVER's I01 listener, the SELinux TCP-listen boundary, systemd's stale-socket cleanup) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · SECCOMP-OBSERVER-LISTENER / MET-ENFORCE-036 · Publish the compiled filter programs v3 (OBSERVER republished from seccomp allowlists v5) and edge record v6 (the two programs for R10's HE-004-I01) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · W03-PLAN-AMEND-3 / MET-ENFORCE-037 · Publish W03 obligation-register amendment 3 (OBS-HOSTPOL-1 and NP-9 added; HE-003's amendment-1 share corrected; HE-004D1's packet scope) after independent review; plan v2, amendments 1 and 2 and edge record v5 byte-identical; pass required verify through the owner's App.
- [x] Alpha 2 · LAB-RUNPLAN-001 / MET-LINUX-007 · Publish the lab run-plan contract v1 (run plan, lease and teardown-residual report with an offline checker) after independent review; pass required verify through the owner's App.
- [x] Alpha 2A · NATIVE-PROFILE-V5 / MET-ENFORCE-038 · Publish the capture-only native-profile v5 (the seven host fields record-only with four T04 proofs; the record native-profile v4's) and edge record v7 (HE-004D2) after independent review; native-profile v1 to v4, I06 v1 to v3 and edge records v1 to v6 byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · MET-PERF-041 · Raise the pytest-diagnostics caps (30 MiB per process, 140,000 events, the scan limits derived) under the verifier's 32 MiB output ceiling with 2 MiB reserved for all other output, fail-closed, with a diagnostic-caps contract record; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · I06-RBAC-V4 / MET-ENFORCE-039 · Publish the I06 backend profile v4 (the policy observer's ClusterRole and binding pinned exactly; check_evidence v3's) and edge record v8 (HE-008, HE-004-I01) after independent review; I06 v1 to v3, native-profile v1 to v5 and edge records v1 to v7 byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · CHAIN-COMPACTION-001 / MET-PERF-042 · Compact the history chain's route and payload scaffold tests in the 63 bridged layers (head full fan-in, identical-input twins), share test-side YAML parses per module, and adopt the identity rule as a standing rule; M2 (B1 0.819, B4 0.661 owner-accepted), M3 (0 FAIL), independent review; pass required verify through the owner's App.
- [x] Alpha 2A · EDGE-V9 / MET-ENFORCE-040 · Publish operator edge record v9 (v8's 66 rows plus the I01 wire's channel schema and vectors for HE-004-I01, registered before use) after independent contract review; the first packet built under the identity rule and step rule; pass required verify through the owner's App.
- [x] Alpha 2A · EVOLUTION-SURFACE-001 / MET-GOV-001 · Publish the evolution surface record v1 (who may propose, generate, test, approve and activate each artifact class at the product and programme levels; the derived gate-material list) with its model and vectors, after five independent contract review rounds and the owner's NOTE fold; gate material; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · DIGEST-CONTRACT / MET-ENFORCE-041 · Publish the I01 digest contract (the seven projection objects and four enforcement digests: definitions, model and vectors) and operator edge record v10 for HE-004-I01B after independent design and contract review; the layer test runs VPO's validate_messages on the complete I01 positive (C1-1); pass required verify through the owner's App.
- [x] Alpha 2A · REVIEW-RECORD-V2 / MET-GOV-002 · Publish the review record v2 contract (two records per review round bound by the file-byte sha256, the brief registry, the frozen list, oracle identities, schemas, model and vectors, the in-suite pre-check) and the evolution surface record v2 (gate list 27 -> 31), after six independent contract review rounds; gate material; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · LINUX-PROBE-KIT-SCOPE / MET-LIVE-002 · Publish the probe-kit scope amendment (the CAMPAIGN_PROXY server side, worker entry, case recipes and receipt candidates moved from R12's CONF-LIVE-003/004/005 to the probe kit; record, model and vectors) after independent design and contract review, with the review-record brief registry rider; gate material; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · LINUX-PROBE-KIT-GATE / MET-GOV-003 · Amend the evolution surface record to version 3 (the Linux probe kit's top-level data directory linux-probe-kit/ as CONTRACT_AND_SOURCE; vectors re-pinned; the D5a oracle test scoped and its identity re-issued) after independent design and contract review, with the MET-LIVE-004 brief registry entries; gate material; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · LINUX-PROBE-INTERFACE / MET-LIVE-003 · Bring the neutral Linux probe interface contract (Q-PK-6) into harness-onion as data, byte-identical (the four v1/ handoff files, the binding record with LPK-0's placeholder bound, the reference model and vectors), after one light review, with its D5a oracle; pass required verify through the owner's App.
- [x] Alpha 2A · LINUX-PROBE-KIT-ADMISSION / MET-LIVE-004 · Publish workload profile v2 and admission semantics v4 as one combined contract (adopted as candidate c3 after two in-tree CONTRACT rounds), with its D5a oracles, every non-chain pinned file byte-identical and the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under the step rule (B-L1-3); pass required verify through the owner's App.
- [x] Alpha 2A · LINUX-ROOT-ALIASES / MET-LINUX-009 · Publish the signed root-alias contract for the native runner kit (version 4 inputs with a signed root-alias record in ci/linux-runner/, the two linux-runner docs, the vectors and the D5a oracle; v3 unchanged), adopted as candidate c3 after two in-tree CONTRACT rounds, with the registry rider; gate material; pass required verify through the owner's App after the owner approves the exact head.
- [x] Alpha 2A · DIGEST-CONTRACT-V2 / MET-ENFORCE-042 · Publish the I01 digest contract v2 beside the frozen v1 (admission v4's sealed rendering, profile v2's complete positive with W1, edge record v11; adopted as candidate c4 after three in-tree CONTRACT rounds), with its D5a oracle and the registry rider; every non-chain pinned file byte-identical and the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under the step rule (B-L1-3); pass required verify through the owner's App after the owner's per-PR approval.
- [x] Alpha 2A · LINUX-HOST-AUTH-001 / MET-LINUX-008 · Publish the Linux host-authority contract v1 for the owner's per-run GCP Linux hosts (the superseding host authority, the host recipe, the launcher install steps and the key custody model as data, with the offline checker and its tests; DATA_CHECK_ONLY), adopted as candidate c8 after three in-tree CONTRACT rounds, with its D5a oracle; no gate class; pass required verify through the owner's App after the lane monitor's and the owner's PR approval.
- [x] Alpha 2A · LANG-PLACEMENT-ADR-001 / MET-GOV-004 · Publish the language-placement ADR 0010 (the owner's language policy LANG-D2 (a) as one digest-bound line, and the planned language of every catalogued repository and deployable as data bound to its source lines, with the minimal offline checker and its tests), with its D5a oracle; exceptions pending LANG-HOTPATH-DECISION-001; gate material (the registry rider); pass required verify through the owner's App after the owner's per-PR approval.
- [ ] Alpha 2A · TECH-ORCHESTRATION-001 / MET-ADOPT-005 · Record the H10 execution authority in ADR 0011 (the owner's TECH-D1 and Q-TO-6: PostgreSQL leases and outbox as H10's qualified baseline, Temporal an optional provider), with the new H10 planning-target block and one R08 clause, naming the superseded planning texts without editing them; the provider catalog unchanged; gate material (the H10 harness document and the registry rider); pass required verify through the owner's App after the owner's per-PR approval.
- [ ] Alpha 2A · CONF-FIX-010 · Complete safe design and exact authority before any product attempt. (NON_DISPATCHABLE_RETAINED_HISTORY by MET-LIVE-002)
- [ ] Alpha 2A · CONF-LIVE-004 · Produce the exact native-probe source implementation and separately qualify it. (not dispatchable as written; moved scope to LINUX-PROBE-KIT-001; narrowed R12 successor pending)
- [ ] Alpha 2A · CONF-LIVE-005 · Produce a reproducible selected package and operator handoff. (not dispatchable as written; moved scope to LINUX-PROBE-KIT-001; narrowed R12 successor pending)
- [ ] Alpha 2A · CONF-LIVE-006 · Integrate the external trusted campaign path.
- [ ] Alpha 2A · CONF-LINUX-001 · Obtain fresh native Linux AMD64 PASS for the blocked runtime-coding gate.
- [ ] Alpha 2 · CTRL-INTEGRATE-001 · Complete production tenant overview and durable status projection after its Linux gate.
- [ ] Alpha 2 · CONF-A2-001 · Qualify the exact integrated read-only profile and inherited foundation evidence.
- [ ] Alpha 3 · CONF-A3-001 · Qualify governed action and interaction.
- [ ] Alpha 4 · CONF-WG-001 · Produce an unsigned banking tenant-acceptance candidate (ID kept from the white-goods plan) after required enterprise campaigns.

## Retained MET-PERF-019-era launch order (historical; not current dispatch)

1. Prepare MET-PERF-019 as one source-only packet against accepted main `0314a684`: exact 92 paths, 190 immutable predecessor YAML, reversible current-to-190 projection, inherited 52 commands plus its one declared validator, and source/error-parity review. No executed diagnostic, selected test or new attempt follows from source publication.
2. Bind independently reviewed exact-source finite execution authority before any reservation. Complete the unchanged full isolated acceptance, required self-hosted CI, protected green merge and separate exact-main evidence. A separately authorized operator must prove Linux host image, root-owned signed admission, throughput, egress/cost bounds and automatic plus independent teardown before runner registration. Refresh and serialize the actual queue before exact-job admission. Preserve PR144's failed history and require its own later base/scope reconciliation. Dashboard source registration remains a separately owned orchestrator packet.
3. Continue W01 design and the existing conformance correction chain under their exact approved packet boundaries. W02–W07 and unpublished EXT/OSS/SEM proposals are not dispatch targets.
4. Run native Linux campaigns only with the external trusted signed launcher, pre-existing authorized capacity and the exact server-side zero-cost admission. Missing target/backend is NOT_RUN_ENV_UNAVAILABLE, never PASS or permission to provision.
5. Start an eligible product packet only after its published predecessor contracts, immutable locks, required native gate and repository policy are satisfied. Release qualification and tenant acceptance require their own exact evidence.

All local packet acceptance runs use the preinstalled deny-all-outbound OS-isolated launcher, direct argv and the same process tree for prefetch and acceptance. Warm snapshots remain denied. Live campaign evidence may cover only declared deployment, runtime, security, assurance and unsigned tenant-candidate axes. Source, unit, PR, merge, SBOM/artifact, signature/release, deployment, runtime, assurance and tenant acceptance are independently recorded. A waiver never replaces a fresh required production PASS.

Required cross-harness acceptance includes unknown-outcome retry safety, streaming cancellation acknowledgement, memory deletion surviving restore, staged-versus-committed data, budget reservations, stateful-provider migration and rollback, real tenant RLS, stale overview projections, local assets, WCAG 2.2 AA, offline installation, security/upgrade campaigns and independent tenant acceptance. Thresholds and profile scope must be frozen in the owning packet before tests.

Alpha 2 has not ended, so the requested phase-end model-effort reminder is **NOT_DUE**. Keep the selected model/effort unchanged; at phase closeout report the next phase’s recommended effort without switching it automatically.

## Retained source-navigation keys (historical)

The links and exact tokens below preserve predecessor source-navigation checks. Their recorded labels—including `WAITING_PREDECESSOR_CORRECTION`, `NOT_AUTHORIZED` and `BLOCKED_LOCAL_BUDGET_EXHAUSTED`—describe earlier checkpoints, **not** today's dispatch authority or the current phase status above.

| Detailed source | Retained publication keys |
|---|---|
| [Paper/repository map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) | `MET-ADOPT-002`; `WAITING_PREDECESSOR_CORRECTION` |
| [Proxy diagnostics](alpha-2/PROXY_PERFORMANCE_DIAGNOSTICS.md) | `MET-PERF-006` |
| [Canonical repair](alpha-2/CANONICAL_REPAIR_PLAN.md) | `MET-PERF-007`; `NOT_AUTHORIZED` |
| [Backend timing](alpha-2/BACKEND_TIMING_DIAGNOSTICS.md) | `MET-PERF-008`; `CONF-DIAG-002`; `NOT_AUTHORIZED` |
| [Completion profiling](alpha-2/COMPLETION_PROFILING.md) | `MET-PERF-009`; `CONF-DIAG-003`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Validation performance](alpha-2/VALIDATION_PERFORMANCE_REPAIR.md) | `MET-PERF-010`; `WAITING_PREDECESSOR_CORRECTION` |
| [Document repair plan](alpha-2/DOCUMENT_REPAIR_PLAN.md) | `MET-PERF-011`; `CONF-DIAG-003`; `INCOMPLETE_DIAGNOSTIC_RETAINED`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Document repair authority](alpha-2/DOCUMENT_REPAIR_AUTHORITY.md) | `MET-PERF-012`; `CONF-PERF-006`; `CONF-BENCH-002`; `WAITING_META`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Benchmark transport](alpha-2/BENCHMARK_TRANSPORT.md) | `MET-PERF-013`; `CONF-BENCH-003`; `NON_DISPATCHABLE`; `CANDIDATE_FROZEN` |
| [Factory diagnostics](alpha-2/FACTORY_DIAGNOSTICS.md) | `MET-PERF-014`; `CONF-DIAG-004`; `BLOCKED_LOCAL_FAILURE` |
| [Guard cost repair](alpha-2/GUARD_COST_REPAIR.md) | `MET-PERF-015`; `CONF-FIX-009`; `CLOSED_PARTIAL_DIAGNOSTIC` |
| [Accounting scope](alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md) | `MET-PERF-016`; `CONF-FIX-009` |
| [Guard traversal](alpha-2/GUARD_TRAVERSAL_REPAIR.md) | `MET-PERF-017`; `CONF-FIX-010` |
| [Catalog traversal](alpha-2/CATALOG_TRAVERSAL_REPAIR.md) | `MET-PERF-018`; `BLOCKED_SAFE_DESIGN` |
| [Local acceptance](alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md) | `MET-ACCEPT-001`; `CONF-LIVE-003` |
| [Conformance publication](alpha-2/CONFORMANCE_PUBLICATION.md) | `MET-PUBLISH-001`; `CONF-LIVE-003` |
| [Conformance completion](alpha-2/CONFORMANCE_COMPLETION.md) | `MET-REPAIR-017`; `WAITING_PREDECESSOR_CORRECTION` |
| [Completion integration](alpha-2/COMPLETION_INTEGRATION.md) | `MET-REPAIR-018`; `CONF-FIX-008`; `DONE_SOURCE_GATES` |
| [Observation/enforcement](alpha-2/OBSERVATION_ENFORCEMENT_PUBLICATION.md) | `MET-REPAIR-019`; `BLOCKED_SAFE_DESIGN` |
| [Enforcement integration](alpha-2/ENFORCEMENT_INTEGRATION.md) | `MET-ENFORCE-001`; `BLOCKED_SAFE_DESIGN` |
| [Host-interface publication](alpha-2/HOST_INTERFACE_PUBLICATION.md) | `MET-ENFORCE-003`; `BLOCKED_SAFE_DESIGN` |
