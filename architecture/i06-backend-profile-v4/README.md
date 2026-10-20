# I06 backend profile v4 — the policy observer's ClusterRole, pinned exactly (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: no cluster, distribution, host or
kernel is observed, nothing is installed or provisioned, and no distribution is selected. All E01-E12 stay
OPEN_UNPROVEN.

v4 is I06 backend profile v3 (`../i06-backend-profile-v3/`, MET-ENFORCE-033) plus the policy observer's read grants: one
closed ClusterRole and one ClusterRoleBinding, both named `planeon:policy-observer`, and an exact pin over them. It is
the I06 successor that owner decision Q-HE4-6 (a) asks to name the role (OBS-RBAC-1). It is a delta (Q-RBAC-1 (a)):
`scripts/i06_backend_profile_v4.py` imports v3, and no evidence rule changes.

## Decisions (verbatim)

Q-HE4-6 (owner via the lane monitor, 2026-10-18):

> - Q-HE4-6 = (a): one closed ClusterRole, named by the next I06 successor and provisioned by HE-008; the client certificate is exactly CN=planeon:policy-observer with no O groups and the clientAuth EKU; a refused read exits 82. The owner ACCEPTS the residual that `list secrets` returns Secret data, to be re-assessed at HE-004-I01, with the optional audit check carried.

Q-NPE-5 (owner via the lane monitor, 2026-10-19):

> - Q-NPE-5 (a): the ClusterRole I06 successor gets its own slot after 252 and before HE-008.

The slot-253 decisions (owner via the lane monitor, 2026-10-19):

> Monitor relay, owner decisions on slot 253 (SCOPE.md d09da60e), 2026-10-19:
> - Q-RBAC-1 (a): a delta I06 v4 that imports v3, keeps check_evidence exactly as v3's, and adds the role document and an exact pin. The owner accepts a third I06 successor.
> - Q-RBAC-3 (a): pin exactly. Any other binding naming the observer, including the writer's RoleBinding to Role planeon-policy-observer, makes the observer refuse its snapshot. Narrowing the writer's role names is carried to W02G-F2 and an I07 successor.
> - Q-RBAC-2, 4, 5, 6, 7 and 8: all (a) as in SCOPE.md (names planeon:policy-observer; HE-008 and HE-004-I01 both check; the Secret audit check decided at I01; AMEND links it later; closure covers the observer's own bindings; the provisioning route is left to HE-008 under the stated constraints).
> Record these verbatim and dated. SLOT 253 is yours (packet id at mechanics). GO for the contract draft and review rounds (light).

Q-RBAC-9 and Q-RBAC-10 (the monitor, 2026-10-19):

> Monitor decisions, 2026-10-19 (a strict tightening within the owner's exact-pin intent; I'll tell the owner):
> - Q-RBAC-9 = (a): add RB07, so that only the contract's ClusterRoleBinding may reference ClusterRole planeon:policy-observer, and any other binding of that role to any subject refuses. Give it negatives: a second ClusterRoleBinding, a RoleBinding referencing the ClusterRole, and an aggregated role.
> - Q-RBAC-10 = "I06-RBAC-V4". The visionary or a lane adds the roadmap item under the lock at merge time.
> The R116/DESIGN-C correction is noted and carried. Fold RB07 and the r1 fixes into candidate 2, then the delta round. The listed details (labels refused, rule order, ignored metadata) are for the reviewer to judge.

Q-RBAC-11 (the monitor, 2026-10-19):

> Monitor: Q-RBAC-11 = (a), consistent with the owner's Q-RBAC-7 (a): closure covers the observer's own bindings only. State the system:authenticated limit plainly and carry it to T04 (cluster-wide check over non-stock bindings to that group) and to HE-004-I01. Don't add (b) as a switch unless it's genuinely trivial; a dormant stricter mode is review surface we don't need. If the owner wants (b) later, it becomes a successor. R1-1 to R1-5 and RB07 go into candidate 2, then the delta r2. I'll tell the owner about the limit.

## Why a successor

- **OBS-RBAC-1** (`../w03-obligation-amendment-2/amendment.json:270-284`) says the observer's read grants are exactly
  those HE-004C's requests need, that the identity closure gives `planeon:policy-observer` `allowedGrants: []`
  (`../i06-backend-profile/identity-closure.json:1765-1774`), that an I06 successor names them and that HE-008
  provisions them. I06 v3 deferred them (`../i06-backend-profile-v3/README.md:18`, `:192`), and native-profile v5 gave
  them their own slot before HE-008 (Q-NPE-5 (a), `../native-profile-v5/README.md:41`).
- **I06 v3 cannot pin them.** Its snapshot check judges policy-relevant grants only
  (`scripts/i06_backend_profile.py:237`, `_grants`): a subject with none is skipped (`:624`), and IC03 compares the rest
  with the closure entry (`:638`). The observer's grants are reads, none of POLICY_WRITE, STATUS_WRITE, SPECIAL or
  WORKLOAD, so v3 accepts the observer with any grant outside I06's policy-relevant categories added, or any read
  removed: get or every verb on secrets, list and watch on every resource, a missing rule, no rule at all, or no binding
  (SN01-SN11, each pinned with `v3Result` null). Only SPECIAL grants are refused, by v3's IC03 (SN12-SN14).
- **I06 v3's positive does not fit.** Its snapshot positive gives the observer get, list and watch on four groups with
  admission `*`, and none of secrets, apiservices, customresourcedefinitions or certificatesigningrequests
  (`../i06-backend-profile-v3/vectors.json:3870`). v4's positive replaces exactly those rules (XR01).

## What v4 keeps

- **Evidence, unchanged.** `check_evidence` is v3's function object (asserted by `check_vectors`): the W02a v4 binding,
  the evidence record `planeon.internal.i06-distribution-evidence/v2` and SC00-SC15 are v3's, and every production call
  is still refused. No evidence case is replayed here; v3's own `check_vectors` replays them.
- **The snapshot record and IC00-IC05.** The record stays `planeon.internal.i06-rbac-snapshot/v1`. v4's
  `check_rbac_snapshot` runs v3's (`scripts/i06_backend_profile_v3.py:91-99`) first, so every v3 refusal and its order
  stay: v3's 43 snapshot cases (5 accepted, 38 negative) replay on v4's positive with their v3 results.
- **The v1 data.** The writer inventory, identity closure, upstream facts and bootstrap RBAC are v1's. The observer's
  closure entry stays `allowedGrants: []`: it counts policy-relevant grants, and the role has none. Its note "Reads the
  policy kinds by name" is superseded by this README only.
- **Frozen.** The I06 v1, v2 and v3 contracts and models, native-profile v1 to v5 and edge records v1 to v7 are
  byte-identical; this packet adds files only.

## What v4 adds

- `observer-rbac.json` (`planeon.internal.i06-observer-rbac/v1`): the identity, the ClusterRole and the
  ClusterRoleBinding in Kubernetes JSON (HE-008 applies them as they are), and the marked Secret residual.
- Criteria RB00-RB07, after v3's 30 rows (`criteria.json`, `planeon.internal.i06-selection-criteria/v4`).
- `check_observer_snapshot`, the observer's acceptance of a snapshot: `check_rbac_snapshot` and `check_observer_rbac`
  composed, under the caller obligation in "The exact pin".
- `check_observer_document` (RB00), `check_observer_rbac` (RB01-RB04, RB06, RB07) and RB05 in `check_rbac_snapshot`. The
  rules are the model's `OBSERVER_RULES`, as the writer's grants are fixed by v1's model.

## Files

| File | Content |
|---|---|
| `observer-rbac.json` | the identity, the two objects and the marked residual |
| `criteria.json` | v3's 30 criteria unchanged, then RB00-RB07 |
| `vectors.json` | the snapshot and objects positives, 7 document, 6 accepted and 61 negative object, 2 accepted and 14 negative snapshot and 6 cross-version cases; v3's snapshot cases by reference |
| `../../scripts/i06_backend_profile_v4.py` | the reference model; imports v3 |
| `status.json` | the candidate's status, decisions, counts and carried items |
| `source-index.json` | the subject's and inputs' digests at the base, and the R10 inputs |
| `../artifact-edges/operator-harness-engineering-v8.json`, `README-v8.md` | edge record v8 |

## The observer's ClusterRole

R10 lines are mas-harness-operator main `1a0c529` (tree `8c1ae5e1`, HE-004D1), read by `git show`; `…/observer/` is
`host-enforcement/crates/observer/` and `…/effect-gate/` is `host-enforcement/crates/effect-gate/`. The role is derived
from HE-004C's request code, not from a list: every request the observer can issue is a body-less `GET`
(`…/observer/src/http.rs:56`), built only in `requests.rs` by seven builders (no other `Request` constructor in
`…/observer/src/`) and issued from `observe.rs`:

| Request | Target form | Verb | Built at | Issued at |
|---|---|---|---|---|
| Snapshot list, fresh or `Exact` at `R` | `/api/v1/<r>` or `/apis/<g>/v1/<r>`, no namespace segment; OR05's two with their field selector | `list`, cluster-wide | `…/observer/src/requests.rs:82, 84, 103, 109` | `…/observer/src/observe.rs:790, 810` |
| Watch, one per served spec | the same path with `watch=true&allowWatchBookmarks=true&resourceVersion=<RV>` | `watch` | `…/observer/src/requests.rs:112` | `…/observer/src/observe.rs:986, 998` |
| Per-spec probe (`PER_SPEC_PROGRESS`, off in production, `…/observer/src/observe.rs:77`) | the same path with `limit=1` | `list` | `…/observer/src/requests.rs:116` | `…/observer/src/observe.rs:1135` |
| Progress read | `/api/v1/namespaces?limit=1` | `list` on `namespaces` | `…/observer/src/requests.rs:154` | `…/observer/src/observe.rs:1134` |
| Discovery of the group | `/apis/admissionregistration.k8s.io` | non-resource `get` | `…/observer/src/requests.rs:133` | `…/observer/src/observe.rs:757` |
| Discovery of each served version | `/apis/admissionregistration.k8s.io/<v>` (each version the APIGroup lists) | non-resource `get` | `…/observer/src/requests.rs:138` | `…/observer/src/observe.rs:764` |
| Version | `/version` | non-resource `get` | `…/observer/src/requests.rs:142` | `…/observer/src/observe.rs:847` |
| OR07 | `/readyz/poststarthook/rbac/bootstrap-roles` | non-resource `get` | `…/observer/src/requests.rs:146` | `…/observer/src/observe.rs:680` |
| Exposition (S0, snapshot, cycle, stream-end check) | `/metrics` | non-resource `get` | `…/observer/src/requests.rs:150` | `…/observer/src/observe.rs:656, 867, 1136` |

The 20 request specs are `Resource::ALL` (`…/observer/src/inputs.rs:89`). Each spans the cluster or all namespaces and
never has a label selector (`:158`, `:159`), so every namespaced list is cluster-wide and needs a ClusterRoleBinding.
Non-resource rules, too, are honoured only through one.

| # | apiGroups | resources / nonResourceURLs | verbs | Request specs (`…/observer/src/inputs.rs`) |
|---|---|---|---|---|
| 1 | `""` | `limitranges`, `namespaces`, `resourcequotas`, `serviceaccounts`, **`secrets`** | `list`, `watch` | `LimitRanges` `:102`, `Namespaces` `:103`, `ResourceQuotas` `:104`, `ServiceAccounts` `:105`, `ServiceAccountTokenSecrets` `:138` (field selector `type=kubernetes.io/service-account-token`), `BootstrapTokenSecrets` `:143` (field selector `type=bootstrap.kubernetes.io/token`) |
| 2 | `networking.k8s.io` | `networkpolicies` | `list`, `watch` | `NetworkPolicies` `:106` |
| 3 | `rbac.authorization.k8s.io` | `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings` | `list`, `watch` | `RoleBindings` `:107`, `Roles` `:108`, `ClusterRoles` `:109`, `ClusterRoleBindings` `:110` |
| 4 | `admissionregistration.k8s.io` | `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `mutatingadmissionpolicies`, `mutatingadmissionpolicybindings`, `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | `list`, `watch` | `ValidatingWebhookConfigurations` `:111`, `MutatingWebhookConfigurations` `:114`, `MutatingAdmissionPolicies` `:117`, `MutatingAdmissionPolicyBindings` `:121`, `ValidatingAdmissionPolicies` `:132`, `ValidatingAdmissionPolicyBindings` `:135` |
| 5 | `apiregistration.k8s.io` | `apiservices` | `list`, `watch` | `ApiServices` `:125` |
| 6 | `apiextensions.k8s.io` | `customresourcedefinitions` | `list`, `watch` | `CustomResourceDefinitions` `:126` |
| 7 | `certificates.k8s.io` | `certificatesigningrequests` | `list`, `watch` | `CertificateSigningRequests` `:129` |
| 8 | — (its own rule) | `/metrics`, `/readyz/poststarthook/rbac/bootstrap-roles`, `/version`, `/apis/admissionregistration.k8s.io`, `/apis/admissionregistration.k8s.io/*` | `get` | `…/observer/src/requests.rs:31, 29, 33, 25` (the constants), builders `:133`, `:138` |

Every rule has `resourceNames` empty and no `aggregationRule`; no resource `get`, no `*` verb, resource or group, and no
SPECIAL verb. Rule 8 stands alone because R10's producer refuses a rule with resources beside non-resource URLs (R99,
`…/effect-gate/MODEL_DEFINED.md:1531`). This is MODEL_DEFINED R116 (`…/effect-gate/MODEL_DEFINED.md:1686`) rule for
rule, and R10's own test role (`…/observer/tests/c_support/mod.rs:369-385`) in content and names.

- **Closed.** The generator checks it against R10: the specs' (group, resource) pairs are exactly the 19 of rules 1-7
  (20 specs; OR05's two Secret specs share core `secrets`), and each of the 88 request targets (each spec in its fresh,
  `Exact`, watch and probe forms, discovery of the group and of three version tokens, `/version`, OR07, `/metrics` and
  the progress read) is authorized by exactly one of the 43 grants (19 pairs × 2 verbs, 5 URLs × `get`), and each grant
  authorizes at least one target.
- **`/version` is API discovery.** OBS-RBAC-1 names the specs, API discovery, `/metrics` and `/readyz`; `/version`
  counts under discovery, as the stock `system:discovery` role groups it (R116).
- **The one pattern.** `/apis/admissionregistration.k8s.io/*` matches by prefix. A longer path under it is a resource
  request, which only rules 1-7 can authorize, so in effect it grants the group's version documents, whichever versions
  the APIGroup lists (Q-HE4-6 (a)).
- **Request attributes.** A `GET` on a collection is `list`, with `watch=true` it is `watch`, a path outside the
  resource paths is a non-resource `get`; selectors, `limit`, `resourceVersion` and the `Accept` form do not change the
  verb, and RBAC ignores selectors. This is the apiserver's request-info resolution, in no pinned contract; T04 confirms
  it on the enrolled host ("403 on reads outside the role", `…/effect-gate/MODEL_DEFINED.md:1805-1806`).
- **Group grants: the limit (Q-RBAC-7 (a), Q-RBAC-11 (a)).** Whatever its `O`, the certificate makes the observer a
  member of `system:authenticated`, so every grant to that group reaches it. The stock ones are `system:basic-user`'s
  self-reviews (`../i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json:17`) and the discovery, version and health
  URLs of `system:discovery` and `system:public-info-viewer`, which the vendored derivation drops (`:13`); the role does
  not rely on them. **Only bindings naming User `planeon:policy-observer` are pinned, with RB07's references to the
  role.** Grants that reach the observer through `system:authenticated` beyond the stock ones are neither pinned here
  nor seen by I06 when they are reads (a binding of that group to Secret reads, or to `nonResourceURLs: ["*"]`, passes
  both checks). T04 runs a cluster-wide check over non-stock bindings to that group, and HE-004-I01 carries the limit.
  With no `O`, no other group applies; `system:monitoring` would add `nodes/metrics` (`:72`).

## The `secrets` rule and the accepted residual

- **Marked.** Rule 1's `secrets` (list and watch, every namespace) is marked in `observer-rbac.json` `residuals` (its
  `ruleIndex` is 0-based: 0 is rule 1). HE-004C asks only for OR05's two field-selected, metadata-only lists and
  watches; RBAC can express neither a field selector nor a metadata-only answer, so the grant allows full Secret reads.
- **Accepted** by the owner (Q-HE4-6 (a), quoted above), with `watch` included: R116 records that `list` and `watch` on
  `secrets` allow full Secret reads (`…/effect-gate/MODEL_DEFINED.md:1686`). Mitigations as recorded there: the
  credential's custody (root 0400, `planeon_observer_cred_t`) and, before HE-004-I01, no way out of the observer (no
  file write, no listener, outbound only to the apiserver); OR05 (`../i06-backend-profile-v3/criteria.json:162`) keeps
  credential-bearing token Secrets absent.
- **Re-assessed at HE-004-I01** (`…/effect-gate/MODEL_DEFINED.md:1779`), where the optional audit check is decided
  (Q-RBAC-5 (a)). If adopted, HE-008 seals the audit rule (SC12) and T04 reads the log. A limit to carry with it: an
  audit event records the user, the verb and the request URI with its query, not the `Accept` header, so it can flag a
  Secret request outside the two selector forms, or a named `get`, but cannot tell a metadata-only answer from a full
  one with the same URI.

## The binding, the names and the certificate

- **Names (Q-RBAC-2 (a)).** The ClusterRole and the ClusterRoleBinding are both `planeon:policy-observer`, as the
  profile fixes every identity name (`../i06-backend-profile/README.md:218`) and as R10's test role has them. The colon
  keeps them apart from the writer's hyphenated Role `planeon-policy-observer`
  (`../i06-backend-profile/identity-closure.json:1751`), a different object.
- **The binding.** One ClusterRoleBinding; `roleRef` the ClusterRole; exactly one subject, User
  `planeon:policy-observer` with apiGroup `rbac.authorization.k8s.io`. The I07 writer cannot provision it: it writes no
  ClusterRoles or ClusterRoleBindings (`../i06-backend-profile/README.md:237`).
- **The certificate** (HE-008; plan I06-7, `../w03-plan-v2/plan.json:450`): subject exactly
  `CN=planeon:policy-observer`, no `O`, the clientAuth EKU (Q-HE4-6 (a)); `observer-rbac.json` `identity` states it. An
  `O` would add groups beyond what RB05 and RB06 see.

## The exact pin

| ID | Rule | Checked by |
|---|---|---|
| RB00 | The observer RBAC document (observer-rbac.json) is closed, of version planeon.internal.i06-observer-rbac/v1 on baseline v1.37.1, and equals the model's: the identity (User planeon:policy-observer; certificate subject CN=planeon:policy-observer, no organizations, clientAuth), the ClusterRole and ClusterRoleBinding both named planeon:policy-observer, and the marked Secret residual | `check_observer_document` |
| RB01 | The RBAC object lists are closed (clusterRoles, clusterRoleBindings and roleBindings, each object with a metadata name); exactly one ClusterRole is named planeon:policy-observer; it has no aggregationRule key, no member beyond apiVersion, kind, metadata and rules, kind and apiVersion (when present) ClusterRole and rbac.authorization.k8s.io/v1, and no metadata beyond its name and the apiserver-set uid, resourceVersion, generation, creationTimestamp and managedFields (no labels, annotations, ownerReferences or finalizers) | `check_observer_rbac` |
| RB02 | Its rules are exactly the model's eight, in order: list and watch on the 19 (group, resource) pairs of HE-004C's 20 request specs in seven rules by group, and get on /metrics, /readyz/poststarthook/rbac/bootstrap-roles, /version, /apis/admissionregistration.k8s.io and /apis/admissionregistration.k8s.io/* in its own rule; resourceNames empty; an absent or null list reads as empty | `check_observer_rbac` |
| RB03 | Exactly one ClusterRoleBinding is named planeon:policy-observer, with the members and metadata rule of RB01, and its roleRef is exactly {apiGroup rbac.authorization.k8s.io, kind ClusterRole, name planeon:policy-observer} | `check_observer_rbac` |
| RB04 | Its subjects are exactly [{apiGroup rbac.authorization.k8s.io, kind User, name planeon:policy-observer}] | `check_observer_rbac` |
| RB05 | In the RBAC snapshot, after IC00-IC05 unchanged, User planeon:policy-observer is present and its effectiveRules are exactly the role's seven resource rules at scope CLUSTER, in order, and nothing else at any scope. This judges the snapshot's User planeon:policy-observer only: the snapshot does not expand groups, so grants that reach the observer through system:authenticated are not in it | `check_rbac_snapshot` |
| RB06 | No ClusterRoleBinding other than the contract's and no RoleBinding has a User subject named planeon:policy-observer, whatever its apiGroup: this covers non-resource rules, which the snapshot does not carry. Only bindings naming User planeon:policy-observer are pinned, with RB07's references to the role (Q-RBAC-7 (a), Q-RBAC-11 (a)): grants that reach the observer through its implicit group system:authenticated beyond the stock bootstrap ones are neither pinned here nor seen by I06 when they are reads (carried to T04 and HE-004-I01). Caller obligation (Q-RBAC-3 (a)): the observer accepts its snapshot only if check_observer_snapshot accepts it, that is check_rbac_snapshot on the snapshot and check_observer_rbac on the ClusterRoles, ClusterRoleBindings and RoleBindings of the read, at the snapshot's one resourceVersion, that produced it | `check_observer_rbac` |
| RB07 | Nothing else reaches the observer ClusterRole: no ClusterRoleBinding other than the contract's and no RoleBinding has a roleRef of kind ClusterRole named planeon:policy-observer (whatever its apiGroup or subjects), and no other ClusterRole has an aggregationRule selector that matches the role's empty labels (an empty selector, or one with no matchLabels and only NotIn or DoesNotExist expressions); a roleRef or selector that cannot be read refuses | `check_observer_rbac` |

- **Objects and snapshot.** RB05 judges the RBAC snapshot, which carries resource rules only: R10's producer drops other
  subjects' non-resource rules and refuses one bound to the loopback user (`…/observer/src/rbac.rs:4-7`). RB01-RB04,
  RB06 and RB07 judge the RBAC objects, so an extra non-resource URL (ON08-ON10) or a second binding of a non-resource
  role (ON48) is refused too. The objects are HE-008's manifest, or the observer's own live lists
  (`…/observer/src/rbac.rs:252-256`).
- **The composed acceptance and the caller obligation (Q-RBAC-3 (a)).** The observer accepts its snapshot only if
  `check_observer_snapshot` accepts it: `check_rbac_snapshot` (IC00-IC05, then RB05) on the snapshot, then
  `check_observer_rbac` (RB01-RB04, RB06, RB07) on the ClusterRoles, ClusterRoleBindings and RoleBindings of the same
  read, at the snapshot's one resourceVersion, from which the snapshot was produced. Neither check is a warning, and the
  lists may not come from another read. CO01-CO07 pin the composition: CO02 and CO03 are exact snapshots refused only by
  the lists (a non-resource role bound to the observer; an aggregate selecting the role), and the snapshot's refusal
  comes first (CO05, CO06). A composed case pairs a snapshot case and an object case of this file; the function judges
  the pair as given, and the caller obligation is what makes a pair one read.
- **Exact, in order.** A narrower rule (ON20, SN10), a reordered rule list (ON23, SN09) and a duplicate (SN08) are
  refused, as is anything wider. Absent, null and empty lists read alike (OA04), as R10's producer reads them. The
  apiserver's own metadata (uid, resourceVersion, generation, creationTimestamp, managedFields) is ignored (OA01);
  labels, annotations (including a client-side apply's), ownerReferences and finalizers are refused (ON26-ON28, ON38,
  ON61).
- **Nothing else reaches the role (RB07, Q-RBAC-9 (a)).** Only the contract's ClusterRoleBinding may reference
  ClusterRole `planeon:policy-observer`: a second ClusterRoleBinding of it (ON52, ON53) or a RoleBinding referencing it
  (ON54, ON55), whatever the subject, refuses, and so does another ClusterRole whose aggregationRule selects it
  (ON56-ON58: an empty selector, or one with no matchLabels and only NotIn or DoesNotExist expressions, matches the
  role's empty labels). A roleRef or selector that cannot be read refuses (ON59, ON60). Aggregates that cannot select it
  are accepted (OA05), as is a namespaced Role that shares the name (OA06). The aggregation controller is
  required-disabled (`../i06-backend-profile/README.md:129`), so under the profile an aggregate would not copy the
  role's rules; RB07 refuses it anyway, failing closed if the profile drifts.
- **Who is the observer.** RB06 matches User subjects named `planeon:policy-observer`, with or without an apiGroup
  (ON50). Only those bindings are pinned, with RB07's references to the role. A Group named `planeon:policy-observer`
  does not reach the user (OA03, SA02), because the certificate has no `O`; `system:authenticated` does reach it, and
  its grants beyond the stock ones are outside the pin (the limit above).
- **The I07 writer's observer Role (Q-RBAC-3 (a)).** The closure lets the policy writer escalate and bind Role
  `planeon-policy-observer` (`../i06-backend-profile/identity-closure.json:1751`; I07 v3
  `../i07-policy-write-v3/policy-kinds.json:97-111`), and I07 v3's vectors K22 and K23 bind it to the observer
  (`../i07-policy-write-v3/vectors.json:2289`, `:2326`). Any such binding makes the observer refuse: ON45 and ON46 are
  those two objects exactly (checked against I07 v3's bytes), and SN04 is the snapshot effect of one. Narrowing the
  writer's role names is carried to W02G-F2 and an I07 successor.

## Consumers

- **HE-008** (provisioning; Q-RBAC-4 (a), Q-RBAC-8 (a)) vendors `observer-rbac.json` and this README, runs
  `check_observer_document` on the vendored document (RB00) and `check_observer_rbac` on its manifest (the document's
  two objects, no RoleBindings; RB01-RB04, RB06, RB07) before applying it, and creates exactly those two objects. Its
  route is its own, under these constraints: no cluster-admin credential on the host at qualification time (SC03); the
  objects exist before the observer's first epoch; no ownerReferences (OR02); the certificate as above. Any later change
  is a policy-kind write that the observer sees. Its OBS-RBAC-1 share is "provisions the grants once an I06 successor
  names them".
- **HE-004-I01** (the observer's own pin; Q-RBAC-4 (a)) vendors `criteria.json` and `vectors.json` and accepts a
  snapshot only through `check_observer_snapshot`, on the RBAC lists it already reads for that snapshot (the caller
  obligation above). It also re-assesses the Secret residual, decides the audit check
  (`…/effect-gate/MODEL_DEFINED.md:1779`) and carries the `system:authenticated` limit (Q-RBAC-11 (a)).
- **T04**: 403 on reads outside the role (`…/effect-gate/MODEL_DEFINED.md:1805-1806`); the certificate subject; the
  stock `system:authenticated` roles on the enrolled host and a cluster-wide check over non-stock bindings to that group
  (Q-RBAC-11 (a)); the audit check, if adopted.
- **Edge record v8** (`../artifact-edges/operator-harness-engineering-v8.json`) registers the role document and this
  README for HE-008, and the criteria and vectors for HE-004-I01; the model is pinned by digest, not copied. The edge
  rule binds bytes, modes and versions, not the label.

## Vectors

| Section | Cases |
|---|---|
| `documentNegative` | 7 |
| `objectsAccepted` | 6 |
| `objectsNegative` | 61 |
| `snapshotAccepted` | 2 |
| `snapshotNegative` | 14 |
| `crossVersion` | 6 |
| `composed` | 7 |
| v3's snapshot cases, replayed | 43 (5 accepted, 38 negative) |

`check_vectors` runs 151 checks: the evidence identity, the criteria, the document and its 7 negatives, the objects
positive and its 6 accepted and 61 negative variants, the snapshot positive, v3's 43 snapshot cases replayed, the 16 new
snapshot cases (each with v3's result on the same snapshot), 6 cross-version cases and 7 composed cases. The model fixes
the case set (each section's ids, in order), the two anchors (XR01: v3's positive, no operation; XR02: v4's positive, no
operation), v4's ids disjoint from v3's replayed snapshot ids, the six frozen inputs' SHA-256 and the RB rows' digest.
The snapshot positive is v3's with only the observer's rules replaced, which `check_vectors` re-derives. ON45 and ON46
must equal I07 v3's K22 and K23 objects. Every RB criterion has a pinned refusal, and RB07's negatives cover a second
ClusterRoleBinding, a RoleBinding and an aggregated ClusterRole. Every input is also pinned by SHA-256 in `inputs`.

| Case | Base | I06 v3 | I06 v4 |
|---|---|---|---|
| XR01: I06 v3's snapshot positive (its observer has get, list and watch, admission *, and no secrets, apiservices, customresourcedefinitions or certificatesigningrequests) | v3 | accepts | refuses: RB05 |
| XR02: I06 v4's snapshot positive | v4 | accepts | accepts |
| XR03: v4's positive with get secrets at cluster scope | v4 | accepts | refuses: RB05 |
| XR04: v4's positive with every verb on secrets | v4 | accepts | refuses: RB05 |
| XR05: v4's positive without the observer | v4 | accepts | refuses: RB05 |
| XR06: v4's positive with v3's S06 (the observer with a write): v3's refusal in both | v4 | refuses: IC03 | refuses: IC03 |

## Not claimed

- No cluster, distribution, host or kernel observation; nothing provisioned; no selected distribution.
- The request-attribute mapping (`list`, `watch`, non-resource `get`) is the apiserver's, confirmed only by T04.
- Grants that reach the observer through `system:authenticated`: only bindings naming User `planeon:policy-observer` are
  pinned, with RB07's references to the role. Grants through that group beyond the stock bootstrap ones are not pinned
  here, and I06 does not see them when they are reads (Q-RBAC-7 (a), Q-RBAC-11 (a); carried to T04 and HE-004-I01).
- No production evidence: v3's rule stands (a reviewed W02a revision with a production backend profile and an I06
  successor bound to it).
- I06 v1, v2 and v3, native-profile v1 to v5 and edge records v1 to v7 stay byte-identical.

## Still open

- v3's list (`../i06-backend-profile-v3/README.md`, "Still open"), carried unchanged, less OBS-RBAC-1's naming, which v4
  discharges, and the edge-v5 `providerPacket` item, which v3's adoption (MET-ENFORCE-033) discharged. W02-PROD's
  import-fallback narrowing (R3-3) is applied to v4's own import only.
- HE-008: the provisioning route under the constraints above (Q-RBAC-8 (a)).
- HE-004-I01: the observer's acceptance through `check_observer_snapshot` (the caller obligation), the Secret residual's
  re-assessment, the audit-check decision and the `system:authenticated` limit.
- T04: the 403, certificate-subject and stock-role checks, and a cluster-wide check over non-stock bindings to
  `system:authenticated` (Q-RBAC-11 (a)).
- W02G-F2 and an I07 successor: narrowing the writer's role names (Q-RBAC-3 (a)).
- OBS-RBAC-1's packet list: the next W03 plan amendment adds this packet with its id (Q-RBAC-6 (a); Q-A3-6 (a),
  `../w03-obligation-amendment-3/amendment.json:33`, `:273`; C3-2, `../w03-obligation-amendment-2/status.json:104-108`).
- The "20 pairs" wording of the HE-004C design text: 20 request specs, 19 (group, resource) pairs. R116 enumerates
  correctly; a clarifying note is carried to R10's next MODEL_DEFINED touch.
- The packet id is assigned at mechanics, and `providerPacket` `TBD` in edge v8 then. The work item is I06-RBAC-V4
  (Q-RBAC-10); the roadmap item is added under the lock at merge time.

## Contract review round 1 findings and dispositions

Round 1 (candidate 1, record sha256 `06e61ab6…`) returned CHANGES_REQUIRED with 3 MINOR and 2 NOTE findings. Candidate 2
answers each, and adds RB07 (Q-RBAC-9 (a)) and the work item (Q-RBAC-10):

| Finding | Disposition |
|---|---|
| R1-1 MINOR, the case set | The model fixes each section's ids in order (`CASE_IDS`), the anchors XR01 and XR02 (`ANCHORS`) and v4's ids disjoint from v3's replayed snapshot ids; the round's two probes (SN01 moved into crossVersion with XR01 dropped; SN01 renamed S06) are generator self-tests, both refused |
| R1-2 MINOR, the composition | The composed function `check_observer_snapshot` (chosen), pinned by CO01-CO07, and the caller obligation in this README, the model docstring and RB06's requirement |
| R1-3 MINOR, the `system:authenticated` limit | Stated in RB05's and RB06's requirements, "Group grants: the limit", "Who is the observer" and "Not claimed"; carried in `status.json` to T04 (a cluster-wide check over non-stock bindings to the group) and HE-004-I01; no stricter mode (Q-RBAC-11 (a)) |
| R1-4 NOTE, frozen pins | The model fixes the six frozen inputs' SHA-256 (`FROZEN_INPUTS`) and the RB rows' digest (`RB_ROWS_SHA256`); the round's three probes with `inputs` updated are self-tests, each refused |
| R1-5 NOTE, wording | (a) the producer's loopback refusal; (b) "any grant outside I06's policy-relevant categories"; (c) v3's discharged edge-v5 item; (d) ON61 holds finalizers; (e) `ruleIndex` is 0-based; (f) HE-008 runs `check_observer_document` (RB00) too |
