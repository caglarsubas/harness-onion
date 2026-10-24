# Workload profile v2 (`CAMPAIGN_PROXY_MTLS_ZERO_COST_V2`) — LPK-1 contract (UNIT_VERIFICATION_ONLY)

Alpha 2; 2026-10-24. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (candidate c2; one combined
LPK-1 review, series `MET-LIVE-004/contract`, with `../admission-semantics-v4/`; source index in
`../linux-probe-kit-admission/`). This status line is the candidate line the README is reviewed with; `status.json`
governs.

Profile v2 is the LPK-1 (LINUX-PROBE-KIT-ADMISSION, packet MET-LIVE-004) successor **beside** workload profile v1
(`../proxy-contract-inputs/profile.schema.json` and `vectors.json`, MET-REPAIR-009's authority). It is not an edit of
v1: v1's schema, vectors, guide and authority stay byte-identical, and **profile v1 remains the wire's profile** (I01's
complete positive, VPC/VPO, the native-profile record's `profileDigest`, R10's replay of v1's vectors) until the carried
wire steps W1-W4 land. LPK-0's record (`../probe-kit-scope/amendment.json`, MET-LIVE-002) keeps the proxy profile in its
WIRE_AND_BINDING row, and LPK-1 keeps that true; `status.json` `predecessorRecord` cites it.

Profile v2 lets the kit's Pods pass admission v4: they carry the three shape-echo annotations and may carry bounded
emptyDir volumes, mounted at `/work/<name>`, and every image is still pulled `Never`. Decisions: the owner's Q-PK-3,
"Never, pinned (Recommended)" (profile v2 gains the echo annotations and bounded emptyDir volumes), Q-PK-4 and "As steps
(Recommended)"; the lane monitor's Q-LPK1-1 to Q-LPK1-12 and Q-LPK1-D1 (at most 4 volumes), D2 (the `/work/` root, and
the mount path equal to `/work/<volume name>`), D3, D4 and D5. Nothing here installs, compiles, contacts or grants
anything.

## Files

| File | Content |
|---|---|
| `README.md` | This text |
| `profile.schema.json` | v1's draft 2020-12 schema with exactly the changes below, `$id` `https://schemas.planeon.ai/internal/proxy-execution-profile/v2.json` |
| `vectors.json` | 67 cases: 1 full positive, 50 negatives and 16 cross-contract cases; `evidenceClass` UNIT_VERIFICATION_ONLY, `nativeAcceptance` false (as v1's) |
| `status.json` | The contract state, review rounds, non-claims, carried steps and the predecessor record; it governs this README's status line |
| `../../scripts/proxy_profile_v2.py` | Reference model, standard library only: `validate(profile, schema)`, `precondition(profile, namespace)`, `schema_error(instance, schema)` |

## The schema: what changes, what is kept

`profile.schema.json` is v1's schema, re-`$id`'d as `…/proxy-execution-profile/v2.json`, with exactly these changes:
0. **`profileId`** is const `CAMPAIGN_PROXY_MTLS_ZERO_COST_V2`. A v1 document is refused (P00).
1. **Pod `metadata`** gains `annotations`. It is closed and required, and it requires exactly
   `planeon.ai/a2-containers`, `planeon.ai/a2-init-containers` and `planeon.ai/a2-volumes`, all strings.
   `a2-containers` has the pattern `^probe=[a-z0-9][a-z0-9.:/-]*@sha256:[0-9a-f]{64}$`; `a2-init-containers` is const
   `""`, since `initContainers` stays forbidden; `a2-volumes` is empty or up to four comma-joined volume names (maxLength
   255). The model checks each echo against the spec, as A2 does (P30, P32). ConfigMap and Service metadata stay closed,
   with no annotations.
2. **`metadata.name` is a DNS label for all three kinds:** `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`, maxLength 63 (v4
   MC01). As a side effect, a ConfigMap can no longer be named `kube-root-ca.crt` (MC11).
3. **Pod `spec` drops `hostNetwork`, `hostPID` and `hostIPC`** from `properties` and `required`. The spec stays closed,
   so they are forbidden. Their absence is Kubernetes' default `false`, so host namespaces stay off, exactly as v1's
   const `false` kept them, and v4's MC30 (presence refused) is unchanged.
4. **Pod `spec`** gains `volumes`: optional, with minItems 1 and maxItems 4 when present. Each entry is closed as
   `{name, emptyDir: {sizeLimit}}`, both required. `name` is a DNS label of at most 63 characters, never
   `kube-api-access-*` (a schema `not` pattern; v4 MC36), and unique within the Pod (P35); `sizeLimit` is a decimal byte
   quantity in the profile's byte form, `^[1-9][0-9]{0,14}$`; `medium` and every other source are forbidden.
5. **The `probe` container** gains `volumeMounts`: optional, with minItems 1 and maxItems 4 when present. Each entry is
   closed as `{name, mountPath}`; `name` is one of the Pod's volumes, each volume is mounted exactly once, and no mount
   names an undeclared volume (P33); `mountPath` is exactly `/work/<name>`, by the schema pattern
   `^/work/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$` and the model's equality (P33). `readOnlyRootFilesystem` stays required
   true. So every writable path the Pod declares is a bounded emptyDir at `/work/<its name>`; the paths the Pod does not
   declare are listed under "The interface's check names".
6. **The bound:** Σ `sizeLimit` ≤ the container's `ephemeral-storage` limit. This is a model rule (P34), not a schema
   rule.
7. **`imagePullPolicy`** stays const `Never`, and `images == localImages` holds (P21, VPC's rule).

**Patterns.** Every `pattern` in the schema is read as the pinned G-JSONSCHEMA bundle reads it, by Python's
`re.search`, where `$` also matches before one trailing line feed; the model's walker does the same, and admission
v4's regular expressions read their `^...$` anchors the same way. So a pattern-checked string may end in one line
feed: `536870912` followed by one, as a `sizeLimit` or an ephemeral-storage quantity, or `probe-pod` followed by one,
as a name, matches. Profile v2, admission v4 and the bundle agree on every such string, so profile v2 is never wider
than admission v4, and the apiserver's own quantity and name validation refuses such a string (a reading of
upstream, not verified at v1.37.1).

**KEPT** (unchanged from v1): the top-level members `binding`, `capacityEntries`, `policy`, `quota`, `resources` and
`localImages`; the definitions `binding`, `credentialIdentity`, `apiRule`, `proxyRule`, `gvkRule`, `resourceRef`,
`units`, `resource` and `policy`; and, in `manifest`, everything the changes above do not name: the `apiVersion` and
`kind` consts, the closed labels (`planeon.ai/run-nonce`, `planeon.ai/tenant-id`), the ConfigMap's `immutable` and
`data`, the Service's closed spec and ports, and the Pod's restartPolicy, serviceAccountName,
automountServiceAccountToken (const false), enableServiceLinks, its one `probe` container (image pattern, const `Never`,
cpu, memory and ephemeral-storage requests and limits, securityContext) and every other closed member.

## The model (`scripts/proxy_profile_v2.py`)

The model uses the standard library only. `validate(profile, schema)` checks the closed v2 schema (P00, with its own
walker over exactly the keywords the schema uses, draft 2020-12 meaning) and the semantic rules, and returns one refusal
per document, `P<nn> <text>`: the first rule that fails in VPC's order, stated below. The table lists the codes; its row
order is not the evaluation order. It carries every rule and bound of VPC's `validate_profile`
(`scripts/validate_proxy_contract.py`, lines 125-213) unchanged, in VPC's order, each with its own code. `schema` must
be the reviewed v2 schema (its canonical sha256 is pinned as `SCHEMA_SHA256`); another schema raises an error, because
that check concerns the caller, not the document, so it has no P code.

| Code | Rule (VPC's, KEPT unless marked) | State | Refusal text |
|---|---|---|---|
| P00 | the closed v2 schema | CHANGED: v2's schema | `P00 the document does not match the closed profile v2 schema` |
| P01 | every value an exact JSON builtin (an object with string keys, an array, a string, an integer, a boolean or null), so a number parsed as a float is refused, integral (`9443.0`) or not (`0.5`); depth at most 16, the 262144 size budget, integers within ±(2^53−1); canonical size at most 262144 | KEPT (VPC's `_bounded` and canonical-size check) | `P01 the profile holds a non-data value (any number parsed as a float, integral or not) or exceeds the depth, size-budget, integer-range or canonical-size bounds` |
| P02 | the binding window: canonical UTC times, 0 < expiresAt − validFrom ≤ 900 s | KEPT | `P02 the binding window is not a canonical UTC window of at most 900 s` |
| P03 | the service-account subject in the binding namespace | KEPT | `P03 the service-account subject is outside the binding namespace` |
| P04 | a separate API endpoint when there are resources, none otherwise | KEPT | `P04 the API endpoint is missing, reused or unused` |
| P05 | the credential inventory (client, then server) | KEPT | `P05 the credential inventory differs from the binding` |
| P06 | each credential's subject and expiry equal the binding | KEPT | `P06 a credential's subject or expiry differs from the binding` |
| P07 | no client/server credential reuse | KEPT | `P07 the client and server credentials are reused` |
| P08 | the fixed proxy rule: endpoint, namespace and the ten paths | KEPT | `P08 the fixed proxy rule differs` |
| P09 | no duplicate or foreign preexisting reference | KEPT | `P09 a duplicate or foreign preexisting reference` |
| P10 | the three policy references (quota, limit range, service account) by uid and digest | KEPT | `P10 the three policy references differ from the policy` |
| P11 | the service-account reference name equals the subject's | KEPT | `P11 the service-account reference name differs from the subject` |
| P12 | no duplicate preexisting uid | KEPT | `P12 a duplicate preexisting resource uid` |
| P13 | each manifest's digest and its 16384-byte bound | KEPT | `P13 a manifest digest or 16384-byte size mismatch` |
| P14 | each resource's namespace and labels equal the binding; no duplicate logical identity | KEPT | `P14 a resource outside the binding scope or a duplicate logical identity` |
| P15 | no takeover of a preexisting resource | KEPT | `P15 a resource takes over a preexisting resource` |
| P16 | the Pod's service account equals the subject's | KEPT | `P16 the Pod service account differs from the subject` |
| P17 | requests equal limits | KEPT | `P17 unequal requests and limits` |
| P18 | a Service selects exactly the binding labels | KEPT | `P18 a Service selector other than the binding labels` |
| P19 | the exact GVK and name grants | KEPT | `P19 the GVK and name grants differ from the resources` |
| P20 | the exact API rules | KEPT | `P20 the API rules differ from the resources` |
| P21 | Pod images equal `localImages` | KEPT | `P21 the Pod images differ from localImages` |
| P22 | the quota | KEPT | `P22 the quota is exceeded` |
| P30 | the containers echo equals `probe=<image>` | NEW | `P30 the containers echo differs from probe=<image>` |
| P32 | the volumes echo equals the volume names, comma-joined, in order | NEW | `P32 the volumes echo differs from the volume names` |
| P33 | each volume mounted exactly once, at `/work/<name>`; no mount of an undeclared volume; judged over volume names, after P35 (P33's reading, below) | NEW | `P33 a volume not mounted exactly once at /work/<name>, or a mount of an undeclared volume` |
| P34 | Σ `sizeLimit` ≤ the container's `ephemeral-storage` limit | NEW | `P34 the emptyDir sizeLimits exceed the container's ephemeral-storage limit` |
| P35 | volume names unique | NEW | `P35 duplicate volume names` |

**P01's full content.** P01 is VPC's `_bounded` (lines 104-122, called at line 129) and its canonical-size check (line
130), unchanged. P01: every value is an exact JSON builtin, that is an object with string keys, an array, a string, an
integer, a boolean or null. A number parsed as a float is refused, integral or not, so `9443.0` and `0.5` both refuse
P01. The depth is at most 16; the size budget is 262144, where each string, keys included, costs its length and every
other value costs 1; every integer is within ±(2^53−1). Then the canonical form is at most 262144 bytes.
That canonical-size step also refuses a profile whose canonical form cannot be encoded as UTF-8, for example one
holding a lone surrogate (the JSON escape `\ud800`, which a JSON reader accepts) in any string: VPC's line 130
refuses it at the same step, so `validate` refuses it with the P01 text below, and so does `precondition`.

**P01's refusal text, verbatim.** Every P01 clause refuses with this one text, and K01 and K01b expect exactly it:

`P01 the profile holds a non-data value (any number parsed as a float, integral or not) or exceeds the depth, size-budget, integer-range or canonical-size bounds`

VPC's `parse` refuses only NaN and the infinities as constants, so a float reaches `validate_profile`. The closed v2
schema accepts an integral float as an `integer` (draft 2020-12; the pinned G-JSONSCHEMA bundle, jsonschema 4.24.0, does
too), so `9443.0` passes P00 and P01 alone refuses it (K01b). `0.5` fails P00 as well, but P01 runs first, so it also
refuses with P01.

**The evaluation order.** It is VPC's, as `validate_profile` runs its rules (VPC lines 128-209):
1. P01: every value is an exact JSON builtin, so a number parsed as a float is refused, integral or not (VPC line 110);
   the depth, size-budget and integer bounds (`_bounded`, called at line 129); then the canonical size (line 130);
2. P00: the closed v2 schema, where VPC validates its schema (line 131);
3. P02 to P12, in code order (lines 132-170);
4. per resource, in the order of `resources` (lines 171-196): P13, P14 and P15; then, for a Pod, P16 and P17 followed by
   the new rules P35, P30, P32, P33 and P34; for a Service, P18. Every rule of one resource runs before any rule of the
   next resource;
5. P19 to P22, in code order (lines 197-209).

VPC's first statement (line 128) pins the digest of its `schema` argument. It checks no document, so it has no P code
and no place in this order. A document that fails several rules refuses with the first of them in this order. K01 (over
the depth bound and outside the schema) expects P01, and the order vectors O01 and O02 pin step 4.

**P33's reading.** P33 is judged over volume names, after P35 has made them unique: the probe container's mount names
are exactly the Pod's volume names, each mounted once, and each `mountPath` is `/work/<name>`. P35 runs before P33, so a
Pod with a duplicate volume name refuses P35 and never reaches P33. No expected code depends on how P33 would read
duplicate names. (In the author's design proof (local, not published), the model compared the two name lists sorted, which equals this rule whenever the names are
unique. Only a hypothetical evaluation in the table's code order would show the difference: with P33 as the proof
computed it, the two name lists compared sorted, only K01, O01 and O02 would change their code; with P33 as stated here,
or as "the mount names are distinct and equal the volume names counted with multiplicity", V11 would change too. The
contract's order is VPC's, above, under which every expected code is the same for all three readings.)

**P40, the cross-contract precondition.** `precondition(profile, namespace)` returns `P40 the binding namespace is not the sealed qualification namespace` when the binding
namespace is not the sealed qualification namespace. P40 is not a profile rule, because the sealed namespace is not
profile data; the kit's signer calls it with the sealed value. Like `validate`, `precondition` first refuses a
profile whose canonical form cannot be encoded with the P01 text, and it returns P99 (below) for an argument that is
not a profile object with a binding namespace.

**P99, a defensive code with two uses.** (1) In `validate`, `P99 malformed profile data` is the catch-all for a
document whose evaluation raises, as in the model of the author's design proof (local, not published); VPC returns
its one generic refusal in the same place. A lone surrogate does not reach it (P01, above). One parsed, schema-valid
document is still known to reach it: a Pod whose cpu request and limit are equal and end in one line feed (for
example `500m` followed by one), which the cpu pattern admits (see Patterns) and whose millicore value then cannot
be read; VPC refuses the same document with its generic refusal at the same point. (2) `precondition` returns P99
for an argument that is not a profile object with a binding namespace, a document `validate` refuses. No vector
expects P99.

**Out of scope.** VPC's other function, `validate_proxy_contract`, which pins v1's authority, the 127-file baseline and
the packet membership, stays v1's authority check. Profile v2's authority is LPK-1's authority record and layer, which
come with the packet. VPC pins v1's schema digest, so it never validates a v2 document, and LPK-1 does not change that.

**Schema validation.** The layer test cross-checks the schema with the pinned G-JSONSCHEMA bundle on every vector, and
every schema validation in the build, the D5a oracle and the packet review uses that bundle, never another install.

## The cross-contract statement

Every profile v2 document whose `binding.namespace` equals the sealed qualification namespace (P40) has each of its
resources (Pod, ConfigMap, Service) admitted by admission v4's `check_manifest`, and each final object admitted by the
sealed A2 objects, under the plain sealed cluster facts: AlwaysPullImages off, and no ServiceAccount pull secrets, global
default PriorityClass, LimitRange default, other toleration seconds or out-of-CIDR allocation. These are the same facts
under which v3's own positives pass (E01-E04 against E05-E11). No profile v2 Pod passes v3: v3's signer check refuses it
with MC33, or with MC02 when P40 fails. v3's sealed A2 alone refuses its final object with `A2-POD-PULL-POLICY` only
while AlwaysPullImages is off. With the plugin on, v3's A2 would admit the rewritten object, so v3's signer check, not
its A2, is what keeps profile v2 Pods out of v3.

The rule table and the cross-contract vectors below prove it on these rules. Each divergence that profile v2 refuses is
one that v4 would also refuse, so the profile is never wider than admission on these rules, and P40 carries MC02.

## Vectors (`vectors.json`)

67 cases: 1 positive, 50 negatives and 16 cross-contract cases.
- **The positive** is one full document with a Pod, a ConfigMap and a Service. The Pod carries the three echo keys, two
  emptyDir volumes (`scratch` 536870912 and `results` 268435456 bytes) mounted at `/work/scratch` and `/work/results`,
  an ephemeral-storage limit of 1073741824 and `Never`. Its binding namespace is the sealed namespace `planeon-qual`,
  and every resource's `manifestDigest` is computed.
- **A case** is `{id, intent, ops, rehash, expect}`. `ops` apply to a copy of the positive, in order: `set` puts
  `value` at `path` (a list of member names and array indexes), and `delete` removes the member at `path`.
  `rehash: true` then recomputes every resource's `manifestDigest` as `"sha256:"` plus the hex sha256 of the manifest's
  canonical JSON (sorted keys, no spaces, UTF-8, no NaN), so a manifest-level case reaches its rule and not P13. `expect`
  is the refusal's code and text, exactly as `validate` returns it. An op value written `9443.0` is the JSON number
  9443.0, which a JSON reader parses as a float; it is kept in that spelling.
- **The negatives** (50): V01-V27, K01, K01b, K02-K22 without K17 and K21, O01 and O02.
  - New rules: a foreign annotation and a missing echo key (P00); a containers echo naming another image (P30) and a
    volumes echo in another order (P32); a non-empty init-containers echo (P00); a volume without `sizeLimit`, with
    `medium`, or of hostPath or PVC type (P00); five volumes (P00); a duplicate volume name (P35); an unmounted volume
    (P33); a mount outside `/work/` (P00); a mount at `/work/<another name>` (P33); the sum over the limit (P34);
    `Always`, `IfNotPresent` and a missing pull policy (P00); an image not in `localImages` (P21) (V01-V19).
  - Divergences from v4: `hostNetwork` present even as `false`, a Pod name with `.` or a trailing `-`, a
    `kube-api-access-x1` volume, an init container and a ConfigMap name with `.` (P00); requests ≠ limits (P17); the v1
    `profileId` (P00) (V20-V27).
  - One per kept VPC rule family, P01 to P22 (K01-K22; P17 and P21 are reached by V24 and V19), and K01b: the positive
    with the Service port written `9443.0`, rehashed, which the closed schema accepts and P01's non-data clause alone
    refuses.
  - The evaluation order: K01 (over the depth bound and outside the schema) → P01; O01, the Pod's sizeLimits over its
    limit (P34) and the ConfigMap in another namespace (P14) → P34, because every rule of the Pod, the first resource,
    runs before the ConfigMap's; O02, one Pod with a duplicate volume name (P35) and a containers echo naming another
    image (P30) → P35, because the new rules run P35, P30, P32, P33, P34.
- **The cross-contract cases** (`crossContract`): each is `{id, intent, ops, rehash, serverFacts, expect: {profileV2,
  precondition, v4, v3}}`. The packet's layer test runs them with both new models and the frozen v3 model; neither model
  imports the other. `profileV2` is "valid" or the refusal; `precondition` is "met" or P40's text; `v4` and `v3` give,
  per resource, the signer's code (`check_manifest`), or the A2 result of the final object (`final_object` under the
  admission vectors' `server` block updated with `serverFacts`, then `check_final`), as "A2 admit" or "A2 " and the A2
  code.

| Case | Profile v2 | P40 | v4 (Pod / ConfigMap / Service) | v3 (Pod / ConfigMap / Service) |
|---|---|---|---|---|
| X01 the profile v2 positive: Pod, ConfigMap and Service | valid | met | A2 admit / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X02 hostNetwork present (false) | P00 | met | MC30 / A2 admit / A2 admit | MC30 / A2 admit / A2 admit |
| X03 Pod name with a dot | P00 | met | MC01 / A2 admit / A2 admit | MC01 / A2 admit / A2 admit |
| X04 Pod name ending in - | P00 | met | MC01 / A2 admit / A2 admit | MC01 / A2 admit / A2 admit |
| X05 binding namespace other than the sealed one (profile-valid) | valid | P40 | MC02 / MC02 / MC02 | MC02 / MC02 / MC02 |
| X06 volume named kube-api-access-x1 | P00 | met | MC36 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X07 requests differ from limits | P17 | met | MC34 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X08 pull policy Always | P00 | met | MC33 / A2 admit / A2 admit | A2 admit / A2 admit / A2 admit |
| X09 emptyDir without sizeLimit | P00 | met | MC42 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X10 sizeLimits over the limit | P34 | met | MC42 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X11 medium Memory | P00 | met | MC42 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X12 containers echo mismatch | P30 | met | MC37 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X13 volumes echo mismatch | P32 | met | MC37 / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X14 AlwaysPullImages enabled despite the pin (profile-valid) | valid | met | A2 A2-POD-PULL-POLICY / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |
| X15 ConfigMap name with a dot | P00 | met | A2 admit / MC01 / A2 admit | MC33 / MC01 / A2 admit |
| X16 a profile v2 Pod with no volumes and no mounts | valid | met | A2 admit / A2 admit / A2 admit | MC33 / A2 admit / A2 admit |

On X01, v3's sealed A2 alone reads `A2-POD-PULL-POLICY` with the plugin off and admits with it on; v3's signer refuses
the Pod with MC33 first.

## The rule table: what implies each v4 rule

Rows marked "cluster fact" hold under the plain sealed cluster, as for v3's positives. They are not profile rules.

| v4 rule | Implied by (profile v2) |
|---|---|
| MC00 | `manifest` is oneOf Pod, ConfigMap, Service with `apiVersion` const `v1` |
| MC01 | the name pattern (DNS label, all kinds) |
| MC02 | P14 (namespace = binding) and P40 (binding = sealed) |
| MC03, MC05 | closed `metadata` and closed manifests (no status) |
| MC04 | closed labels (`planeon.ai/run-nonce`, `planeon.ai/tenant-id`) and closed annotations (three `planeon.ai/a2-*`) |
| MC06 | `spec` required |
| MC10 | `immutable` const true |
| MC11 | the DNS-label name cannot be `kube-root-ca.crt` |
| MC20-MC22 | `type` const ClusterIP; spec closed to `{type, selector, ports}`; ports closed `{name, protocol, port, targetPort}` |
| MC30 | closed Pod spec with no host members, node, runtime class, priority, tolerations, pull secrets, ephemeral containers, scheduling gates, resource claims or `serviceAccount` |
| MC31 | `automountServiceAccountToken` const false |
| MC32 | `containers` minItems 1 |
| MC33 | the image pattern (a subset of v4's digest pattern: no `_`) and `imagePullPolicy` const `Never`; P21 |
| MC34 | requests and limits required with cpu, memory and ephemeral-storage; P17 |
| MC35 | `mountPath` under `/work/` |
| MC36 | the volume-name `not` pattern |
| MC38-MC41 | volume entries closed to `{name, emptyDir}`; closed spec (no `resources`, `affinity` or `topologySpreadConstraints`) |
| MC42 | `sizeLimit` required in decimal bytes and no `medium`; the ephemeral-storage limit required in decimal bytes; no init containers; P34 |
| MC37 | three keys required, `a2-init-containers` const `""`; P30, P32 |
| A2-RESERVED | as MC04; no LimitRange default for cpu, memory or ephemeral-storage, which the container states (cluster fact for other resources, E07) |
| A2-POD-ECHO | P30, P32; automount off, so no token volume |
| A2-POD-TOKEN | automount const false |
| A2-POD-PULL-SECRETS | no `imagePullSecrets` (closed); no ServiceAccount pull secrets (cluster fact, E05) |
| A2-POD-IMAGE-VOLUME | as MC38 |
| A2-POD-TOLERATIONS, A2-POD-PRIORITY, A2-POD-PLACEMENT | no such fields (closed); sealed seconds and no global default class (cluster facts, E06, E09) |
| A2-POD-PULL-POLICY | const `Never`; AlwaysPullImages pinned off (C28), fail closed if not (X14) |
| A2-POD-EMPTYDIR | `sizeLimit` required, `medium` forbidden |
| A2-CM-PUBLISHER, A2-CM-IMMUTABLE | the name is never `kube-root-ca.crt`; `immutable` const true |
| A2-SVC-TYPE, A2-SVC-DEFAULTS | closed spec and ports |
| A2-SVC-ALLOCATION | one address in the sealed CIDR and family (cluster fact, E10, E11) |

## The interface's check names

The interface's check names map to the rules that make them true. They are a mapping, not new rules. Writable paths and
downloads the Pod contract does not govern are residuals, each with an owner. Each upstream statement is an author's
reading, not verified at v1.37.1, and is listed in admission v4's `allowlists.json` `unverified`.

| Check (case) | Made true by | Residual and owner |
|---|---|---|
| `declared-volumes-only` (READ_ONLY_ROOT_FILESYSTEM) | `readOnlyRootFilesystem` true; the only declared volumes are bounded emptyDirs at `/work/<name>` (P33, MC41, MC42); A2-POD-ECHO fixes the volume names on the final object | Paths the kubelet and runtime provide outside the Pod's volumes: the termination-message file (`terminationMessagePath` defaults to `/dev/termination-log`, cited at `defaults.go:94-96`), the kubelet-managed `/etc/hosts`, and the runtime's `/dev/shm`. Owners: the kit's native READ_ONLY_ROOT_FILESYSTEM case lists and observes them; HE-008's sealed CONTAINER_RUNTIME_CONFIG bounds `/dev/shm`. v1.37.1 citations owed |
| `root-read-only` (case 7) | `readOnlyRootFilesystem` const true (KEPT) | v4 has no securityContext rule: signer-guaranteed (A1 bytes, the profile check at signing); the native case proves it |
| `no-privilege-escalation` (case 7) | `allowPrivilegeEscalation` const false (KEPT) | as above |
| `namespace-pinned` (KUBERNETES_SMOKE) | P14 (every resource, proxy and API rule in `binding.namespace`); P40 (= the sealed namespace); v4 MC02 and A2's namespaceSelector; claim C26 | none in the contract; the kit's signer must call P40 |
| `quota-pinned` (KUBERNETES_SMOKE) | the profile's `quota` (P22); the ResourceQuota and LimitRange references by uid and digest (P10); MC42 bounds emptyDir inside the ephemeral-storage limit | the live objects are I01's projections, outside LPK-1 |
| `admission-enforced` (KUBERNETES_SMOKE) | v4's A1 and A2 claims (C21 directory hash, C22, C26, C28) | only in the sealed namespace (hence `namespace-pinned`), and only after the carried steps |
| `no-downloads` (CONTROL_CONTAINER_STARTUP; LINUX_TARGET_BUILD) | `Never` (MC33, A2-POD-PULL-POLICY); `images == localImages` (P21); no image volume (MC38); AlwaysPullImages pinned off (C28) and fail-closed | The runtime's sandbox (pause) image, which the Pod contract does not govern. Owner: HE-008's sealed CONTAINER_RUNTIME_CONFIG (a pinned, preloaded sandbox image, no pull) and the native case. LINUX_TARGET_BUILD's downloads are a build-time check of the kit, outside the Pod contract |
| `run-labelled-cleanup` (case 8) | P14's labels | cleanup is the kit's |
| `arbitrary-nonroot-uid`, `capabilities-dropped`, `seccomp-enforced` (case 6) | `runAsNonRoot`, `runAsUser` ≥ 10000, `drop: [ALL]`, `RuntimeDefault` (KEPT) | signer-guaranteed; native case |

## Carried steps and non-claims

No kit install, LINUX-PROBE-KIT-001's included, happens before every carried step has landed (`status.json` `carried`).
Profile v2 cannot be carried on the binding and observation wire until W1-W4 accept it: W1, the I01 successor also takes
profile v2 for its complete positive and its layer test (a profile v2 path through VPC/VPO, whose successor validates v2
documents with `proxy_profile_v2`); W2, edge v11 also registers this `vectors.json` for R10; W3, R10's re-vendor also
replays the binding and observation cases with this positive; W4, the native-profile record's caller obligation names
`proxy_profile_v2` for a v2 profile. S1-S3 and C1-C2 are admission v4's (`../admission-semantics-v4/README.md`).

Non-claims: nothing is installed or compiled; no apiserver is contacted; admission v3 and v2, profile v1, I06, I01 and
edge records v1-v10 are byte-identical; "pinned off" binds the contract only until I06's successor and HE-008 carry it;
profile v1 remains the wire's profile until the wire steps W1-W4 land. LPK-1's design was checked by the author's design
proof (local, not published) and four TOOLS design rounds, cited by sha256 in
`../linux-probe-kit-admission/source-index.json`.
