# Credential authentication versus execution — MET-REPAIR-013

Alpha 2 · approved 2026-09-09 · source-only authority. Catalog 142 packets;
thirteen repositories, four planes and sixteen harnesses remain unchanged.

## Decision and exact supersession

The user approved separating client authentication from server-authorized
execution. This is a deliberate, narrow credential-ordering change, not a claim
that opening a credential proves current policy. The accepted prior contracts
and product source remain immutable historical evidence.

The current client credential hook requires a policy guard before opening the
sole credential; its TCP resource also requires those retained credential bytes.
The only actual policy-observation channel is server-local. There is no authorized
client observation channel before authentication. CONF-FIX-005 tests intentionally
use a UNIT_ONLY policy adapter; they do not close this integration gap.
Classification: SOURCE_INSPECTION_ONLY; no runtime escape or new failed product
test is claimed, and this publication performs no product execution.

For CAMPAIGN_PROXY_MTLS_ZERO_COST_V1 only, this authority supersedes the
client-side interpretation of MET-REPAIR-012 section "Separate owned resources
and ordering", item 2; the corresponding fixed-hook comments in the accepted
CONF-FIX-005 source; and the general "before credentials" wording of the trusted
live-runner contract and AGENTS rule 12. Only the meta AGENTS clause is amended
now. Historical guides, records, packet YAML and product source are not rewritten.
MET-REPAIR-009/010 server observation, credential custody and mutation rules are
otherwise unchanged. No other credential purpose receives this exception.

## Client: authentication-only eligibility

The fixed installed live_proxy_client._require_current_credential_policy(context,
deadline) hook is retained for compatibility. Under this amendment it verifies
CLIENT_AUTHENTICATION_ELIGIBILITY, not a remote observation. It must return None
only after real checks of the exact NativeSupervisor/context/channel ownership,
active fixed operation, kernel isolation, durable client nonce reservation,
all three independent valid and nonrevoked signer roles, retained authority/kit,
strict profile and capacity scope, credential enrollment and signed expiry.
A flag, callback, forged context, schema-valid projection or truthy return value
does not satisfy that eligibility. Missing prerequisites still fail closed.

The hook must perform no credential read, resource acquisition, transport call,
recursive late-resource guard call, observer connection or native probe itself.
It uses only retained authority and the existing fixed custody/check interfaces.
The installed owner performs complete peer checks before and after the hook.
This separation prevents recursion when credential_bytes, transport, tls_memfd
and close_memfd each call the same guard. Every blocking I/O still rechecks
authority, peer, revocation, custody and absolute deadlines.

Only then may the existing late-resource owner read the one root-owned 0400
CAMPAIGN_PROXY_CLIENT_MTLS credential, no-follow and exactly once, retaining its
ancestry and identity. Strict certificate/PEM validation must complete before
TLS use. The existing numeric-family TCP and sealed memfd ownership remain;
the proxy must use MemoryBIO so the raw socket has one close owner. No alternate
credential path, socket adoption, early read, reopen or registry unsealing.

Authentication targets only the independently signed IP/family/port, TLS1.3,
server name/SPKI and release-pinned local CA under MET-REPAIR-009. No DNS,
redirect, proxy environment, resumption, early data, new endpoint, policy-read
request, preflight HTTP operation, auth header or public wire field is added.
The credential is not sent in an HTTP body and is never exposed to campaign
children, logs, artifacts or evidence. Its purpose grants no Kubernetes access.

After authenticated TLS, the client may send exactly the existing fixed POST
request for the active operation. Sending a request is not admission, execution,
quota reservation on the server, evidence acceptance or a native PASS. No client
status may assert "policy observed" from TLS success or stored projections.
Failure or ambiguity consumes the nonce and closes owned I/O; no automatic retry.

## Server: independent execution gate remains mandatory

The independently installed server remains the only policy-observer consumer.
It independently verifies its installation, containment, three signing roles,
retained release/capacity/profile, nonce, client certificate and fixed request.
Client authentication never replaces these checks or authorizes a mutation.

Retain MET-REPAIR-010 startup ordering: establish server custody/containment,
obtain independently current local policy observation and atomically reserve
the run/whole-run headroom before opening server credentials. Server TLS identity
and KUBERNETES_PROXY_SERVER_MTLS credentials do NOT gain the client exception.
The server's TLS key authenticates only this protected server; it is never the
campaign credential. Missing observer/backend prevents protected live startup.

After authenticating the peer and validating each fixed request, obtain fresh
server observation before any upstream credential use, fixed probe or mutation,
and after blocking I/O. Recheck full effective RBAC, namespace UID, quota,
enforcement and pinned policy generation. The preexisting capacity broker must
fence that same generation in its serialized admission transaction before every
effect. A read-only snapshot, client approval or five-second freshness alone is
not this transactional fence. Zero-resource runs also require the observer.

Loss, staleness, generation drift, revocation, quota exhaustion, malformed
request or missing fencing denies effects. Never broaden endpoints/API grants,
create capacity, pull images, contact a billing API, or return a successful
receipt when the probe or required post-I/O checks failed. Cleanup remains
exact-name/exact-UID with independently current permission; otherwise preserve
CLEANUP_PENDING and ambiguous reservations. Do not reclaim a consumed nonce.

## Packet scope, source locks and evidence

This single meta packet changes no product file and creates no new product
packet. CONF-LIVE-003 still owns its exact eight paths and all eight cumulative
commands. Its fixture must bind this authority and the corrected checkpoint:
conformance main 9df7dd7f2df8ac64096ef37d8df259761947d552, tree
1310cc74cc0ed39cfeb1068e998a0f78502a4be4; 127 files / 327 test identities.
All 327 predecessor methods and all historical source proofs remain mandatory.
Stages stay 110/120/127/135/141/146/151; only the original final launcher hook
may change in CONF-LIVE-006. No old test rewrite or new product path exemption.

The machine record pins all 141 old packet bytes, predecessor authority and
source locks, corrected checkpoint, inert diagnostic source slices and exact
meta changes. Its historical-byte bridge checks the exact current approved
AGENTS/test substitutions before comparing old pins. Historical reconstruction
is not current acceptance; no snapshot source is imported, compiled or executed.
Keep test IDs, assertions and parametrization except explicitly enumerated
current-catalog/status/bridge substitutions. Preserve 139/141 historical counts
separately from the current 142-packet / 158-YAML corpus.

Meta tests check the closed authority, pin/recipe/ownership integrity, source
diagnosis and non-authorizing ordering vectors. The vectors are DATA_CHECK_ONLY,
not policy proof, runtime flags, a public protocol or native acceptance.
CONF-LIVE-003 must separately test the actual fixed guard with mocked OS I/O:
first authentication without a client observer; refusal before any local gate;
no recursive acquisition; certificate/endpoint mismatch; authenticated requests
with absent/stale/revoked policy producing no effects; zero-resource observation;
generation races; post-I/O failure; exact-UID cleanup; and no successful receipt
or tenant/native acceptance from transport success alone.

All twenty predecessor commands plus the new data validator run through the
same existing signed offline wrapper, in one deny-all tree. Keep both complete
replays, nested 420 seconds, trusted 900 seconds and workflow fifteen minutes.
No timing/coverage/isolation relaxation; preserve failures and bounded retries.
Required localhost PR CI, merge and independent local exact-main remain separate.
No new root installation/policy/key, administrator prompt, hosted runner,
download, paid API, cloud action, artifact upload or warm-source access.

## Roadmap and rollback

| Phase | ID / gate | Status during publication | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundations | DONE_RECORDED | Source/offline only |
| Alpha 2 | MET-REPAIR-012 / CONF-FIX-005 | DONE_SOURCE_GATES | PR106 / PR11; corrected 127/327 checkpoint |
| Alpha 2 | MET-REPAIR-013 | ONGOING | Authentication/execution ordering authority |
| Alpha 2 | CONF-LIVE-003 | WAITING | Consume this closed source authority, then implement proxy |
| Alpha 2 | CONF-LIVE-004 | WAITING | Ten native Linux probes |
| Alpha 2 | CONF-LIVE-005 | WAITING | Reproducible packaging/operator handoff |
| Alpha 2 | CONF-LIVE-006 | WAITING | Trusted campaign integration |
| Alpha 2 | Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installation and qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | Existing roadmap and tenant decision |

Before consumption, revert this publication as one reviewed unit. After
consumption use a reviewed successor, not a rewrite of accepted authority.
Preserve trust/replay history, tenant data, failed logs and exact-main evidence.
This approval changes source credential ordering; it does not install or authorize
a live campaign. Alpha 2 remains ONGOING; model-effort transition NOT_DUE.
