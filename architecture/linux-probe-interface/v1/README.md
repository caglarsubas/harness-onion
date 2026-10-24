# Linux probe interface (draft): sources

Source: R12 main c17bcfe3 (tree 9c2b2b8a, read at e1b8bb8d). Every path below is an R12 repository path, and every line
number is at e1b8bb8d.

Files: `probe-interface.json` is the draft contract; `probe-interface.schema.json` is its closed JSON Schema (draft
2020-12). A neutral extractor lifted the interface only, under owner decision Q-PK-6. R12's test logic, campaign
internals, server code, credentials, host names and local paths are not part of it.

Field paths use JSON-pointer style; `[name=x]`, `[id=x]` and `[code=x]` select an array entry.

## Field sources

| Field | R12 source at e1b8bb8d |
| --- | --- |
| `/schemaVersion` | contract metadata, not an R12 field |
| `/source/repository` | contract metadata: R12 repository name |
| `/source/commit` | contract metadata: R12 main c17bcfe3, full id from the merge record by operator relay (gap G10) |
| `/source/tree` | contract metadata: tree of e1b8bb8d, equal to the tree of c17bcfe3 per the brief |
| `/source/readAt` | contract metadata: local commit e1b8bb8d |
| `/cases[id=HOST_ISOLATION_NEGATIVES]` | src/harness_conformance/linux_readiness.py:27 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=LINUX_TARGET_BUILD]` | src/harness_conformance/linux_readiness.py:28 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=FULL_PREDECESSOR_REGRESSION]` | src/harness_conformance/linux_readiness.py:29 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=CONTROL_CONTAINER_STARTUP]` | src/harness_conformance/linux_readiness.py:30 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=POSTGRES_MIGRATION_AND_RLS]` | src/harness_conformance/linux_readiness.py:31 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=DURABLE_RESTART]` | src/harness_conformance/linux_readiness.py:32 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=ARBITRARY_NON_ROOT_UID]` | src/harness_conformance/linux_readiness.py:33 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=READ_ONLY_ROOT_FILESYSTEM]` | src/harness_conformance/linux_readiness.py:34 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=KUBERNETES_SMOKE]` | src/harness_conformance/linux_readiness.py:35 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/cases[id=DEFAULT_DENY_NETWORK]` | src/harness_conformance/linux_readiness.py:36 (id, checks); src/harness_conformance/linux_readiness.py:24, 38-39 (order; axis by position); src/harness_conformance/linux_readiness.py:320, 328 (path); src/harness_conformance/live_session.py:161 (path); src/harness_conformance/linux_readiness.py:192-193 (regression repositories); src/harness_conformance/live_session.py:211-212 (regression repositories) |
| `/request/schemaVersion` | src/harness_conformance/linux_readiness.py:336; src/harness_conformance/live_session.py:159 |
| `/request/document/mediaType` | src/harness_conformance/live_proxy_client.py:312; src/harness_conformance/linux_readiness.py:329 |
| `/request/document/maxBytes` | src/harness_conformance/live_session.py:17, 77, 155 (default bound applied to the request) |
| `/request/document/encoding/form` | src/harness_conformance/live_session.py:82-84, 87-89 |
| `/request/document/encoding/gaps` | gap reference (see Gaps below) |
| `/request/document/topLevel` | src/harness_conformance/live_session.py:86 |
| `/request/document/maxDepth` | src/harness_conformance/live_session.py:19, 50 |
| `/request/document/depthCounting` | src/harness_conformance/live_session.py:44, 50, 63-64, 67 |
| `/request/document/maxMembers` | src/harness_conformance/live_session.py:56-57 |
| `/request/document/keyTypes` | src/harness_conformance/live_session.py:60-62 |
| `/request/document/valueTypes` | src/harness_conformance/live_session.py:53, 56, 68-69 |
| `/request/document/integerRange` | src/harness_conformance/live_session.py:70-71 |
| `/request/document/refusals[code=SESSION_SIZE_EXCEEDED]` | src/harness_conformance/live_session.py:54-55, 58-59, 72-73, 79, 83, 88 |
| `/request/document/refusals[code=SESSION_DEPTH_EXCEEDED]` | src/harness_conformance/live_session.py:19, 50 |
| `/request/document/refusals[code=SESSION_COLLECTION_EXCEEDED]` | src/harness_conformance/live_session.py:57 |
| `/request/document/refusals[code=SESSION_TYPE_INVALID]` | src/harness_conformance/live_session.py:62, 69, 71, 86 |
| `/request/document/refusals[code=SESSION_DATA_MALFORMED]` | src/harness_conformance/live_session.py:90-93 |
| `/request/document/gaps` | gap reference (see Gaps below) |
| `/request/members[name=schemaVersion]` | src/harness_conformance/linux_readiness.py:336; src/harness_conformance/live_session.py:33-34, 156, 159 |
| `/request/members[name=operation]` | src/harness_conformance/linux_readiness.py:319, 336; src/harness_conformance/live_session.py:33, 157-158 |
| `/request/members[name=endpointId]` | src/harness_conformance/linux_readiness.py:321, 337; src/harness_conformance/live_session.py:33, 164-165 |
| `/request/members[name=namespace]` | src/harness_conformance/linux_readiness.py:337; src/harness_conformance/live_session.py:33, 164-165 |
| `/request/members[name=method]` | src/harness_conformance/linux_readiness.py:337; src/harness_conformance/live_session.py:33, 160 |
| `/request/members[name=path]` | src/harness_conformance/linux_readiness.py:320, 337; src/harness_conformance/live_session.py:34, 161 |
| `/request/members[name=runNonce]` | src/harness_conformance/linux_readiness.py:338; src/harness_conformance/live_session.py:34, 164-165 |
| `/request/members[name=architecture]` | src/harness_conformance/linux_readiness.py:25, 338; src/harness_conformance/live_session.py:34, 162 |
| `/request/members[name=probeDigest]` | src/harness_conformance/linux_readiness.py:339; src/harness_conformance/live_session.py:34, 166-167 |
| `/request/members[name=commandDigest]` | src/harness_conformance/linux_readiness.py:339; src/harness_conformance/live_session.py:34, 166-167 |
| `/request/inputsCopied/envelope` | src/harness_conformance/linux_readiness.py:338 |
| `/request/inputsCopied/capacity` | src/harness_conformance/linux_readiness.py:336-339 (the returned request copies no capacity member) |
| `/request/inputsCopied/plan` | src/harness_conformance/linux_readiness.py:321, 337-339 |
| `/receipt/document/mediaType` | src/harness_conformance/live_proxy_client.py:312; src/harness_conformance/linux_readiness.py:329 |
| `/receipt/document/maxBytes` | src/harness_conformance/live_session.py:18, 79, 193; src/harness_conformance/live_proxy_client.py:316; src/harness_conformance/linux_readiness.py:330 |
| `/receipt/document/encoding/form` | src/harness_conformance/live_session.py:82-84, 87-89 |
| `/receipt/document/encoding/gaps` | gap reference (see Gaps below) |
| `/receipt/document/topLevel` | src/harness_conformance/live_session.py:86 |
| `/receipt/document/maxDepth` | src/harness_conformance/live_session.py:19, 50 |
| `/receipt/document/depthCounting` | src/harness_conformance/live_session.py:44, 50, 63-64, 67 |
| `/receipt/document/maxMembers` | src/harness_conformance/live_session.py:56-57 |
| `/receipt/document/keyTypes` | src/harness_conformance/live_session.py:60-62 |
| `/receipt/document/valueTypes` | src/harness_conformance/live_session.py:53, 56, 68-69 |
| `/receipt/document/integerRange` | src/harness_conformance/live_session.py:70-71 |
| `/receipt/document/refusals[code=SESSION_SIZE_EXCEEDED]` | src/harness_conformance/live_session.py:54-55, 58-59, 72-73, 79, 83, 88 |
| `/receipt/document/refusals[code=SESSION_DEPTH_EXCEEDED]` | src/harness_conformance/live_session.py:19, 50 |
| `/receipt/document/refusals[code=SESSION_COLLECTION_EXCEEDED]` | src/harness_conformance/live_session.py:57 |
| `/receipt/document/refusals[code=SESSION_TYPE_INVALID]` | src/harness_conformance/live_session.py:62, 69, 71, 86 |
| `/receipt/document/refusals[code=SESSION_DATA_MALFORMED]` | src/harness_conformance/live_session.py:90-93 |
| `/receipt/document/gaps` | gap reference (see Gaps below) |
| `/receipt/statuses` | src/harness_conformance/linux_readiness.py:46; src/harness_conformance/live_session.py:12, 208 |
| `/receipt/repositories` | src/harness_conformance/linux_readiness.py:40; src/harness_conformance/live_session.py:12, 211 |
| `/receipt/inventory/count` | src/harness_conformance/linux_readiness.py:180-181 |
| `/receipt/inventory/ordered` | src/harness_conformance/linux_readiness.py:182-184 |
| `/receipt/fields[name=caseId]` | src/harness_conformance/linux_readiness.py:183-184; src/harness_conformance/live_session.py:35, 194-197 |
| `/receipt/fields[name=status]` | src/harness_conformance/linux_readiness.py:46, 183-184; src/harness_conformance/live_session.py:35 |
| `/receipt/fields[name=observedAt]` | src/harness_conformance/linux_readiness.py:75-77, 185; src/harness_conformance/live_session.py:35 |
| `/receipt/fields[name=runNonce]` | src/harness_conformance/linux_readiness.py:186; src/harness_conformance/live_session.py:35, 195-197 |
| `/receipt/fields[name=probeDigest]` | src/harness_conformance/linux_readiness.py:187-188; src/harness_conformance/live_session.py:35, 196-197 |
| `/receipt/fields[name=commandDigest]` | src/harness_conformance/linux_readiness.py:187-188; src/harness_conformance/live_session.py:36, 196-197 |
| `/receipt/fields[name=outputDigest]` | src/harness_conformance/linux_readiness.py:187-188, 199; src/harness_conformance/live_session.py:36, 233-234 |
| `/receipt/fields[name=output]` | src/harness_conformance/linux_readiness.py:189; src/harness_conformance/live_session.py:36, 201-203 |
| `/receipt/output/members[name=checks]` | src/harness_conformance/linux_readiness.py:71, 190-191; src/harness_conformance/live_session.py:204, 207-209 |
| `/receipt/output/members[name=regressions]` | src/harness_conformance/linux_readiness.py:192-193; src/harness_conformance/live_session.py:204, 211-212 |
| `/receipt/output/regression/fields[name=inventoryDigest]` | src/harness_conformance/linux_readiness.py:195-196 |
| `/receipt/output/regression/fields[name=collected]` | src/harness_conformance/linux_readiness.py:87-88, 195, 197-198 |
| `/receipt/output/regression/fields[name=executed]` | src/harness_conformance/linux_readiness.py:87-88, 195, 197-198 |
| `/receipt/output/regression/fields[name=skipped]` | src/harness_conformance/linux_readiness.py:87-88, 195, 197-198 |
| `/receipt/output/regression/fields[name=failed]` | src/harness_conformance/linux_readiness.py:87-88, 195, 197-198 |
| `/http/transport/protocol` | src/harness_conformance/linux_readiness.py:327 |
| `/http/transport/tlsVersion` | src/harness_conformance/live_proxy_client.py:178, 267 |
| `/http/transport/alpn` | src/harness_conformance/live_proxy_client.py:187, 268 |
| `/http/transport/sessionResumption` | src/harness_conformance/live_proxy_client.py:267 |
| `/http/transport/sessionTickets` | src/harness_conformance/live_proxy_client.py:182 |
| `/http/transport/compression` | src/harness_conformance/live_proxy_client.py:182 |
| `/http/transport/mutualTls` | src/harness_conformance/live_proxy_client.py:177, 179, 191, 269, 371 |
| `/http/transport/serverIdentity` | src/harness_conformance/live_proxy_client.py:145-148, 180, 201 |
| `/http/transport/serverCertificate/dnsSubjectAltName` | src/harness_conformance/live_proxy_client.py:123, 145, 147, 180-181, 201 |
| `/http/transport/serverCertificate/wildcardSubjectAltName` | src/harness_conformance/live_proxy_client.py:148 |
| `/http/transport/serverCertificate/publicKeyPinned` | src/harness_conformance/live_proxy_client.py:124, 146 |
| `/http/transport/serverCertificate/chainVerified` | src/harness_conformance/live_proxy_client.py:179, 186, 190 |
| `/http/transport/identityGaps` | gap reference (see Gaps below) |
| `/http/transport/requestsPerConnection` | src/harness_conformance/live_proxy_client.py:285, 292, 341 |
| `/http/transport/maxReceivedBytesPerConnection` | src/harness_conformance/live_proxy_client.py:261 |
| `/http/transport/codes[code=TLS_PROTOCOL_INVALID]` | src/harness_conformance/live_proxy_client.py:267-268 |
| `/http/transport/codes[code=TLS_EOF_OR_SIZE]` | src/harness_conformance/live_proxy_client.py:261 |
| `/http/request/requestLine` | src/harness_conformance/live_proxy_client.py:320, 384 |
| `/http/request/headers[name=Content-Type]` | src/harness_conformance/live_proxy_client.py:292 |
| `/http/request/headers[name=Content-Length]` | src/harness_conformance/live_proxy_client.py:292, 313 |
| `/http/request/headers[name=Connection]` | src/harness_conformance/live_proxy_client.py:292 |
| `/http/request/headers[name=Host]` | src/harness_conformance/live_proxy_client.py:293-295, 384 |
| `/http/request/body` | src/harness_conformance/live_proxy_client.py:384 |
| `/http/request/minBodyBytes` | src/harness_conformance/live_proxy_client.py:316 |
| `/http/request/maxBodyBytes` | src/harness_conformance/live_proxy_client.py:316; src/harness_conformance/linux_readiness.py:330 |
| `/http/response/statusLine` | src/harness_conformance/live_proxy_client.py:318 |
| `/http/response/headers[name=Content-Type]` | src/harness_conformance/live_proxy_client.py:311-312 |
| `/http/response/headers[name=Content-Length]` | src/harness_conformance/live_proxy_client.py:311, 313 |
| `/http/response/headers[name=Connection]` | src/harness_conformance/live_proxy_client.py:311, 313 |
| `/http/response/body` | src/harness_conformance/live_proxy_client.py:385, 387; src/harness_conformance/live_session.py:82-84, 87-89, 193-194 |
| `/http/response/minBodyBytes` | src/harness_conformance/live_proxy_client.py:316 |
| `/http/response/maxBodyBytes` | src/harness_conformance/live_proxy_client.py:316; src/harness_conformance/linux_readiness.py:330; src/harness_conformance/live_session.py:18 |
| `/http/response/endOfStream` | src/harness_conformance/live_proxy_client.py:261, 347-348 |
| `/http/headerRules/lineSeparator` | src/harness_conformance/live_proxy_client.py:292, 296, 301 |
| `/http/headerRules/terminator` | src/harness_conformance/live_proxy_client.py:296, 300, 328 |
| `/http/headerRules/fieldSeparator` | src/harness_conformance/live_proxy_client.py:305-306 |
| `/http/headerRules/maxHeaderBlockBytes` | src/harness_conformance/live_proxy_client.py:300, 329 |
| `/http/headerRules/maxLines` | src/harness_conformance/live_proxy_client.py:302 |
| `/http/headerRules/nameCase` | src/harness_conformance/live_proxy_client.py:307 |
| `/http/headerRules/allowedNames` | src/harness_conformance/live_proxy_client.py:308 |
| `/http/headerRules/duplicateNames` | src/harness_conformance/live_proxy_client.py:308 |
| `/http/headerRules/valueByteRange` | src/harness_conformance/live_proxy_client.py:309 |
| `/http/headerRules/leadingWhitespace` | src/harness_conformance/live_proxy_client.py:305 |
| `/http/headerRules/contentLengthPattern` | src/harness_conformance/live_proxy_client.py:313 |
| `/http/service/name` | src/harness_conformance/linux_readiness.py:326 |
| `/http/service/protocol` | src/harness_conformance/linux_readiness.py:327 |
| `/http/service/methods` | src/harness_conformance/linux_readiness.py:327 |
| `/http/service/paths` | src/harness_conformance/linux_readiness.py:328 |
| `/http/service/requestMediaType` | src/harness_conformance/linux_readiness.py:329 |
| `/http/service/responseMediaType` | src/harness_conformance/linux_readiness.py:329 |
| `/http/service/requestMaxBytes` | src/harness_conformance/linux_readiness.py:330 |
| `/http/service/responseMaxBytes` | src/harness_conformance/linux_readiness.py:330 |
| `/http/service/timeoutSeconds` | src/harness_conformance/linux_readiness.py:330 |
| `/http/service/portSource` | src/harness_conformance/linux_readiness.py:327 (value not recorded, gap G13) |
| `/http/timeouts/connectSeconds` | src/harness_conformance/live_proxy_client.py:380 |
| `/http/timeouts/tlsHandshakeSeconds` | src/harness_conformance/live_proxy_client.py:266 |
| `/http/timeouts/responseHeaderSeconds` | src/harness_conformance/live_proxy_client.py:327 |
| `/http/refusals[code=HTTP_MESSAGE_INVALID]` | src/harness_conformance/live_proxy_client.py:290-291 |
| `/http/refusals[code=HTTP_HOST_INVALID]` | src/harness_conformance/live_proxy_client.py:294 |
| `/http/refusals[code=HTTP_HEADERS_SIZE]` | src/harness_conformance/live_proxy_client.py:329 |
| `/http/refusals[code=HTTP_TRUNCATED_HEADERS]` | src/harness_conformance/live_proxy_client.py:331 |
| `/http/refusals[code=HTTP_HEADERS_INVALID]` | src/harness_conformance/live_proxy_client.py:300-305, 311-314 |
| `/http/refusals[code=HTTP_HEADER_FORBIDDEN]` | src/harness_conformance/live_proxy_client.py:307-309 |
| `/http/refusals[code=HTTP_BODY_SIZE]` | src/harness_conformance/live_proxy_client.py:315-316 |
| `/http/refusals[code=HTTP_STATUS_INVALID]` | src/harness_conformance/live_proxy_client.py:317-318 |
| `/http/refusals[code=HTTP_REQUEST_TARGET]` | src/harness_conformance/live_proxy_client.py:319-321 |
| `/http/refusals[code=HTTP_SURPLUS]` | src/harness_conformance/live_proxy_client.py:335, 340, 347-348 |
| `/http/refusals[code=HTTP_TRUNCATED_BODY]` | src/harness_conformance/live_proxy_client.py:338 |
| `/http/refusals[code=HTTP_PIPELINING]` | src/harness_conformance/live_proxy_client.py:341 |
| `/http/refusals[code=HTTP_BUFFERED_RECORD_SURPLUS]` | src/harness_conformance/live_proxy_client.py:342-346 |

## Gaps (form only recorded)

- **G1.** Digest form. R12's digest validator (require_digest, in a module outside the four allowed files) was not read. The pattern ^sha256:[0-9a-f]{64}$ is observed only from the PACKET_DIGEST constant (src/harness_conformance/linux_readiness.py:23); every digest field carries patternRead=false.
- **G2.** Id form. R12's id validator (require_id) was not read; endpointId, namespace and runNonce carry form "id" with no pattern.
- **G3.** Canonical encoding. canonical_bytes, require_canonical_document and canonical_digest(value, domain) live in a module outside the allowed files. The canonical JSON rules of the request and receipt documents, and outputDigest's byte construction and hash, are recorded by name and domain tag only.
- **G4.** probeDigest and commandDigest. The read files never state which bytes these digest. They are recorded as values copied from the plan's probes.<caseId> (src/harness_conformance/linux_readiness.py:339) and echoed in the receipt (src/harness_conformance/live_session.py:195-197).
- **G5.** inventoryDigest. Only the digest form is recorded. The rules that judge this value are not part of this contract.
- **G6.** Document decoding. The document form rules (top-level object, depth, members, key and value types, integer range, byte bounds and their refusal codes) are recorded from src/harness_conformance/live_session.py:17-19, 44-93. What stays unread is the canonical byte rules behind require_canonical_document and canonical_bytes (G3), and so which refusal code a byte string that is not canonical JSON raises.
- **G7.** Exact receipt validation in the native channel (src/harness_conformance/live_proxy_client.py:387 comment) lives in a module outside the allowed files. The receipt form here comes from live_session.validate_receipt and linux_readiness.validate_linux_evidence.
- **G8.** status. Only the three allowed values are recorded. The rules that judge this value are not part of this contract.
- **G9.** Regression counts. Only the integer form 0..10000000 (src/harness_conformance/linux_readiness.py:87-88) is recorded. The rules that judge these values are not part of this contract.
- **G10.** Source commit. c17bcfe3 is not present in the local clone, and resolving it would need the network. source.commit holds the full id c17bcfe32df26eab13844b73f65666bb0fa4e0a0, which came from the PR #33 merge record by operator relay. tree and readAt are full ids resolved locally.
- **G11.** observedAt. Only the time form is recorded. The rules that judge this value are not part of this contract.
- **G12.** Host header. Its value is the selected endpoint's tls.serverName (src/harness_conformance/live_proxy_client.py:384); only the form is recorded, no host name.
- **G13.** Service port. It comes from the selected envelope endpoint's port (src/harness_conformance/linux_readiness.py:327); no value is recorded.
- **G14.** TLS identity. Only the form of what the client requires of the server is recorded: TLS is mutual (src/harness_conformance/live_proxy_client.py:177, 179, 191, 269, 371); the server certificate carries the selected endpoint's tls.serverName as a DNS subjectAltName, with no common-name fallback (src/harness_conformance/live_proxy_client.py:123, 145, 147, 180-181, 201); a subjectAltName that contains "*" is refused (src/harness_conformance/live_proxy_client.py:148); the server's public key is pinned (src/harness_conformance/live_proxy_client.py:124, 146); and the server chain is checked against the configured CA under strict X.509 checks (src/harness_conformance/live_proxy_client.py:179, 186, 190). No certificate, key, name or digest value is part of this contract.
- **G15.** closed() semantics. closed() lives in a module outside the allowed files. That it refuses a key outside the listed names is recorded. That it also requires every listed name to be present is inferred from the closed() calls: for checks (src/harness_conformance/linux_readiness.py:71, 190; src/harness_conformance/live_session.py:207), and for regressions (src/harness_conformance/linux_readiness.py:71, 193; src/harness_conformance/live_session.py:212).

## Cross-check against the documented boundary

`docs/live-backend/linux-boundary.md` documents the supervisor and custody boundary, not the probe message forms. It agrees with the draft
where it touches the interface: the single transport hook
`live_proxy_client.execute_protected(request, installed_context, deadline)` (docs/live-backend/linux-boundary.md:161-162), TLS identity
and a bounded request and response among the proxy's obligations (docs/live-backend/linux-boundary.md:169-172), and the ten real probes
owned by a later packet (docs/live-backend/linux-boundary.md:173-174); the ten fixed operations themselves are declared at
src/harness_conformance/linux_readiness.py:26-38. The document states no field, header or refusal code that conflicts with the draft.
