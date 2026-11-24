#!/usr/bin/env python3
"""Broker handoff transcript model v2 (EDGE-V13, MET-014): v1's DATA model (scripts/validate_broker_handoff.py) with one
clause of validate_transcript changed: CLEANUP_RECORDED no longer needs a received receipt byte (`payload and` dropped
from the "cleanup order" rule), so a no-receipt transcript (STARTED, CLEANUP_RECORDED, then TERMINAL with receiptSize 0)
can end. Valid only with the v13 schema (architecture/broker-handoff-inputs-v2/channel.schema.json): the model does not
refuse a COMPLETED size-0 transcript; the schema's if/then does. ZERO, COMMON, require and _shape are verbatim copies of
v1's; canonical, digest, parse and _bounded come from validate_proxy_contract, where v1 takes them from (bare name first,
then scripts.), so this module never imports validate_broker_handoff. Non-authorizing broker protocol DATA oracle; no
native I/O."""
from __future__ import annotations

import base64

import jsonschema

try:
    from validate_proxy_contract import canonical, digest, parse, _bounded
except ImportError:
    from scripts.validate_proxy_contract import canonical, digest, parse, _bounded

ZERO = "sha256:" + "0" * 64
COMMON = ("bindingDigest", "reservationDigest", "runNonce", "caseId", "requestDigest",
          "observationDigest", "generation", "challenge")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _shape(value, variant, schema):
    _bounded(value)
    limit = 16384 if variant in ("dispatch", "workerStart") else 65536
    require(len(canonical(value)) <= limit, "bounded message required")
    jsonschema.Draft202012Validator({**schema, "oneOf": [{"$ref": "#/$defs/" + variant}]}).validate(value)


def validate_transcript(binding, request, frames, schema):
    """Reject structural/transcript ambiguity; no enforcement result is issued."""
    try:
        _shape(binding, "binding", schema)
        _shape(request, "dispatch", schema)
        require(request["bindingDigest"] == "sha256:" + digest(canonical(binding)), "binding mismatch")
        require(type(frames) is list and 2 <= len(frames) <= 2048, "bounded transcript required")
        previous, execution, pending, chunk_index = ZERO, None, None, 0
        actions, payload, cleanup, ended, action_failed = set(), bytearray(), None, False, False
        for sequence, frame in enumerate(frames, 1):
            _shape(frame, "frame", schema)
            require(not ended and all(frame[k] == request[k] for k in COMMON), "scope/generation changed")
            require(frame["sequence"] == sequence and frame["previousDigest"] == previous, "frame chain mismatch")
            if execution is None:
                require(frame["kind"] == "STARTED", "controlled start required")
                execution = frame["executionId"]
            else:
                require(frame["executionId"] == execution and frame["kind"] != "STARTED", "execution replay")
            kind, data = frame["kind"], frame["payload"]
            if kind == "RESOURCE_ACTION":
                require(pending is None and not payload and cleanup is None
                        and data["actionId"] not in actions
                        and data["manifestDigest"] in binding["caseResourceDigests"][request["caseId"]],
                        "unowned/overlapping resource action")
                pending = data
                actions.add(data["actionId"])
            elif kind == "RESOURCE_RESULT":
                require(pending is not None and pending["actionId"] == data["actionId"], "result has no matching action")
                outcomes = {"CREATE": {"CREATED"}, "GET": {"ABSENT", "PRESENT"}, "DELETE": {"DELETED"}}
                require(data["outcome"] in outcomes[pending["verb"]] | {"DENIED", "AMBIGUOUS"}, "verb/outcome mismatch")
                action_failed |= data["outcome"] in ("DENIED", "AMBIGUOUS")
                if data["objectBase64"] is not None:
                    raw = base64.b64decode(data["objectBase64"], validate=True)
                    require(len(raw) <= 16384 and base64.b64encode(raw).decode() == data["objectBase64"]
                            and canonical(parse(raw)) == raw, "noncanonical resource data")
                require((data["outcome"] in ("CREATED", "PRESENT")) == (data["objectBase64"] is not None),
                        "resource outcome/data mismatch")
                pending = None
            elif kind == "RECEIPT_CHUNK":
                require(pending is None and cleanup is None and data["index"] == chunk_index, "chunk ordering")
                raw = base64.b64decode(data["dataBase64"], validate=True)
                require(0 < len(raw) <= 24576 and base64.b64encode(raw).decode() == data["dataBase64"], "canonical chunk")
                payload.extend(raw)
                require(len(payload) <= 4194304, "receipt size")
                chunk_index += 1
            elif kind == "CLEANUP_RECORDED":
                require(pending is None and cleanup is None, "cleanup order")
                require((data["state"] == "CLEAN") == (not data["remainingResources"]), "cleanup state mismatch")
                names = set()
                for row in data["remainingResources"]:
                    key = (row["kind"], row["namespace"], row["name"])
                    require(key not in names and row["manifestDigest"] in binding["caseResourceDigests"][request["caseId"]]
                            and (row["uid"] is not None or row["reasonCode"] == "IO_AMBIGUOUS"), "cleanup scope")
                    names.add(key)
                cleanup = data
            elif kind == "TERMINAL":
                require(pending is None and cleanup is not None and len(payload) == data["receiptSize"]
                        and "sha256:" + digest(bytes(payload)) == data["receiptDigest"]
                        and data["cleanupDigest"] == cleanup["cleanupDigest"], "terminal receipt mismatch")
                require(data["status"] != "COMPLETED" or cleanup["state"] == "CLEAN" and not action_failed,
                        "failed action or pending cleanup is not completed")
                ended = True
            elif kind != "STARTED":
                raise ValueError("aborted/refused transcript cannot complete")
            previous = "sha256:" + digest(canonical(frame))
        require(ended, "terminal frame missing")
        return []
    except (ValueError, TypeError, KeyError, RecursionError, jsonschema.ValidationError):
        return ["invalid DATA_CHECK_ONLY transcript; no native authority"]
