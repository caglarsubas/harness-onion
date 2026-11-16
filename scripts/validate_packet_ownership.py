#!/usr/bin/env python3
"""Closed ownership checks for implementation task packets.

This module intentionally has no workspace I/O.  The readiness validator passes
the already schema-validated packet mapping here, which keeps the ownership
rules small enough to exercise with negative unit vectors.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

PRODUCT_BOOTSTRAP_PACKETS = {
    "mas-harness-contracts": "CON-001",
    "mas-harness-sdks": "SDK-001",
    "mas-harness-industry-packs": "IND-001",
    "mas-harness-control-plane": "CTRL-001",
    "mas-harness-runtime-plane": "RUN-001",
    "mas-harness-model-plane": "MODEL-001",
    "mas-harness-knowledge-plane": "KN-001",
    "mas-harness-execution-plane": "EXEC-001",
    "mas-harness-trust-plane": "TRUST-001",
    "mas-harness-operator": "OP-001",
    "mas-harness-distribution": "DIST-001",
    "mas-harness-conformance-labs": "CONF-001",
}

CONFORMANCE_GENERIC_MAKE_TARGETS = {
    "campaign",
    "evidence-verify",
    "acceptance-package",
}

CONTROL_BOOTSTRAP_CORRECTION_PATHS = {
    "AGENTS.md",
    "ci/handlers/prefetch.py",
    "ci/targets/ctrl-fix-001.json",
    "tests/bootstrap/test_static_contract.py",
}

DISTRIBUTION_BOOTSTRAP_CORRECTION_PATHS = {
    "AGENTS.md",
    "Makefile",
    "ci/targets/dist-fix-001.json",
    "tests/bootstrap/test_dispatch.py",
}

ALLOWED_MAKE_VARIABLES = {
    "BACKEND",
    "CAMPAIGN",
    "MODULE",
    "PACK",
    "PROVIDERS",
}

HARNESSCTL_COMMAND_OWNERS = {
    "validate": (
        "CON-002",
        "src/planeon_harness_contracts/commands/validate.json",
    ),
    "catalog": (
        "CON-002",
        "src/planeon_harness_contracts/commands/catalog.json",
    ),
    "verify-determinism": (
        "CON-004",
        "src/planeon_harness_contracts/commands/verify-determinism.json",
    ),
    "compatibility": (
        "CON-006",
        "src/planeon_harness_contracts/commands/compatibility.json",
    ),
}

MAKE_TARGET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
MAKE_VARIABLE_PATTERN = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\x00\s;|&`$<>]+)$")


# MET-009 (slot 291; MON-291-DESIGN-RULE D1 (a), ANNEX_291): each plane's health shell precedes the plane's registered
# bootstrap. Closed: exactly these three rows, each five strings. A row orders its shell before its registered bootstrap
# only while both packets are in the mapping, each names its plane's repository, and each packet's canonical content
# digest (sha256 of the parsed packet as sorted-key compact JSON; this module does no workspace I/O) equals the row's;
# it orders nothing else. A row whose shell is absent is skipped; a present shell without its registered bootstrap, a
# repository mismatch, and a digest that differs or cannot be computed each refuse that row. The published YAML
# digests of the same packets:
#   RUN-001 YAML sha256 4fa60ad4793d2268ccd5f84e0cbc4ce3d45340abf2ba824b30cc895b5a618457; PLANE-BOOTSTRAP-R05 YAML sha256 a9c03745470c3c9fd209fd111249b96a9705151571a589576f6f2e93aa6dcd2b
#   MODEL-001 YAML sha256 753847ad57b2247a281b23c8f7db1956da3ae5d33f32433b25e80d44585160c0; PLANE-BOOTSTRAP-R06 YAML sha256 8718777c765977bd26015c26cd62a593e6db9d960c7eb4f6d44748ac35e4f4ae
#   EXEC-001 YAML sha256 7a6a95f429315d157c8f2ee4bcfb63584bbfd2ae9dcfb26420adaf30fbf76108; PLANE-BOOTSTRAP-R08 YAML sha256 534065bd434de67faddb91af738c61ebe33e9acaa2d2dec5110e0e1181c877ec
PLANE_SHELL_ORDER = (
    ("mas-harness-runtime-plane", "RUN-001", "78e61ca9adba62e5e11e49d58c1a28ea7a98ed0f61f8b30d6b2f4cb0b8597150", "PLANE-BOOTSTRAP-R05", "c961cb71c3ffde53681364619ab6c8eb4a674135d64c5b486e30df7ab47b9f03"),
    ("mas-harness-model-plane", "MODEL-001", "3151b8f0d5568a916e44df7d3147be598d3420e38cddf6dd3f2ddd44f3e98d6d", "PLANE-BOOTSTRAP-R06", "b7f2a079dc05e901a86bf1ed9e06c61c194bea70c5400ab732c7cea492a1340d"),
    ("mas-harness-execution-plane", "EXEC-001", "296daa3ddd4e361c54dc87f33fc63c341ffac8f805f1f0858c7c4870a40ee99d", "PLANE-BOOTSTRAP-R08", "70a9a32c6092ac7301bc399a3421a93bb804977e37431b53ebc403c6bdf0a74e"),
)


def packet_content_sha256(packet: dict[str, Any]) -> str:
    """The canonical content digest of one parsed packet."""

    return hashlib.sha256(
        json.dumps(packet, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def plane_shell_order(
    packets: dict[str, dict[str, Any]], table: tuple[tuple[str, str, str, str, str], ...] | None = None
) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    """The extra predecessors the closed plane-shell table grants, and its refusals."""

    rows = PLANE_SHELL_ORDER if table is None else table
    planes = {
        "mas-harness-runtime-plane": "PLANE-BOOTSTRAP-R05",
        "mas-harness-model-plane": "PLANE-BOOTSTRAP-R06",
        "mas-harness-execution-plane": "PLANE-BOOTSTRAP-R08",
    }
    if (
        len(rows) != 3
        or any(not isinstance(row, tuple) or len(row) != 5 for row in rows)
        or any(not isinstance(cell, str) for row in rows for cell in row)
        or sorted(row[0] for row in rows) != sorted(planes)
        or any(row[1] != PRODUCT_BOOTSTRAP_PACKETS.get(row[0]) for row in rows)
        or any(row[3] != planes.get(row[0]) for row in rows)
        or len({row[1] for row in rows} | {row[3] for row in rows}) != 6
    ):
        return {}, ["plane shell order table must hold exactly the three closed rows"]
    extra: dict[str, tuple[str, ...]] = {}
    errors: list[str] = []
    for repository, registered_id, registered_sha, shell_id, shell_sha in rows:
        if shell_id not in packets:
            continue
        if registered_id not in packets:
            errors.append(f"plane shell order row {shell_id}: {registered_id} absent")
            continue
        registered, shell = packets[registered_id], packets[shell_id]
        if registered.get("repository") != repository or shell.get("repository") != repository:
            errors.append(f"plane shell order row {shell_id}: repository mismatch")
            continue
        for packet_id, packet, expected in ((registered_id, registered, registered_sha), (shell_id, shell, shell_sha)):
            try:
                digest = packet_content_sha256(packet)
            except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
                errors.append(f"plane shell order row {shell_id}: {packet_id} content digest unavailable")
                break
            if digest != expected:
                errors.append(f"plane shell order row {shell_id}: {packet_id} content digest mismatch")
                break
        else:
            extra[registered_id] = (shell_id,)
    return extra, errors


def packet_ancestors(
    packets: dict[str, dict[str, Any]], extra: dict[str, tuple[str, ...]] | None = None
) -> dict[str, set[str]]:
    """Return the transitive predecessor closure for every packet."""

    cache: dict[str, set[str]] = {}

    def visit(packet_id: str, visiting: set[str]) -> set[str]:
        if packet_id in cache:
            return cache[packet_id]
        if packet_id in visiting:
            return set()
        next_visiting = {*visiting, packet_id}
        result: set[str] = set()
        for predecessor in [*packets.get(packet_id, {}).get("predecessors", []), *(extra or {}).get(packet_id, ())]:
            result.add(predecessor)
            result.update(visit(predecessor, next_visiting))
        cache[packet_id] = result
        return result

    for packet_id in packets:
        visit(packet_id, set())
    return cache


def path_is_covered(allowed_paths: list[str], required_path: str) -> bool:
    """Return whether a packet path grant covers one exact repository path."""

    normalized_required = str(PurePosixPath(required_path))
    return any(
        normalized_required == str(PurePosixPath(allowed_path))
        or normalized_required.startswith(
            str(PurePosixPath(allowed_path)).rstrip("/") + "/"
        )
        for allowed_path in allowed_paths
    )


def paths_overlap(left: str, right: str) -> bool:
    """Return whether two repository-local path grants can address one path."""

    normalized_left = str(PurePosixPath(left)).rstrip("/")
    normalized_right = str(PurePosixPath(right)).rstrip("/")
    return (
        normalized_left == normalized_right
        or normalized_left.startswith(normalized_right + "/")
        or normalized_right.startswith(normalized_left + "/")
    )


def parse_make_command(packet_id: str, command: Any) -> tuple[str | None, list[str]]:
    """Parse a closed direct-argv Make invocation and return target/errors."""

    if (
        not isinstance(command, list)
        or not command
        or not isinstance(command[0], str)
        or PurePosixPath(command[0]).name != "make"
    ):
        return None, []
    errors: list[str] = []
    if len(command) < 2 or not isinstance(command[1], str):
        return None, [f"packet {packet_id} make argv must name exactly one target"]
    target = command[1]
    if not MAKE_TARGET_PATTERN.fullmatch(target):
        errors.append(
            f"packet {packet_id} make target {target!r} is not a closed lexical target"
        )
    seen_variables: set[str] = set()
    for argument in command[2:]:
        if not isinstance(argument, str):
            errors.append(
                f"packet {packet_id} make argument {argument!r} is not NAME=value"
            )
            continue
        match = MAKE_VARIABLE_PATTERN.fullmatch(argument)
        if match is None:
            errors.append(
                f"packet {packet_id} make argument {argument!r} is not a safe NAME=value binding"
            )
            continue
        variable = match.group(1)
        if variable not in ALLOWED_MAKE_VARIABLES:
            errors.append(
                f"packet {packet_id} make variable {variable!r} is not declared"
            )
        if variable in seen_variables:
            errors.append(
                f"packet {packet_id} repeats make variable {variable!r}"
            )
        seen_variables.add(variable)
    return target, errors


def _all_commands(packet: dict[str, Any]) -> list[Any]:
    return [
        *packet.get("prefetchCommands", []),
        *packet.get("offlineAcceptanceCommands", []),
    ]


def validate_packet_ownership(packets: dict[str, dict[str, Any]]) -> list[str]:
    """Validate Make, CLI, porting-ledger, and path ownership closure."""

    errors: list[str] = []
    extra, order_errors = plane_shell_order(packets)
    errors.extend(order_errors)
    ancestors = packet_ancestors(packets, extra)

    present_product_repositories = {
        packet.get("repository")
        for packet in packets.values()
        if packet.get("repository") in PRODUCT_BOOTSTRAP_PACKETS
    }
    for repository in sorted(present_product_repositories):
        bootstrap_packet_id = PRODUCT_BOOTSTRAP_PACKETS[repository]
        if packets.get(bootstrap_packet_id, {}).get("repository") != repository:
            errors.append(
                f"product repository {repository} must contain bootstrap packet {bootstrap_packet_id}"
            )

    make_targets: dict[str, set[str]] = {}
    for packet_id, packet in packets.items():
        targets: set[str] = set()
        for command in _all_commands(packet):
            target, command_errors = parse_make_command(packet_id, command)
            errors.extend(command_errors)
            if target is not None:
                targets.add(target)
        make_targets[packet_id] = targets

        repository = packet.get("repository")
        bootstrap_packet = PRODUCT_BOOTSTRAP_PACKETS.get(repository)
        allowed_paths = packet.get("allowedPaths", [])
        # Q-VX45-6 successor ids (MET-SECTOR-005, Q278-4 (b)): <P> plus one capital letter whose predecessors are
        # exactly [<P>], with <P> in the catalog naming the same repository, keep <P>'s exact descriptor.
        descriptor_id = packet_id
        successor = re.fullmatch(r"(.*[0-9])([A-Z])", packet_id)
        if (successor and packet.get("predecessors") == [successor.group(1)]
                and packets.get(successor.group(1), {}).get("repository") == repository):
            descriptor_id = successor.group(1)
        descriptor_path = f"ci/targets/{descriptor_id.casefold()}.json"
        owns_makefile = "Makefile" in allowed_paths
        owns_descriptor = descriptor_path in allowed_paths

        is_product_bootstrap = packet_id == bootstrap_packet
        is_generic_conformance_consumer = (
            repository == "mas-harness-conformance-labs"
            and packet_id != "CONF-001"
            and bool(targets)
            and targets <= CONFORMANCE_GENERIC_MAKE_TARGETS
        )

        if packet_id == "CTRL-FIX-001":
            if repository != "mas-harness-control-plane":
                errors.append("CTRL-FIX-001 must target mas-harness-control-plane")
            if packet.get("predecessors") != ["CTRL-001"]:
                errors.append("CTRL-FIX-001 must depend only on CTRL-001")
            if set(allowed_paths) != CONTROL_BOOTSTRAP_CORRECTION_PATHS:
                errors.append("CTRL-FIX-001 path authority is not the closed bootstrap correction")
            if targets != {"prefetch", "prefetch-lineage-regression", "bootstrap-e2e", "zero-bill"}:
                errors.append("CTRL-FIX-001 Make targets are not the closed bootstrap correction set")
        elif repository == "mas-harness-control-plane" and packet_id != "CTRL-001":
            forbidden_correction_paths = CONTROL_BOOTSTRAP_CORRECTION_PATHS - {
                "ci/targets/ctrl-fix-001.json"
            }
            if any(
                paths_overlap(path, forbidden)
                for path in allowed_paths
                for forbidden in forbidden_correction_paths
            ):
                errors.append(
                    f"product packet {packet_id} overlaps the CTRL-FIX-001 bootstrap correction"
                )

        if packet_id == "DIST-FIX-001":
            if repository != "mas-harness-distribution":
                errors.append("DIST-FIX-001 must target mas-harness-distribution")
            if packet.get("predecessors") != ["DIST-001"]:
                errors.append("DIST-FIX-001 must depend only on DIST-001")
            if set(allowed_paths) != DISTRIBUTION_BOOTSTRAP_CORRECTION_PATHS:
                errors.append("DIST-FIX-001 path authority is not the closed bootstrap correction")
            if targets != {"prefetch", "dist-fix-regression", "zero-bill"}:
                errors.append("DIST-FIX-001 Make targets are not the closed bootstrap correction set")
        elif repository == "mas-harness-distribution" and packet_id != "DIST-001":
            forbidden_correction_paths = DISTRIBUTION_BOOTSTRAP_CORRECTION_PATHS - {
                "ci/targets/dist-fix-001.json"
            }
            if any(
                paths_overlap(path, forbidden)
                for path in allowed_paths
                for forbidden in forbidden_correction_paths
            ):
                errors.append(
                    f"product packet {packet_id} overlaps the DIST-FIX-001 bootstrap correction"
                )

        if is_product_bootstrap:
            if not owns_makefile:
                errors.append(
                    f"product bootstrap packet {packet_id} must own Makefile"
                )
            if not path_is_covered(allowed_paths, "ci/run_make_target.py"):
                errors.append(
                    f"product bootstrap packet {packet_id} must own ci/run_make_target.py"
                )
            if owns_descriptor:
                errors.append(
                    f"product bootstrap packet {packet_id} must not own a later-packet descriptor"
                )
            bootstrap_authority_text = "\n".join(
                str(item)
                for field in ("contracts", "deliverables", "expectedEvidence")
                for item in packet.get(field, [])
            ).casefold()
            for required_phrase in (
                "closed packet-local make target descriptor dispatch v1",
                "bootstrap makefile delegates only to ci/run_make_target.py",
                "negative make-dispatch vectors reject",
                "inert destination porting ledger v1 with zero current copy authorizations",
                "porting.yaml contains only the closed no_authorization bootstrap sentinel",
                "porting bootstrap validation proves zero authorized source mappings",
            ):
                if required_phrase not in bootstrap_authority_text:
                    errors.append(
                        f"product bootstrap packet {packet_id} omits authority phrase {required_phrase!r}"
                    )
        elif repository in PRODUCT_BOOTSTRAP_PACKETS and owns_makefile and packet_id != "DIST-FIX-001":
            errors.append(
                f"product packet {packet_id} may not share bootstrap-owned Makefile"
            )

        if is_generic_conformance_consumer:
            if owns_descriptor:
                errors.append(
                    f"generic conformance packet {packet_id} must use CONF-001 targets without a local descriptor"
                )
            if "CONF-001" not in ancestors.get(packet_id, set()):
                errors.append(
                    f"generic conformance packet {packet_id} must depend transitively on CONF-001"
                )
        elif targets and not is_product_bootstrap and repository in PRODUCT_BOOTSTRAP_PACKETS:
            if not owns_descriptor:
                errors.append(
                    f"packet {packet_id} make targets require exact descriptor {descriptor_path}"
                )

        descriptor_grants = [
            path for path in allowed_paths if path.startswith("ci/targets/")
        ]
        if not targets and descriptor_grants:
            errors.append(
                f"packet {packet_id} owns Make descriptors without invoking Make"
            )
        if descriptor_grants and descriptor_grants != [descriptor_path]:
            errors.append(
                f"packet {packet_id} may own only exact descriptor {descriptor_path}"
            )

        has_porting_ledger = "PORTING.yaml" in allowed_paths
        has_port_candidate = any(
            source.get("reuseMode") == "PORT_CANDIDATE"
            for source in packet.get("sourceReuse", [])
            if isinstance(source, dict)
        )
        if has_porting_ledger and not (is_product_bootstrap or has_port_candidate):
            errors.append(
                f"ordinary packet {packet_id} may not own bootstrap PORTING.yaml"
            )
        if is_product_bootstrap and not has_porting_ledger:
            errors.append(
                f"product bootstrap packet {packet_id} must seed inert PORTING.yaml"
            )

        for command in _all_commands(packet):
            if not isinstance(command, list):
                continue
            command_indexes = [
                index
                for index, argument in enumerate(command)
                if isinstance(argument, str)
                and PurePosixPath(argument).name == "harnessctl"
            ]
            if not command_indexes:
                continue
            if len(command_indexes) != 1:
                errors.append(
                    f"packet {packet_id} harnessctl argv must contain one command boundary"
                )
                continue
            command_index = command_indexes[0]
            if len(command) <= command_index + 1:
                errors.append(f"packet {packet_id} harnessctl argv lacks a command")
                continue
            command_name = command[command_index + 1]
            owner_record = HARNESSCTL_COMMAND_OWNERS.get(command_name)
            if owner_record is None:
                errors.append(
                    f"packet {packet_id} invokes unregistered harnessctl command {command_name!r}"
                )
                continue
            owner_packet_id, command_descriptor = owner_record
            if packet_id != owner_packet_id and owner_packet_id not in ancestors.get(
                packet_id, set()
            ):
                errors.append(
                    f"packet {packet_id} invokes harnessctl {command_name} outside owner predecessor closure"
                )
            owner_packet = packets.get(owner_packet_id)
            if owner_packet is None or command_descriptor not in owner_packet.get(
                "allowedPaths", []
            ):
                errors.append(
                    f"harnessctl {command_name} owner {owner_packet_id} must own exact descriptor {command_descriptor}"
                )

    packet_items = sorted(packets.items())
    for index, (left_id, left_packet) in enumerate(packet_items):
        for right_id, right_packet in packet_items[index + 1 :]:
            if left_packet.get("repository") != right_packet.get("repository"):
                continue
            if (
                left_id in ancestors.get(right_id, set())
                or right_id in ancestors.get(left_id, set())
            ):
                continue
            for left_path in left_packet.get("allowedPaths", []):
                for right_path in right_packet.get("allowedPaths", []):
                    if paths_overlap(left_path, right_path):
                        errors.append(
                            f"unordered same-repository packets {left_id} and {right_id} overlap at "
                            f"{left_path!r} and {right_path!r}"
                        )

    return errors
