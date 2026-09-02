#!/usr/bin/env python3
"""Closed ownership checks for implementation task packets.

This module intentionally has no workspace I/O.  The readiness validator passes
the already schema-validated packet mapping here, which keeps the ownership
rules small enough to exercise with negative unit vectors.
"""

from __future__ import annotations

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


def packet_ancestors(packets: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    """Return the transitive predecessor closure for every packet."""

    cache: dict[str, set[str]] = {}

    def visit(packet_id: str, visiting: set[str]) -> set[str]:
        if packet_id in cache:
            return cache[packet_id]
        if packet_id in visiting:
            return set()
        next_visiting = {*visiting, packet_id}
        result: set[str] = set()
        for predecessor in packets.get(packet_id, {}).get("predecessors", []):
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
    ancestors = packet_ancestors(packets)

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
        descriptor_path = f"ci/targets/{packet_id.casefold()}.json"
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
