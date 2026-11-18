"""MET-009 (slot 291): the plane-shell ordering annex in scripts/validate_packet_ownership.py.

ANNEX_291 T1-T9 as C12's shape matrix: the repository catalog (multi-product), K = 0 (no shell), K = 1 (one shell), a
bridged loop (a synthetic diamond under RUN-001 with a cycle beside it), fail-closed (a fourth row, a short table, a
row that is not five strings, a wrong registered or shell id; a content digest that differs or cannot be computed, on
either side), isolation, a repository mismatch, and a present shell without its registered bootstrap. Rows bind
canonical content digests (sha256 of the parsed packet as sorted-key compact JSON): the module does no workspace I/O
(D-ANNEX-1). The expected ownership diagnostics are derived (the catalog without its shells), never a literal count.
"""

from __future__ import annotations

import copy
import datetime
import functools
import importlib.util
import unittest
from pathlib import Path

from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "plane_shell_order_ownership",
    ROOT / "scripts/validate_packet_ownership.py",
)
assert SPEC and SPEC.loader
OWNERSHIP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNERSHIP)

SHELL_OF = {
    "RUN-001": "PLANE-BOOTSTRAP-R05",
    "MODEL-001": "PLANE-BOOTSTRAP-R06",
    "EXEC-001": "PLANE-BOOTSTRAP-R08",
}
SHELLS = tuple(SHELL_OF.values())
REFUSAL = "plane shell order table must hold exactly the three closed rows"


@functools.lru_cache(maxsize=1)
def _catalog_once() -> dict:
    return {
        path.stem: safe_load(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "task-packets").glob("*.yaml"))
    }


def catalog(without: tuple[str, ...] = ()) -> dict:
    return {key: copy.deepcopy(value) for key, value in _catalog_once().items() if key not in without}


def naming(diagnostics: list[str], packet_id: str) -> list[str]:
    return [line for line in diagnostics if packet_id in line]


def closure(packets: dict) -> dict[str, set[str]]:
    """An independent predecessor closure (breadth-first, per packet) for an acyclic catalog."""

    result = {}
    for packet_id in packets:
        seen: set[str] = set()
        frontier = list(packets[packet_id].get("predecessors", []))
        while frontier:
            predecessor = frontier.pop()
            if predecessor not in seen:
                seen.add(predecessor)
                frontier.extend(packets.get(predecessor, {}).get("predecessors", []))
        result[packet_id] = seen
    return result


class PlaneShellOrderTests(unittest.TestCase):
    def test_t1_repository_catalog_orders_exactly_the_three_rows(self) -> None:
        packets = catalog()
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, [])
        self.assertEqual(extra, {registered: (shell,) for registered, shell in SHELL_OF.items()})
        diagnostics = OWNERSHIP.validate_packet_ownership(catalog())
        self.assertEqual(sorted(diagnostics), sorted(OWNERSHIP.validate_packet_ownership(catalog(without=SHELLS))))
        for shell in SHELLS:
            self.assertEqual(naming(diagnostics, shell), [])

    def test_t2_no_shell_is_the_unannexed_closure(self) -> None:
        packets = catalog(without=SHELLS)
        self.assertEqual(OWNERSHIP.plane_shell_order(packets), ({}, []))
        independent = closure(packets)
        self.assertEqual(OWNERSHIP.packet_ancestors(packets), independent)
        self.assertEqual(OWNERSHIP.packet_ancestors(packets, {}), independent)

    def test_t3_one_shell_applies_its_row_alone(self) -> None:
        packets = catalog(without=SHELLS[1:])
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, [])
        self.assertEqual(extra, {"RUN-001": ("PLANE-BOOTSTRAP-R05",)})
        diagnostics = OWNERSHIP.validate_packet_ownership(catalog(without=SHELLS[1:]))
        self.assertEqual(naming(diagnostics, "PLANE-BOOTSTRAP-R05"), [])
        self.assertEqual(sorted(diagnostics), sorted(OWNERSHIP.validate_packet_ownership(catalog(without=SHELLS))))

    def test_t4_bridged_loop_and_cycle_guard(self) -> None:
        real = catalog()
        packets = {key: real[key] for key in ("RUN-001", "PLANE-BOOTSTRAP-R05")}
        packets.update({
            "SYN-A": {"id": "SYN-A", "predecessors": ["RUN-001"]},
            "SYN-B": {"id": "SYN-B", "predecessors": ["RUN-001"]},
            "SYN-C": {"id": "SYN-C", "predecessors": ["SYN-A", "SYN-B"]},
            "SYN-X": {"id": "SYN-X", "predecessors": ["SYN-Y"]},
            "SYN-Y": {"id": "SYN-Y", "predecessors": ["SYN-X"]},
        })
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual((extra, errors), ({"RUN-001": ("PLANE-BOOTSTRAP-R05",)}, []))
        before = OWNERSHIP.packet_ancestors(packets)
        after = OWNERSHIP.packet_ancestors(packets, extra)
        for packet_id in ("RUN-001", "SYN-A", "SYN-B", "SYN-C"):
            self.assertEqual(after[packet_id] - before[packet_id], {"PLANE-BOOTSTRAP-R05"})
            self.assertEqual(before[packet_id] - after[packet_id], set())
        for packet_id in ("PLANE-BOOTSTRAP-R05", "SYN-X", "SYN-Y"):
            self.assertEqual(after[packet_id], before[packet_id])
        self.assertEqual(after["SYN-X"], {"SYN-X", "SYN-Y"})

    def test_t5_a_table_that_is_not_the_closed_three_rows_is_refused(self) -> None:
        rows = OWNERSHIP.PLANE_SHELL_ORDER
        packets = catalog()
        table = (*rows, rows[0])
        self.assertEqual(OWNERSHIP.plane_shell_order(packets, table), ({}, [REFUSAL]))
        for short in (rows[:2], ()):
            self.assertEqual(OWNERSHIP.plane_shell_order(packets, short), ({}, [REFUSAL]))
        swapped = (rows[0][:3] + ("PLANE-BOOTSTRAP-R06", rows[1][4]), *rows[1:])
        self.assertEqual(OWNERSHIP.plane_shell_order(packets, swapped), ({}, [REFUSAL]))
        sibling = next(
            key for key, packet in sorted(packets.items())
            if packet.get("repository") == rows[0][0] and key not in (rows[0][1], rows[0][3])
        )
        other_registered = (rows[0][0], sibling, OWNERSHIP.packet_content_sha256(packets[sibling]), *rows[0][3:])
        other_shell = (*rows[0][:3], "PLANE-BOOTSTRAP-R99", rows[0][4])
        for row in (other_registered, other_shell, rows[0][:4], list(rows[0]), (*rows[0][:4], None)):
            self.assertEqual(OWNERSHIP.plane_shell_order(packets, (row, *rows[1:])), ({}, [REFUSAL]), row[:2])
        saved = OWNERSHIP.PLANE_SHELL_ORDER
        try:
            OWNERSHIP.PLANE_SHELL_ORDER = table
            diagnostics = OWNERSHIP.validate_packet_ownership(catalog())
        finally:
            OWNERSHIP.PLANE_SHELL_ORDER = saved
        self.assertIn(REFUSAL, diagnostics)
        for shell in SHELLS:
            self.assertNotEqual(naming(diagnostics, shell), [])

    def test_t6_a_digest_that_differs_or_cannot_be_computed_refuses_that_row(self) -> None:
        rows = OWNERSHIP.PLANE_SHELL_ORDER
        others = {"MODEL-001": ("PLANE-BOOTSTRAP-R06",), "EXEC-001": ("PLANE-BOOTSTRAP-R08",)}
        for column, named in ((2, "RUN-001"), (4, "PLANE-BOOTSTRAP-R05")):
            row = list(rows[0])
            row[column] = "0" * 64
            table = (tuple(row), *rows[1:])
            extra, errors = OWNERSHIP.plane_shell_order(catalog(), table)
            self.assertEqual(errors, [f"plane shell order row PLANE-BOOTSTRAP-R05: {named} content digest mismatch"])
            self.assertEqual(extra, others)
        changes = (("objective", lambda value: value + " ", "mismatch"),
                   ("objective", lambda value: datetime.date(2026, 11, 16), "unavailable"))
        for changed in ("RUN-001", "PLANE-BOOTSTRAP-R05"):
            for key, change, outcome in changes:
                packets = catalog()
                packets[changed][key] = change(packets[changed][key])
                extra, errors = OWNERSHIP.plane_shell_order(packets)
                self.assertEqual(errors, [f"plane shell order row PLANE-BOOTSTRAP-R05: {changed} content digest {outcome}"])
                self.assertEqual(extra, others)
                diagnostics = OWNERSHIP.validate_packet_ownership(packets)
                self.assertIn(errors[0], diagnostics)
                self.assertNotEqual([line for line in naming(diagnostics, "PLANE-BOOTSTRAP-R05") if line != errors[0]], [])
                for shell in SHELLS[1:]:
                    self.assertEqual(naming(diagnostics, shell), [])

    def test_t7_isolation(self) -> None:
        packets = catalog()
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, [])
        before = OWNERSHIP.packet_ancestors(packets)
        after = OWNERSHIP.packet_ancestors(packets, extra)
        self.assertEqual(set(after), set(before))
        changed = 0
        for packet_id, ancestors in before.items():
            planes = [registered for registered in SHELL_OF if registered == packet_id or registered in ancestors]
            gained = after[packet_id] - ancestors
            self.assertEqual(ancestors - after[packet_id], set())
            self.assertEqual(gained, {SHELL_OF[registered] for registered in planes})
            changed += bool(gained)
        self.assertGreaterEqual(changed, len(SHELL_OF))

    def test_t8_a_repository_mismatch_refuses_that_row(self) -> None:
        packets = catalog()
        packets["PLANE-BOOTSTRAP-R05"]["repository"] = "mas-harness-model-plane"
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, ["plane shell order row PLANE-BOOTSTRAP-R05: repository mismatch"])
        self.assertEqual(extra, {"MODEL-001": ("PLANE-BOOTSTRAP-R06",), "EXEC-001": ("PLANE-BOOTSTRAP-R08",)})
        packets = catalog()
        packets["RUN-001"]["repository"] = "mas-harness-model-plane"
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, ["plane shell order row PLANE-BOOTSTRAP-R05: repository mismatch"])
        self.assertEqual(extra, {"MODEL-001": ("PLANE-BOOTSTRAP-R06",), "EXEC-001": ("PLANE-BOOTSTRAP-R08",)})

    def test_t9_a_shell_without_its_registered_bootstrap_refuses_that_row(self) -> None:
        packets = catalog(without=("RUN-001",))
        extra, errors = OWNERSHIP.plane_shell_order(packets)
        self.assertEqual(errors, ["plane shell order row PLANE-BOOTSTRAP-R05: RUN-001 absent"])
        self.assertEqual(extra, {"MODEL-001": ("PLANE-BOOTSTRAP-R06",), "EXEC-001": ("PLANE-BOOTSTRAP-R08",)})
        diagnostics = OWNERSHIP.validate_packet_ownership(catalog(without=("RUN-001",)))
        self.assertIn(errors[0], diagnostics)
        self.assertIn("product repository mas-harness-runtime-plane must contain bootstrap packet RUN-001", diagnostics)
        self.assertEqual(OWNERSHIP.plane_shell_order(catalog(without=("RUN-001", "PLANE-BOOTSTRAP-R05")))[1], [])


if __name__ == "__main__":
    unittest.main()
