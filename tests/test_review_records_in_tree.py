"""REVIEW-RECORD-V2's in-suite pre-check (Q-RR2-4 (a); gate material, D-2): every review record in this checkout is on
the frozen list with its digest or is a valid v2 round with its identity; every directory's v2 rounds form one valid
series; every oracle test is on the frozen list or bound by a valid oracle identity. Collected by the existing outer
pytest argv, so no new acceptance command. The monitor also runs `check_tree` over each PR head before a merge (B-9)."""
from pathlib import Path

from scripts import review_record as rr

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/review-record"


def test_every_review_record_and_oracle_test_in_the_tree_passes():
    legacy = rr.load_legacy((HERE / "legacy-review-records.json").read_bytes())
    # The registry goes in as bytes, so check_tree scans them for privacy hits too (B-8).
    report = rr.check_tree(ROOT, legacy, (HERE / "briefs.json").read_bytes(), "harness-onion")
    assert report["legacyRecords"] == len(legacy["entries"])


def test_each_current_brief_is_the_file_at_its_registered_path():
    registry = rr.load_registry((HERE / "briefs.json").read_bytes())
    for brief in (b for b in registry["briefs"] if "supersededAt" not in b):
        assert rr.file_sha256((ROOT / brief["path"]).read_bytes()) == brief["sha256"], brief["series"]
