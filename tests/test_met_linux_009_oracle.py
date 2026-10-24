"""MET-LINUX-009 D5a oracle: the Linux root-alias contract (DESIGN.md revision 4).

Written from the design and the recorded decisions alone, before the candidate
is seen. Synthetic source tests only: no key, host, network or PASS claim. The
kit's own refusals are exercised on synthetic trees and synthetic metadata; no
check is disabled to reach the refusal under test. Each assertion names the
design section it comes from.
"""
import ast
import contextlib
import copy
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest import mock

# Imported the way tests/linux_runner/ does: the kit directory goes first on sys.path.
KIT = Path(__file__).resolve().parents[1] / "ci" / "linux-runner"
sys.path.insert(0, str(KIT))

import common  # noqa: E402
import launcher  # noqa: E402
import prepare  # noqa: E402
from common import Refused, canonical, digest  # noqa: E402

RECORD_SCHEMA = "planeon.linux-root-aliases/v1"
INPUTS_V3 = "planeon.linux-build-inputs/v3"
INPUTS_V4 = "planeon.linux-build-inputs/v4"
POLICY_SCHEMA = "planeon.linux-runner-policy/v3"
IMAGE = "sha256:" + "3" * 64
LIB = {"path": "/lib", "target": "usr/lib", "treeRoot": "/usr/lib"}
LIB64 = {"path": "/lib64", "target": "usr/lib64", "treeRoot": "/usr/lib64"}
RECORD_LIMIT = 64 * 1024
# DESIGN section 2 (choice 3): the v3 fixture policy's rendered profile, pinned from the base kit.
V3_PROFILE_SHA256 = "14b95dabfa48a0d9532d1057f3fe420c129872cf6fd7673a1dd33cc9392b227b"
_REPOSITORY = []


def source_repository():
    """The owned-product repository, read from the kit's own rule so that no account name is written here."""
    if not _REPOSITORY:
        match = re.search(r"([A-Za-z0-9_.-]+)/\(\?:harness-onion\|", inspect.getsource(common))
        if match is None:
            conftest = Path(__file__).resolve().parent / "linux_runner" / "conftest.py"
            match = re.search(r'"repository": "([A-Za-z0-9_.-]+)/harness-onion"', conftest.read_text())
        if match is None:
            raise AssertionError("owned-product repository rule not found in the kit")
        _REPOSITORY.append(match.group(1) + "/harness-onion")
    return _REPOSITORY[0]


def inputs_v3():
    """The tests/linux_runner/conftest.py inputs fixture shape (v3)."""
    tools = {
        "python": {"path": common.PYTHON, "version": "3.12.14", "root": "/opt/planeon/python/3.12.14",
                   "inventorySha256": "1" * 64},
        "firejail": {"path": common.FIREJAIL, "version": "0.9.76", "root": "/usr/bin", "inventorySha256": "2" * 64},
        "git": {"path": "/usr/bin/git", "version": "2.50.1", "root": "/usr/bin", "inventorySha256": "2" * 64},
    }
    return {"schemaVersion": INPUTS_V3,
            "target": {"os": "linux", "architecture": "amd64", "libc": "glibc", "libcVersion": "2.39",
                       "execution": "NATIVE", "imageDigest": IMAGE},
            "tools": tools,
            "caches": [{"root": "/opt/planeon/cache/python", "inventorySha256": "4" * 64,
                        "os": "linux", "architecture": "amd64", "libc": "glibc", "tool": "python"}],
            "systemTrees": [{"root": root, "inventorySha256": "2" * 64 if root == "/usr/bin" else "a" * 64}
                            for root in ("/usr/bin", "/usr/lib", "/etc/firejail")],
            "systemFiles": {"/etc/ld.so.cache": "b" * 64},
            "source": {"repository": source_repository(), "commit": "5" * 40, "treeSha256": "6" * 64},
            "recipes": {"packet": "SIGNED_PACKET_WRAPPER", "nextStandalone": "LINUX_TARGET_BUILD_ONLY",
                        "downloads": "DENIED", "hostOutputReuse": "DENIED"}}


def record_value(aliases=None):
    """DESIGN section 2: the closed record, one per image."""
    return {"aliases": copy.deepcopy([LIB, LIB64] if aliases is None else aliases),
            "imageDigest": IMAGE, "schemaVersion": RECORD_SCHEMA}


def inputs_v4(raw=None, extra_trees=()):
    """DESIGN section 2, Pinning: v4 adds exactly rootAliases {recordSha256} to the v3 member set."""
    value = inputs_v3()
    value["schemaVersion"] = INPUTS_V4
    value["systemTrees"].append({"root": "/usr/lib64", "inventorySha256": "c" * 64})
    value["systemTrees"].extend({"root": root, "inventorySha256": "d" * 64} for root in extra_trees)
    value["rootAliases"] = {"recordSha256": digest(canonical(record_value()) if raw is None else raw)}
    return value


def policy_for(inputs, now=None):
    """The tests/linux_runner/conftest.py policy fixture shape, current at `now`."""
    now = int(time.time()) if now is None else now
    value = {"schemaVersion": POLICY_SCHEMA, "issuedAt": now - 60, "expiresAt": now + 3600,
             "operatorUid": 1001, "operatorName": "runner",
             "workspace": "/opt/planeon/work/harness-onion/harness-onion",
             "runnerHome": "/srv/planeon/runner-agent", "packetSha256": "7" * 64,
             "warmContainer": "/srv/planeon/warm-snapshots",
             "warmRoots": ["/srv/planeon/warm-snapshots/reference"],
             "inputs": inputs, "profileSha256": "8" * 64,
             "transportPins": {path: "9" * 64 for path in
                               ("ci/verify-offline.sh", "ci/run_packet_argv.py", "ci/network_canary.py")},
             "environment": {"UV_CACHE_DIR": "/opt/planeon/cache/python"}}
    value["profileSha256"] = digest(launcher.profile_bytes(value))
    return value


def v3_names(normal):
    names = {"anchor": common.ANCHOR, "public": common.PUBLIC, "policy": common.POLICY,
             "signature": common.POLICY + ".sig"}
    if normal:
        names.update({"manifest": common.MANIFEST, "manifestSignature": common.MANIFEST + ".sig",
                      "preflight": common.PREFLIGHT})
    return names


def v4_names(normal):
    return {**v3_names(normal), "rootAliases": common.ROOT_ALIASES}


def meta(mode, uid=0, gid=0, nlink=1, ino=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=nlink, st_dev=1, st_ino=ino,
                           st_size=0, st_mtime_ns=0, st_ctime_ns=0)


def synthetic_owner(metadata):
    """The test_system_inventory_v2.py synthetic_owner double (DESIGN section 6, test shape)."""
    return (metadata.st_uid in (0, os.getuid())
            and (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                 or not metadata.st_mode & 0o022))


def elf(machine):
    return b"\x7fELF\x02\x01" + bytes(12) + machine.to_bytes(2, "little") + bytes(44)


def by_path_bytes(entries):
    return sorted(entries, key=lambda entry: entry["path"].encode())


def patch(case, target, name, value):
    patcher = mock.patch.object(target, name, value)
    patcher.start()
    case.addCleanup(patcher.stop)


def make_tmp(case):
    previous = os.umask(0o022)
    case.addCleanup(os.umask, previous)
    tmp = Path(tempfile.mkdtemp(prefix="met-linux-009-")).resolve(strict=True)
    case.addCleanup(shutil.rmtree, tmp, True)
    return tmp


def mkdirs(*paths):
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o755)


def write(path, data=b"pinned"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, 0o644)


def synthetic_signature(public, message):
    return hashlib.sha256(b"synthetic source-test signature\x00" + public + message).digest()


def synthetic_verify(public, message, signature):
    return signature == synthetic_signature(public, message)


class RecordRulesTest(unittest.TestCase):
    """DESIGN section 2 (the record), through the one shared validator of section 3."""

    def outcome(self, value=None, raw=None, extra_trees=(), digest_of=None):
        raw = canonical(value) if raw is None else raw
        return common.root_aliases(raw, inputs_v4(raw if digest_of is None else digest_of, extra_trees))

    def admit(self, value=None, **kwargs):
        result = self.outcome(record_value() if value is None else value, **kwargs)
        self.assertTrue(result)
        return result

    def refuse(self, value=None, **kwargs):
        with self.assertRaises(Refused):
            self.outcome(value, **kwargs)

    def test_documented_records_admitted(self):
        # DESIGN section 2: the documented one-alias record and a two-alias record are admitted.
        self.admit(record_value([LIB64]))
        self.admit(record_value([LIB, LIB64]))

    def test_closed_members(self):
        # DESIGN section 2, Members: the record holds exactly schemaVersion, imageDigest and aliases.
        for member in ("schemaVersion", "imageDigest", "aliases"):
            value = record_value()
            del value[member]
            with self.subTest(missing=member):
                self.refuse(value)
        value = record_value()
        value["signature"] = "none"
        self.refuse(value)
        self.refuse(raw=canonical([LIB64]))
        # DESIGN section 2, Members: each alias holds exactly path, target and treeRoot.
        for member in ("path", "target", "treeRoot"):
            value = record_value([LIB64])
            del value["aliases"][0][member]
            with self.subTest(alias_missing=member):
                self.refuse(value)
        self.refuse(record_value([dict(LIB64, mode="0777")]))
        self.refuse(record_value(["/lib64"]))

    def test_schema_version(self):
        # DESIGN section 2: schemaVersion equals planeon.linux-root-aliases/v1.
        for bad in ("planeon.linux-root-aliases/v2", RECORD_SCHEMA + " ", "", None, 1):
            value = record_value()
            value["schemaVersion"] = bad
            with self.subTest(schema=bad):
                self.refuse(value)

    def test_image_digest_pattern_and_equality(self):
        # DESIGN section 2: imageDigest matches sha256:[0-9a-f]{64} ...
        for bad in (IMAGE.upper(), "sha256:" + "A" * 64, "sha256:" + "3" * 63, "sha256:" + "3" * 65,
                    "3" * 64, "sha512:" + "3" * 64, "sha256:" + "g" * 64, IMAGE + "\n", None):
            value = record_value()
            value["imageDigest"] = bad
            with self.subTest(image=bad):
                self.refuse(value)
        # ... and equals the inputs' target.imageDigest (declarative only, RA1-10, RA3-3).
        other = "sha256:" + "4" * 64
        value = record_value()
        value["imageDigest"] = other
        self.refuse(value)
        raw = canonical(value)
        inputs = inputs_v4(raw)
        inputs["target"]["imageDigest"] = other
        self.assertTrue(common.root_aliases(raw, inputs))

    def test_aliases_non_empty_list(self):
        # DESIGN section 2: aliases is a non-empty list; a record with no alias is refused (use v3 inputs).
        for bad in ([], {}, "/lib64", None):
            value = record_value()
            value["aliases"] = bad
            with self.subTest(aliases=bad):
                self.refuse(value)

    def test_aliases_strictly_increasing_path_bytes(self):
        # DESIGN section 2: strictly increasing path byte order, so a duplicate path fails.
        self.refuse(record_value([LIB64, LIB]))
        self.refuse(record_value([LIB, LIB]))
        self.refuse(record_value([LIB, dict(LIB, target="usr/lib64", treeRoot="/usr/lib64")]))
        upper = {"path": "/LIB", "target": "usr/lib64", "treeRoot": "/usr/lib64"}
        self.admit(record_value([upper, LIB]))
        self.refuse(record_value([LIB, upper]))

    def test_path_single_component_pattern(self):
        # DESIGN section 2: path fully matches /[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}: one component under /,
        # never . or .. (common.absolute() is not used). Section 6, record refusals.
        for bad in ("/usr/sbin", "/a/b", "/", "/.", "/..", "lib64", "/lib64/", "//lib64",
                    "/" + "a" * 65, "/-lib", "/.lib", "/li b", "/lib\n", "/lib\xe9", "", None, 64):
            with self.subTest(path=bad):
                self.refuse(record_value([dict(LIB64, path=bad)]))
        for good in ("/" + "a" * 64, "/_lib.64-x", "/L"):
            with self.subTest(path=good):
                self.admit(record_value([dict(LIB64, path=good)]))

    def test_path_never_bridge_root_or_ancestor_lexically(self):
        # DESIGN sections 2 and 6: not a bridge, a declared root or an ancestor of one, checked
        # lexically against the inputs' declared roots, not against the observed host.
        for bad in ("/usr", "/etc"):
            with self.subTest(path=bad):
                self.refuse(record_value([dict(LIB64, path=bad)]))
        self.admit(record_value([LIB64]))

    def test_target_text_limits(self):
        # DESIGN section 2: target is the exact raw link text: non-empty, no NUL, at most 4096 bytes
        # (os.fsencode), relative or absolute.
        for bad in ("", "usr\x00lib64", "a" * 4097, "\xe9" * 2049, None, 5, ["usr/lib64"]):
            with self.subTest(target=repr(bad)[:24]):
                self.refuse(record_value([dict(LIB64, target=bad)]))
        for good in ("a" * 4096, "\xe9" * 2048, "/usr/lib64", "../usr/lib64"):
            with self.subTest(target=good[:24]):
                self.admit(record_value([dict(LIB64, target=good)]))

    def test_tree_root_is_a_declared_system_tree(self):
        # DESIGN section 2: treeRoot is one of the inputs' declared systemTrees roots.
        for bad in ("/usr/libexec", "/usr/lib64/", "/usr/lib64/sub", "/usr", "/opt/planeon/python/3.12.14",
                    "", None):
            with self.subTest(tree=bad):
                self.refuse(record_value([dict(LIB64, treeRoot=bad)]))
        good = {"path": "/libexec", "target": "usr/libexec", "treeRoot": "/usr/libexec"}
        self.admit(record_value([good]), extra_trees=("/usr/libexec",))

    def test_at_most_one_alias_per_tree(self):
        # DESIGN section 2 (choice 4): at most one alias names each treeRoot.
        self.refuse(record_value([dict(LIB, target="usr/lib64", treeRoot="/usr/lib64"), LIB64]))

    def test_exact_canonical_bytes(self):
        # DESIGN section 2, Bytes and digest: the exact bytes equal common.canonical(common.parse(bytes)):
        # ASCII-escaped, sorted keys, compact separators, no trailing newline.
        value = record_value()
        raw = canonical(value)
        unicode_value = record_value([dict(LIB64, target="usr/lib64\xe9")])
        variants = {
            "trailing newline": raw + b"\n",
            "leading space": b" " + raw,
            "indented": json.dumps(value, sort_keys=True, indent=1).encode(),
            "spaced separators": json.dumps(value, sort_keys=True).encode(),
            "unsorted keys": json.dumps({key: value[key] for key in sorted(value, reverse=True)},
                                        separators=(",", ":")).encode(),
            "unescaped non-ASCII": json.dumps(unicode_value, sort_keys=True, separators=(",", ":"),
                                              ensure_ascii=False).encode(),
        }
        for name, variant in variants.items():
            with self.subTest(variant=name):
                self.assertNotEqual(variant, canonical(common.parse(variant)))
                self.refuse(raw=variant)
        self.admit(unicode_value)

    def test_strict_parse_rules(self):
        # DESIGN section 2: strict parse(): duplicate JSON names and nonfinite values fail.
        text = canonical(record_value()).decode()
        duplicate = (text[:-1] + ',"schemaVersion":"' + RECORD_SCHEMA + '"}').encode()
        nonfinite = text.replace('"imageDigest":"' + IMAGE + '"', '"imageDigest":NaN').encode()
        self.assertNotEqual(nonfinite, text.encode())
        for name, raw in (("duplicate name", duplicate), ("nonfinite", nonfinite), ("truncated", b"{"),
                          ("empty", b""), ("not UTF-8", text.encode()[:-1] + b"\xff}")):
            with self.subTest(raw=name):
                self.refuse(raw=raw)

    def sized(self, total):
        """A record that keeps every record rule and is exactly `total` canonical bytes long."""
        wide = "\x01" * 4096  # 4096 bytes of link text, six canonical bytes each
        value = record_value([{"path": "/x1", "target": wide, "treeRoot": "/usr/lib64"},
                              {"path": "/x2", "target": wide, "treeRoot": "/usr/libexec"},
                              {"path": "/x3", "target": "", "treeRoot": "/etc/alternatives"}])
        wide_count, narrow = divmod(total - len(canonical(value)), 6)
        value["aliases"][2]["target"] = "\x01" * wide_count + "a" * narrow
        raw = canonical(value)
        self.assertEqual(len(raw), total)
        self.assertTrue(0 < len(os.fsencode(value["aliases"][2]["target"])) <= 4096)
        return raw

    def test_record_at_most_64_kib(self):
        # DESIGN section 2, Bytes and digest: the file is at most 64 KiB.
        trees = ("/usr/libexec", "/etc/alternatives")
        self.assertTrue(self.outcome(raw=self.sized(RECORD_LIMIT), extra_trees=trees))
        self.refuse(raw=self.sized(RECORD_LIMIT + 1), extra_trees=trees)

    def test_digest_equals_record_sha256(self):
        # DESIGN section 2, Bytes and digest: recordSha256 is the lowercase SHA-256 of the exact bytes.
        raw = canonical(record_value())
        self.refuse(raw=raw, digest_of=canonical(record_value([LIB64])))
        for pinned in ("0" * 64, digest(raw).upper()):
            inputs = inputs_v4(raw)
            inputs["rootAliases"]["recordSha256"] = pinned
            with self.subTest(pinned=pinned[:8]), self.assertRaises(Refused):
                common.root_aliases(raw, inputs)
        self.admit(record_value())

    def test_validator_requires_none_for_v3_and_bytes_for_v4(self):
        # DESIGN section 3, verify_tools(): the validator requires None for v3 inputs and bytes for v4.
        self.assertFalse(common.root_aliases(None, inputs_v3()))
        for raw in (canonical(record_value()), b""):
            with self.subTest(raw=raw[:8]), self.assertRaises(Refused):
                common.root_aliases(raw, inputs_v3())
        with self.assertRaises(Refused):
            common.root_aliases(None, inputs_v4())


class BuildInputsTest(unittest.TestCase):
    """DESIGN section 2, Pinning (Q-RA-FORM (a), choice 2) and section 4, Not changed (choice 6)."""

    def test_v3_member_set_and_checks_unchanged(self):
        # DESIGN section 2: for v3 the closed member set and every check are unchanged.
        self.assertEqual(common.validate_inputs(inputs_v3())["schemaVersion"], INPUTS_V3)
        value = inputs_v3()
        value["rootAliases"] = {"recordSha256": "0" * 64}
        with self.assertRaises(Refused):
            common.validate_inputs(value)

    def test_v4_adds_exactly_root_aliases(self):
        # DESIGN section 2: v4 adds exactly one member, rootAliases {"recordSha256": "<64 hex>"}.
        self.assertEqual(common.validate_inputs(inputs_v4())["schemaVersion"], INPUTS_V4)
        value = inputs_v4()
        del value["rootAliases"]
        with self.assertRaises(Refused):
            common.validate_inputs(value)
        for bad in ({}, {"recordSha256": "A" * 64}, {"recordSha256": "0" * 63},
                    {"recordSha256": "0" * 64, "extra": 1}, "0" * 64, None):
            value = inputs_v4()
            value["rootAliases"] = bad
            with self.subTest(member=repr(bad)[:24]), self.assertRaises(Refused):
                common.validate_inputs(value)
        value = inputs_v4()
        value["extra"] = 1
        with self.assertRaises(Refused):
            common.validate_inputs(value)
        value = inputs_v4()
        value["schemaVersion"] = "planeon.linux-build-inputs/v5"
        with self.assertRaises(Refused):
            common.validate_inputs(value)

    def test_root_list_unchanged(self):
        # DESIGN section 4, Not changed (RA1-9, choice 6): root-level aliases and /usr/sbin never become roots.
        for root in ("/lib", "/lib64", "/sbin", "/usr/sbin"):
            value = inputs_v4()
            value["systemTrees"].append({"root": root, "inventorySha256": "0" * 64})
            with self.subTest(root=root), self.assertRaisesRegex(Refused, "unapproved system root"):
                common.validate_inputs(value)


class V3ByteIdenticalTest(unittest.TestCase):
    """DESIGN section 4 rule 11 and section 6 (positives): with no record, every v3 list is today's."""

    def setUp(self):
        self.tmp = make_tmp(self)
        patch(self, common, "trusted_entry", synthetic_owner)
        self.usr_bin = self.tmp / "usr" / "bin"
        self.usr_lib = self.tmp / "usr" / "lib"
        mkdirs(self.usr_bin, self.usr_lib, self.usr_lib / "sub")
        write(self.usr_bin / "alpha", b"pinned alpha")
        os.symlink("alpha", self.usr_bin / "beta")
        os.symlink("../lib", self.usr_bin / "lib-alias")
        write(self.usr_lib / "sub" / "libz.so.1", b"pinned library")
        self.roots = [str(self.usr_bin), str(self.usr_lib)]

    def expected(self):
        """Today's v3 encoding of this tree, rebuilt independently of the kit."""
        def directory(path):
            return {"kind": "directory", "path": path, "mode": "0755"}

        def file(root, path, data):
            # Every v3 file entry carries its (here single-member) hardlink group.
            return {"kind": "file", "path": path, "mode": "0644", "size": len(data), "sha256": digest(data),
                    "hardlinkGroup": [str(root / path)]}
        return {str(self.usr_bin): [directory(""), file(self.usr_bin, "alpha", b"pinned alpha"),
                                    {"kind": "symlink", "path": "beta", "target": "alpha",
                                     "resolvedPath": str(self.usr_bin / "alpha")},
                                    {"kind": "symlink", "path": "lib-alias", "target": "../lib",
                                     "resolvedPath": str(self.usr_lib)}],
                str(self.usr_lib): [directory(""), directory("sub"),
                                    file(self.usr_lib, "sub/libz.so.1", b"pinned library")]}

    def test_lists_and_digests_are_todays(self):
        # DESIGN section 4 rule 11: system_inventories(roots) without the keyword is byte-identical for v3.
        expected = self.expected()
        result = common.system_inventories(self.roots)
        self.assertEqual(result, expected)
        self.assertEqual({root: digest(canonical(records)) for root, records in result.items()},
                         {root: digest(canonical(records)) for root, records in expected.items()})
        # DESIGN section 1: a root-level link is never enumerated without a record.
        os.symlink("usr/lib", self.tmp / "lib")
        self.assertEqual(common.system_inventories(self.roots), expected)

    def test_empty_keyword_is_todays(self):
        # DESIGN section 4 rule 11: root_aliases=() is the default and keeps every v3 list.
        self.assertEqual(inspect.signature(common.system_inventories).parameters["root_aliases"].default, ())
        self.assertEqual(common.system_inventories(self.roots, root_aliases=()), self.expected())


class CustodyPredicateTest(unittest.TestCase):
    """DESIGN section 4 rules 1-3 and 5 (RA1-1, RA2-3, RA3-2): one predicate on synthetic metadata,
    under the production trusted_entry (no synthetic_owner double)."""

    ROOT_LINK = meta(stat.S_IFLNK | 0o777)
    ROOT_BRIDGE = meta(stat.S_IFDIR | 0o755, nlink=20, ino=2)

    def admitted(self, alias_meta, parent_meta):
        try:
            verdict = common.root_alias_custody(alias_meta, parent_meta)
        except Refused:
            return False
        return verdict is not False

    def test_production_alias_parent(self):
        # DESIGN section 6, test shape: the production test asserts ALIAS_PARENT == "/".
        self.assertEqual(str(common.ALIAS_PARENT), "/")

    def test_production_trusted_entry(self):
        # DESIGN section 6, test shape: the unpatched trusted_entry on links, and a group-writable
        # root-owned directory refused (RA2-3).
        self.assertTrue(common.trusted_entry(meta(stat.S_IFLNK | 0o777)))
        self.assertFalse(common.trusted_entry(meta(stat.S_IFLNK | 0o777, uid=1001)))
        self.assertFalse(common.trusted_entry(meta(stat.S_IFLNK | 0o777, gid=1001)))
        self.assertTrue(common.trusted_entry(meta(stat.S_IFDIR | 0o755)))
        self.assertFalse(common.trusted_entry(meta(stat.S_IFDIR | 0o775)))
        self.assertFalse(common.trusted_entry(meta(stat.S_IFDIR | 0o757)))

    def test_root_link_under_root_bridge_admitted(self):
        # DESIGN section 4 rules 1-3 and 5: a root-owned single link under a root-owned, non-writable directory.
        self.assertTrue(self.admitted(self.ROOT_LINK, self.ROOT_BRIDGE))

    def test_rule_1_refuses_non_link(self):
        # DESIGN section 4 rule 1: lstat shows S_ISLNK.
        for mode in (stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644, stat.S_IFREG | 0o755):
            with self.subTest(mode=oct(mode)):
                self.assertFalse(self.admitted(meta(mode), self.ROOT_BRIDGE))

    def test_rule_2_refuses_non_root_owner(self):
        # DESIGN section 4 rule 2: st_uid == st_gid == 0, through trusted_entry.
        for uid, gid in ((1001, 0), (0, 1001), (1001, 1001)):
            with self.subTest(uid=uid, gid=gid):
                self.assertFalse(self.admitted(meta(stat.S_IFLNK | 0o777, uid=uid, gid=gid), self.ROOT_BRIDGE))

    def test_rule_3_refuses_hardlinked_alias(self):
        # DESIGN section 4 rule 3: st_nlink == 1.
        for nlink in (2, 3):
            with self.subTest(nlink=nlink):
                self.assertFalse(self.admitted(meta(stat.S_IFLNK | 0o777, nlink=nlink), self.ROOT_BRIDGE))

    def test_rule_5_refuses_unsafe_parent(self):
        # DESIGN section 4 rule 5: the parent is a directory, root-owned, with no group or other write.
        parents = {"group-writable": meta(stat.S_IFDIR | 0o775), "other-writable": meta(stat.S_IFDIR | 0o757),
                   "world-writable": meta(stat.S_IFDIR | 0o777), "non-root uid": meta(stat.S_IFDIR | 0o755, uid=1001),
                   "non-root gid": meta(stat.S_IFDIR | 0o755, gid=1001), "link": meta(stat.S_IFLNK | 0o777),
                   "regular file": meta(stat.S_IFREG | 0o644)}
        for name, parent in parents.items():
            with self.subTest(parent=name):
                self.assertFalse(self.admitted(self.ROOT_LINK, parent))


class AliasTreeTest(unittest.TestCase):
    """DESIGN section 4 rules 1-11 on synthetic trees, with common.ALIAS_PARENT and common.trusted_entry
    patched as section 6's test shape says. Positive targets are relative (section 6)."""

    def setUp(self):
        self.tmp = make_tmp(self)
        patch(self, common, "trusted_entry", synthetic_owner)
        patch(self, common, "ALIAS_PARENT", str(self.tmp))
        self.usr_bin, self.usr_lib, self.usr_lib64 = (self.tmp / "usr" / name for name in ("bin", "lib", "lib64"))
        mkdirs(self.usr_bin, self.usr_lib, self.usr_lib64)
        write(self.usr_bin / "real", b"pinned tool")
        write(self.usr_lib / "ld-linux-aarch64.so.1", b"arm64 loader")
        write(self.usr_lib / "libz.so", b"pinned library")
        write(self.usr_lib64 / "ld-linux-x86-64.so.2", b"amd64 loader")
        self.roots = [str(self.usr_bin), str(self.usr_lib), str(self.usr_lib64)]

    def alias(self, name, text, tree, link=True):
        if link:
            os.symlink(text, self.tmp / name)
        return {"path": "/" + name, "target": text, "treeRoot": str(tree)}

    def lib_aliases(self):
        return [self.alias("lib", "usr/lib", self.usr_lib), self.alias("lib64", "usr/lib64", self.usr_lib64)]

    def inventories(self, aliases, roots=None):
        return common.system_inventories(self.roots if roots is None else roots, root_aliases=aliases)

    def entry(self, result, root, path):
        return next(entry for entry in result[str(root)] if entry["path"] == path)

    def test_listed_aliases_admitted_as_entries(self):
        # DESIGN section 4 rule 10: each alias appears in its treeRoot's list as a rootAlias entry,
        # resolving exactly to its treeRoot (rule 6); every other list is unchanged; lists stay sorted.
        before = common.system_inventories(self.roots)
        result = self.inventories(self.lib_aliases())
        lib = {"kind": "rootAlias", "path": "/lib", "target": "usr/lib", "resolvedPath": str(self.usr_lib)}
        lib64 = {"kind": "rootAlias", "path": "/lib64", "target": "usr/lib64", "resolvedPath": str(self.usr_lib64)}
        self.assertEqual(set(result), set(before))
        self.assertEqual(result[str(self.usr_bin)], before[str(self.usr_bin)])
        self.assertEqual(result[str(self.usr_lib)], by_path_bytes(before[str(self.usr_lib)] + [lib]))
        self.assertEqual(result[str(self.usr_lib64)], by_path_bytes(before[str(self.usr_lib64)] + [lib64]))
        for records in result.values():
            self.assertEqual(records, by_path_bytes(records))

    def test_amd64_loader_through_alias(self):
        # DESIGN section 1 (RA1-6), section 4 rule 8 and section 6: an inventoried in-tree link to the AMD64
        # loader crosses /lib64; without the record the same crossing stays refused.
        os.symlink("../../lib64/ld-linux-x86-64.so.2", self.usr_bin / "ld-amd64")
        aliases = self.lib_aliases()
        with self.assertRaisesRegex(Refused, "uninventoried"):
            common.system_inventories(self.roots)
        result = self.inventories(aliases)
        self.assertEqual(self.entry(result, self.usr_bin, "ld-amd64")["resolvedPath"],
                         str(self.usr_lib64 / "ld-linux-x86-64.so.2"))

    def test_arm64_loader_through_alias(self):
        # DESIGN section 1 (RA1-6), section 4 rule 8 and section 6: the ARM64 loader through /lib.
        os.symlink("../../lib/ld-linux-aarch64.so.1", self.usr_bin / "ld-arm64")
        aliases = self.lib_aliases()
        with self.assertRaisesRegex(Refused, "uninventoried"):
            common.system_inventories(self.roots)
        result = self.inventories(aliases)
        self.assertEqual(self.entry(result, self.usr_bin, "ld-arm64")["resolvedPath"],
                         str(self.usr_lib / "ld-linux-aarch64.so.1"))

    def test_dotdot_reentering_a_declared_tree_admitted(self):
        # DESIGN section 6: a .. after an alias that re-enters another declared tree stays admitted.
        os.symlink("../../lib64/../bin/real", self.usr_bin / "reenter")
        result = self.inventories(self.lib_aliases())
        self.assertEqual(self.entry(result, self.usr_bin, "reenter")["resolvedPath"], str(self.usr_bin / "real"))

    def test_absent_alias_refused_as_custody(self):
        # DESIGN section 4: an absent alias (lstat FileNotFoundError) is Refused("root alias custody").
        with self.assertRaisesRegex(Refused, "root alias custody"):
            self.inventories([self.alias("lib64", "usr/lib64", self.usr_lib64, link=False)])

    def test_rule_1_real_directory_refused(self):
        # DESIGN section 4 rule 1 and section 6: a listed alias that is a real directory.
        (self.tmp / "lib64").mkdir()
        with self.assertRaises(Refused):
            self.inventories([self.alias("lib64", "usr/lib64", self.usr_lib64, link=False)])

    def test_rule_4_text_must_equal_target(self):
        # DESIGN section 4 rule 4: os.readlink equals target exactly.
        os.symlink("usr/lib", self.tmp / "lib64")
        with self.assertRaises(Refused):
            self.inventories([self.alias("lib64", "usr/lib64", self.usr_lib64, link=False)])

    def test_rule_5_parent_must_be_a_bridge(self):
        # DESIGN section 4 rule 5 (RA3-2): str(ALIAS_PARENT) in bridges.
        elsewhere = self.tmp / "elsewhere"
        mkdirs(elsewhere)
        os.symlink("../usr/lib64", elsewhere / "lib64")
        with mock.patch.object(common, "ALIAS_PARENT", str(elsewhere)), self.assertRaises(Refused):
            self.inventories([{"path": "/lib64", "target": "../usr/lib64", "treeRoot": str(self.usr_lib64)}])

    def test_rule_6_must_end_exactly_at_tree_root(self):
        # DESIGN section 4 rule 6 and section 6: an alias resolving outside its treeRoot.
        with self.assertRaises(Refused):
            self.inventories([self.alias("lib64", "usr/lib", self.usr_lib64)])

    def test_rule_7_chain_through_another_alias_refused(self):
        # DESIGN section 4 rule 7: a chain through another alias; the other alias is not a node.
        aliases = [self.alias("lib", "lib64", self.usr_lib), self.alias("lib64", "usr/lib64", self.usr_lib64)]
        with self.assertRaisesRegex(Refused, "uninventoried"):
            self.inventories(aliases)

    def test_rule_6_cycle_among_aliases_refused(self):
        # DESIGN section 6: a cycle among aliases fails as "system link traverses uninventoried path".
        with self.assertRaisesRegex(Refused, "uninventoried"):
            self.inventories([self.alias("lib64", "lib64", self.usr_lib64)])

    def test_rule_7_target_at_bridge_or_ancestor_refused(self):
        # DESIGN section 4 rule 7: a target ending at a bridge or at an ancestor of a root.
        for name, text in (("u", "usr"), ("top", ".")):
            with self.subTest(target=text), self.assertRaises(Refused):
                self.inventories([self.alias(name, text, self.usr_lib64)])

    def test_rule_7_subdirectory_of_tree_root_refused(self):
        # DESIGN section 4 rule 7: a subdirectory of treeRoot fails.
        mkdirs(self.usr_lib64 / "sub")
        with self.assertRaises(Refused):
            self.inventories([self.alias("lib64", "usr/lib64/sub", self.usr_lib64)])

    def test_rule_6_escape_above_parent_refused(self):
        # DESIGN section 4 rule 6 (RA3-1): under a patched parent the escape vector uses one more ..
        # than ALIAS_PARENT has components, so that it meets "system link escapes root".
        components = len(self.tmp.parts) - 1
        text = "/".join([".."] * (components + 1) + ["usr", "lib64"])
        with self.assertRaisesRegex(Refused, "escapes root"):
            self.inventories([self.alias("lib64", text, self.usr_lib64)])

    def test_rule_9_unlisted_root_level_link_refused(self):
        # DESIGN section 4 rule 9 and section 6: an unlisted root-level link crossed by an in-tree link.
        aliases = self.lib_aliases()
        os.symlink("usr/lib", self.tmp / "lib32")
        os.symlink("../../lib32/libz.so", self.usr_bin / "via-unlisted")
        with self.assertRaisesRegex(Refused, "uninventoried"):
            self.inventories(aliases)

    def test_rule_9_alias_into_undeclared_tree_refused(self):
        # DESIGN section 4 rule 9: an alias into an undeclared tree.
        with self.assertRaises(Refused):
            self.inventories([self.alias("lib64", "usr/lib64", self.usr_lib64)],
                             roots=[str(self.usr_bin), str(self.usr_lib)])

    def test_in_tree_cycle_through_alias_refused(self):
        # DESIGN section 6: an in-tree cycle through an alias ("cyclic or excessive system link").
        os.symlink("../../lib64/loop", self.usr_lib64 / "loop")
        with self.assertRaisesRegex(Refused, "cyclic or excessive system link"):
            self.inventories(self.lib_aliases())

    def test_rule_8_crossing_then_dotdot_to_bridge_refused(self):
        # DESIGN section 4 rule 8 and section 6: a link may never end at a bridge, even across an alias.
        os.symlink("../../lib64/..", self.usr_bin / "up")
        with self.assertRaisesRegex(Refused, "system link target not inventoried"):
            self.inventories(self.lib_aliases())

    def test_rule_11_single_root_route_refuses_crossing(self):
        # DESIGN section 4 rule 11 (RA2-4): inventory(root, trusted=True, system=True) gains no root_aliases
        # parameter, so a crossing through it stays "system link traverses uninventoried path".
        os.symlink("../../lib64/ld-linux-x86-64.so.2", self.usr_lib64 / "ld-link")
        result = self.inventories(self.lib_aliases())
        self.assertEqual(self.entry(result, self.usr_lib64, "ld-link")["resolvedPath"],
                         str(self.usr_lib64 / "ld-linux-x86-64.so.2"))
        self.assertNotIn("root_aliases", inspect.signature(common.inventory).parameters)
        with self.assertRaisesRegex(Refused, "uninventoried"):
            common.inventory(str(self.usr_lib64), trusted=True, system=True)


class VerifyToolsTest(unittest.TestCase):
    """DESIGN section 3 (verify_tools and the one shared validator) and section 4 rules 11-12, with the
    tests/linux_runner/test_toolchain.py doubles for the host."""

    CACHE = "/etc/ld.so.cache"

    def setUp(self):
        self.exe = elf(62)
        self.cache = b"pinned loader cache"
        self.reads = []
        for target, name, value in (
                (launcher.platform, "system", lambda: "Linux"),
                (launcher.platform, "machine", lambda: "x86_64"),
                (launcher.platform, "libc_ver", lambda: ("glibc", "2.39")),
                (launcher.os.path, "lexists", lambda _path: False),
                (Path, "lstat", lambda _self: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)),
                (launcher, "root_read", self.read),
                (launcher, "inventory", lambda *args, **kwargs: [])):
            patch(self, target, name, value)

    def read(self, path, **kwargs):
        self.reads.append(path)
        return self.cache if path == self.CACHE else self.exe

    def trees(self, inputs, aliases=()):
        directory = {"kind": "directory", "path": "", "mode": "0755"}
        trees = {spec["root"]: [dict(directory)] for spec in inputs["systemTrees"]}
        trees["/usr/bin"] += [{"kind": "file", "path": name, "mode": "0755", "size": len(self.exe),
                               "sha256": digest(self.exe)} for name in ("firejail", "git")]
        for alias in aliases:
            trees[alias["treeRoot"]].append({"kind": "rootAlias", "path": alias["path"], "target": alias["target"],
                                             "resolvedPath": alias["treeRoot"]})
        self.bind(inputs, trees)
        return trees

    def bind(self, inputs, trees):
        for root in trees:
            trees[root] = by_path_bytes(trees[root])
        inputs["systemFiles"][self.CACHE] = digest(self.cache)
        for spec in inputs["systemTrees"]:
            spec["inventorySha256"] = digest(canonical(trees[spec["root"]]))
        for spec in [*inputs["tools"].values(), *inputs["caches"]]:
            spec["inventorySha256"] = digest(canonical(trees.get(spec["root"], [])))

    def test_v3_reads_no_record_and_keeps_call_shape(self):
        # DESIGN section 3: for v3 inputs nothing reads the record; section 4 rule 11 (RA2-9): the keyword is
        # passed only with aliases, so the one-argument double still serves v3.
        inputs = inputs_v3()
        trees = self.trees(inputs)
        calls = []

        def graph(roots):
            calls.append(list(roots))
            return trees
        patch(self, launcher, "system_inventories", graph)
        launcher.verify_tools(inputs)
        launcher.verify_tools(inputs, root_aliases_raw=None)
        self.assertEqual(len(calls), 2)
        self.assertNotIn(common.ROOT_ALIASES, self.reads)

    def test_default_keeps_v3_call_shape(self):
        # DESIGN section 3 (RA2-9): verify_tools(inputs, root_aliases_raw=None).
        self.assertIsNone(inspect.signature(launcher.verify_tools).parameters["root_aliases_raw"].default)

    def test_v3_refuses_record_bytes(self):
        # DESIGN section 3 and section 6 (RA2-2): verify_tools() given bytes for v3 inputs is refused.
        inputs = inputs_v3()
        trees = self.trees(inputs)
        patch(self, launcher, "system_inventories", lambda roots: trees)
        for raw in (canonical(record_value()), b""):
            with self.subTest(raw=raw[:8]), self.assertRaises(Refused):
                launcher.verify_tools(inputs, root_aliases_raw=raw)

    def test_v4_requires_matching_record_bytes(self):
        # DESIGN section 3 and section 6 (RA2-2): None for v4 inputs is refused, and so are bytes whose digest
        # differs from recordSha256; matching bytes are validated and their aliases passed by keyword.
        raw = canonical(record_value())
        inputs = inputs_v4(raw)
        trees = self.trees(inputs, record_value()["aliases"])
        calls = []

        def graph(roots, **kwargs):
            calls.append(kwargs)
            return trees
        patch(self, launcher, "system_inventories", graph)
        with self.assertRaises(Refused):
            launcher.verify_tools(inputs)
        with self.assertRaises(Refused):
            launcher.verify_tools(inputs, root_aliases_raw=None)
        with self.assertRaises(Refused):
            launcher.verify_tools(inputs, root_aliases_raw=canonical(record_value([LIB64])))
        calls.clear()
        launcher.verify_tools(inputs, root_aliases_raw=raw)
        self.assertTrue(calls and calls[-1].get("root_aliases"))

    def test_rule_12_root_alias_entries_never_tool_candidates(self):
        # DESIGN section 4 rule 12: verify_tools() leaves rootAlias entries out of system_nodes. The double's
        # last list carries a rootAlias entry keyed like the selected git; admitted as a node, it would
        # shadow git and fail "selected system tool not inventoried".
        raw = canonical(record_value())
        inputs = inputs_v4(raw)
        trees = self.trees(inputs, record_value()["aliases"])
        trees["/usr/lib64"].append({"kind": "rootAlias", "path": "/usr/bin/git", "target": "usr/bin/git",
                                    "resolvedPath": "/usr/bin/git"})
        trees["/usr/lib64"] = trees.pop("/usr/lib64")
        self.bind(inputs, trees)
        self.assertEqual(list(trees)[-1], "/usr/lib64")
        patch(self, launcher, "system_inventories", lambda roots, **kwargs: trees)
        launcher.verify_tools(inputs, root_aliases_raw=raw)


class OsView:
    """launcher's view of os for the descriptor tests: synthetic root custody and fd link text for the
    test's own descriptors only; everything else is the real os module."""

    def __init__(self):
        self.links, self.modes, self.owners, self.nlinks, self.closed = {}, {}, {}, {}, set()

    def __getattr__(self, name):
        return getattr(os, name)

    def readlink(self, path, *args, **kwargs):
        head, _, tail = str(path).rpartition("/")
        if tail.isdigit() and int(tail) in self.links and head.endswith("/fd"):
            return self.links[int(tail)]
        return os.readlink(path, *args, **kwargs)

    def fstat(self, fd, *args, **kwargs):
        real = os.fstat(fd, *args, **kwargs)
        if fd not in self.links:
            return real
        uid, gid = self.owners.get(fd, (0, 0))
        return SimpleNamespace(st_mode=self.modes.get(fd, stat.S_IFREG | 0o444), st_uid=uid, st_gid=gid,
                               st_nlink=self.nlinks.get(fd, 1), st_size=real.st_size, st_dev=real.st_dev,
                               st_ino=real.st_ino, st_mtime_ns=real.st_mtime_ns, st_ctime_ns=real.st_ctime_ns)

    def close(self, fd):
        self.closed.add(fd)
        os.close(fd)

    def release(self, fd):
        if fd not in self.closed:
            self.closed.add(fd)
            with contextlib.suppress(OSError):
                os.close(fd)


class AuthorityRouteTest(unittest.TestCase):
    """DESIGN section 3, the authority route (RA1-2, choice 1, RA2-1, RA2-2)."""

    PUBLIC_KEY = b"synthetic source-test public key"
    LAUNCHER_BYTES = b"synthetic source-test launcher"

    def test_record_path_beside_policy(self):
        # DESIGN section 3, The path: ROOT_ALIASES = TRUST + "/linux-runner/root-aliases.json", beside POLICY.
        self.assertEqual(common.ROOT_ALIASES, common.TRUST + "/linux-runner/root-aliases.json")
        self.assertEqual(Path(common.ROOT_ALIASES).parent, Path(common.POLICY).parent)

    def test_authority_files_four_seven_five_eight(self):
        # DESIGN section 3, The descriptor sets (choice 1): 4 and 7 names for v3, 5 and 8 for v4.
        policy3, policy4 = policy_for(inputs_v3()), policy_for(inputs_v4())
        for policy, only, expected, count in ((policy3, True, v3_names(False), 4), (policy3, False, v3_names(True), 7),
                                              (policy4, True, v4_names(False), 5), (policy4, False, v4_names(True), 8)):
            with self.subTest(inputs=policy["inputs"]["schemaVersion"], preflight_only=only):
                files = dict(launcher.authority_files(policy, only))
                self.assertEqual(files, expected)
                self.assertEqual(len(files), count)

    def test_hidden_paths_add_record_for_v4_only(self):
        # DESIGN section 3, Hidden paths: hidden_paths(policy) adds ROOT_ALIASES for v4 policies only.
        hidden3 = launcher.hidden_paths(policy_for(inputs_v3()))
        hidden4 = launcher.hidden_paths(policy_for(inputs_v4()))
        self.assertNotIn(common.ROOT_ALIASES, hidden3)
        self.assertEqual(hidden4.count(common.ROOT_ALIASES), 1)
        self.assertEqual([path for path in hidden4 if path != common.ROOT_ALIASES], hidden3)
        self.assertEqual(len(hidden4), len(hidden3) + 1)

    def internal(self, policy, names, record_raw=None, reported=None, modes=None, owners=None, nlinks=None):
        """Run internal_authority() on real descriptors with synthetic custody metadata and a synthetic
        signature primitive (no operational key); every kit check runs."""
        policy_raw = canonical(policy)
        contents = {
            "anchor": canonical({"schemaVersion": "planeon.linux-runner-custody/v1",
                                 "publicKeySha256": digest(self.PUBLIC_KEY),
                                 "launcherSha256": digest(self.LAUNCHER_BYTES),
                                 "policySha256": digest(policy_raw)}),
            "public": self.PUBLIC_KEY, "policy": policy_raw,
            "signature": synthetic_signature(self.PUBLIC_KEY, launcher.POLICY_DOMAIN + policy_raw),
            "rootAliases": b"" if record_raw is None else record_raw,
        }
        tmp = make_tmp(self)
        view = OsView()
        descriptors = {}
        for index, (name, path) in enumerate(names.items()):
            file = tmp / ("descriptor-%d" % index)
            file.write_bytes(contents.get(name, b"{}"))
            fd = os.open(file, os.O_RDONLY)
            self.addCleanup(view.release, fd)
            descriptors[name] = fd
            view.links[fd] = (reported or {}).get(name, path)
            if name in (modes or {}):
                view.modes[fd] = modes[name]
            if name in (owners or {}):
                view.owners[fd] = owners[name]
            if name in (nlinks or {}):
                view.nlinks[fd] = nlinks[name]
        context = {"preflightOnly": True, "authorityDescriptors": descriptors, "policy": policy,
                   "policySha256": digest(policy_raw), "launcherSha256": digest(self.LAUNCHER_BYTES),
                   "roots": policy["warmRoots"], "hiddenPaths": launcher.hidden_paths(policy),
                   "launcher": common.LAUNCHER}

        def root_read(path, **kwargs):
            if path != common.LAUNCHER:
                raise AssertionError("unexpected root read inside isolation")
            return self.LAUNCHER_BYTES
        with mock.patch.object(launcher, "os", view), mock.patch.object(launcher, "root_read", root_read), \
                mock.patch.object(launcher, "pem_public", lambda raw: raw), \
                mock.patch.object(launcher, "verify", synthetic_verify):
            return launcher.internal_authority(context)

    def test_internal_v3_set_for_v3_policy(self):
        # DESIGN section 3, Inside isolation, step 5 (RA2-1): the verified policy, and None for v3.
        policy = policy_for(inputs_v3())
        result = self.internal(policy, v3_names(False))
        self.assertEqual(canonical(result[0]), canonical(policy))
        self.assertIsNone(result[1])

    def test_internal_v4_set_for_v4_policy(self):
        # DESIGN section 3, Inside isolation, step 5 (RA2-1): the verified policy with the record's bytes.
        raw = canonical(record_value())
        policy = policy_for(inputs_v4(raw))
        result = self.internal(policy, v4_names(False), raw)
        self.assertEqual(canonical(result[0]), canonical(policy))
        self.assertEqual(result[1], raw)

    def test_internal_v4_policy_without_record_refused(self):
        # DESIGN section 3, Inside isolation, step 4: a v4 policy without rootAliases is refused.
        policy = policy_for(inputs_v4())
        with self.assertRaises(Refused):
            self.internal(policy, v3_names(False))

    def test_internal_v3_policy_with_record_refused(self):
        # DESIGN section 3, Inside isolation, step 4: a v3 policy with rootAliases is refused.
        policy = policy_for(inputs_v3())
        with self.assertRaises(Refused):
            self.internal(policy, v4_names(False), canonical(record_value()))

    def test_internal_name_set_neither_v3_nor_v4_refused(self):
        # DESIGN section 3, Inside isolation, step 1 and section 6 (RA2-2): exactly the v3 or the v4 set.
        policy = policy_for(inputs_v3())
        extra = {**v3_names(False), "manifest": common.MANIFEST}
        short = {name: path for name, path in v3_names(False).items() if name != "signature"}
        odd = {**v4_names(False), "extra": common.POLICY + ".extra"}
        for label, names in (("v3 plus one", extra), ("normal set", v3_names(True)), ("short", short),
                             ("v4 plus one", odd)):
            with self.subTest(names=label), self.assertRaises(Refused):
                self.internal(policy, names, canonical(record_value()))

    def test_internal_record_descriptor_custody(self):
        # DESIGN section 3, Inside isolation, step 2 and section 6: the record descriptor's readlink path,
        # group or other write, nlink and root ownership.
        raw = canonical(record_value())
        policy = policy_for(inputs_v4(raw))
        cases = {"readlink path": {"reported": {"rootAliases": common.POLICY}},
                 "group-writable": {"modes": {"rootAliases": stat.S_IFREG | 0o464}},
                 "other-writable": {"modes": {"rootAliases": stat.S_IFREG | 0o446}},
                 "not regular": {"modes": {"rootAliases": stat.S_IFDIR | 0o555}},
                 "nlink 2": {"nlinks": {"rootAliases": 2}},
                 "not root-owned": {"owners": {"rootAliases": (1001, 1001)}}}
        for label, overrides in cases.items():
            with self.subTest(case=label), self.assertRaises(Refused):
                self.internal(policy, v4_names(False), raw, **overrides)

    def test_closing_recheck_present(self):
        # DESIGN section 3, After the session: main()'s closing re-check also reads ROOT_ALIASES after the
        # isolation session (digest(root_read(ROOT_ALIASES)) == recordSha256 for v4).
        def name(node):
            return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None

        def reads_record(nodes):
            nodes = list(nodes)
            return ("ROOT_ALIASES" in {name(node) for node in nodes if isinstance(node, (ast.Name, ast.Attribute))}
                    and "root_read" in {name(node.func) for node in nodes if isinstance(node, ast.Call)})
        module = ast.parse(inspect.getsource(launcher))
        functions = {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}
        main = ast.parse(textwrap.dedent(inspect.getsource(launcher.main)))
        sessions = [node.end_lineno for node in ast.walk(main)
                    if isinstance(node, ast.Call) and name(node.func) == "supervise"]
        self.assertTrue(sessions)
        after = [node for node in ast.walk(main) if getattr(node, "lineno", 0) > max(sessions)]
        helpers = {name(node.func) for node in after if isinstance(node, ast.Call)} & set(functions) - {"main"}
        self.assertTrue(reads_record(after)
                        or any(reads_record(ast.walk(functions[helper])) for helper in helpers))


class VersionProfileTest(unittest.TestCase):
    """DESIGN section 2, Kit version (choice 3)."""

    def manifest(self, launcher_version, suite_version):
        return {"schemaVersion": "harness.planeon.ai/trusted-runner-manifest/v1alpha1",
                "launcher": {"path": common.LAUNCHER, "version": launcher_version, "sha256": "1" * 64,
                             "ownerUid": 0, "ownerGid": 0, "mode": "0555"},
                "runner": dict(common.RUNNER),
                "isolation": {**common.ISOLATION, "warmSourceRoots": ["/srv/planeon/warm-snapshots/reference"]},
                "preflight": {"suiteVersion": suite_version, "status": "PASS", "evidenceSha256": "2" * 64,
                              **{name: True for name in common.PROOFS}},
                "signature": {"algorithm": "ED25519", "signaturePath": common.MANIFEST + ".sig",
                              "publicKeyPath": common.PUBLIC, "publicKeySha256": "3" * 64}}

    def test_kit_version(self):
        # DESIGN section 2, Kit version (choice 3): common.VERSION becomes 1.3.0.
        self.assertEqual(common.VERSION, "1.3.0")

    def test_version_bound_into_manifest_and_preflight(self):
        # DESIGN section 2, Kit version: bound into launcher.version and the preflight's suiteVersion.
        common.validate_manifest(self.manifest("1.3.0", "1.3.0"))
        for launcher_version, suite_version in (("1.2.0", "1.3.0"), ("1.3.0", "1.2.0")):
            with self.subTest(launcher=launcher_version, suite=suite_version), self.assertRaises(Refused):
                common.validate_manifest(self.manifest(launcher_version, suite_version))

    def test_profile_bytes_unchanged(self):
        # DESIGN section 2, Kit version: the label does not embed VERSION, so profile_bytes() is
        # byte-identical for the same inputs.
        profile = launcher.profile_bytes(policy_for(inputs_v3()))
        self.assertEqual(profile.split(b"\n", 1)[0], b"# MET-LINUX-004 candidate v3; native preflight required")
        self.assertEqual(digest(profile), V3_PROFILE_SHA256)


@unittest.skipIf(os.geteuid() == 0, "prepare.py refuses a privileged caller by design")
class PrepareTest(unittest.TestCase):
    """DESIGN section 5 (the prepare.py row) and section 6 (prepare.py, RA2-2)."""

    def setUp(self):
        self.tmp = make_tmp(self)
        self.cases = 0

    def request(self, inputs):
        request = policy_for(inputs)
        del request["profileSha256"]
        return request

    def run_prepare(self, request, record_raw=None):
        self.cases += 1
        case = self.tmp / ("case-%d" % self.cases)
        mkdirs(case)
        request_path, output = case / "request.json", case / "output"
        request_path.write_bytes(canonical(request))
        argv = ["prepare.py", "--request", str(request_path), "--output", str(output)]
        if record_raw is not None:
            (case / "record.json").write_bytes(record_raw)
            argv += ["--root-aliases", str(case / "record.json")]
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            prepare.main()
        return json.loads(stdout.getvalue()), output

    def test_v3_request_output_unchanged(self):
        # DESIGN section 5: v3 output unchanged.
        request = self.request(inputs_v3())
        result, output = self.run_prepare(request)
        profile = launcher.profile_bytes({**request, "profileSha256": "0" * 64})
        expected = canonical({**request, "profileSha256": digest(profile)})
        self.assertEqual((output / "policy.json.unsigned").read_bytes(), expected)
        self.assertEqual((output / "firejail.profile.candidate").read_bytes(), profile)
        self.assertEqual(result["status"], "UNSIGNED_CANDIDATE")
        self.assertEqual(result["policySha256"], digest(expected))

    def test_v4_request_with_reviewed_record(self):
        # DESIGN section 5: --root-aliases <file> for v4 requests, validated by common.root_aliases().
        raw = canonical(record_value())
        request = self.request(inputs_v4(raw))
        result, output = self.run_prepare(request, raw)
        self.assertEqual(result["status"], "UNSIGNED_CANDIDATE")
        self.assertEqual(common.parse((output / "policy.json.unsigned").read_bytes())["inputs"], request["inputs"])

    def test_v4_request_without_record_refused(self):
        # DESIGN section 5 and section 6: a v4 request without --root-aliases.
        with self.assertRaises(Refused):
            self.run_prepare(self.request(inputs_v4()))

    def test_v4_record_digest_mismatch_refused(self):
        # DESIGN section 6: a record whose digest differs from the request's recordSha256.
        request = self.request(inputs_v4(canonical(record_value())))
        with self.assertRaises(Refused):
            self.run_prepare(request, canonical(record_value([LIB64])))

    def test_v4_record_breaking_a_rule_refused(self):
        # DESIGN section 6: a record that breaks a record rule, with a matching digest.
        wrong_image = record_value()
        wrong_image["imageDigest"] = "sha256:" + "4" * 64
        for raw in (canonical(wrong_image), canonical(record_value([LIB64, LIB]))):
            with self.subTest(record=raw[:24]), self.assertRaises(Refused):
                self.run_prepare(self.request(inputs_v4(raw)), raw)

    def test_v3_request_with_record_refused(self):
        # DESIGN section 5 and section 6: --root-aliases given with a v3 request.
        with self.assertRaises(Refused):
            self.run_prepare(self.request(inputs_v3()), canonical(record_value()))


if __name__ == "__main__":
    unittest.main()
