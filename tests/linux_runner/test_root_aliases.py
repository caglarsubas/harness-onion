"""MET-LINUX-009 source tests: the signed root-alias record, its custody, resolution and authority route.

Synthetic trees only. Production's ALIAS_PARENT ("/") and root-only custody are asserted separately; the tree tests
patch ALIAS_PARENT to a temporary bridge, as the existing tests patch trusted_entry. No Linux host PASS is claimed.
"""
import copy
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import common
import launcher
from common import (ALIAS_PARENT, INPUTS_V4, LAUNCHER, ROOT_ALIAS_PATH, ROOT_ALIASES, Refused, canonical, digest, inventory,
                    root_alias_custody, root_aliases, system_inventories, validate_inputs)

IMAGE = "sha256:" + "3" * 64


@pytest.fixture
def synthetic_owner(monkeypatch):
    # tmp_path is user-owned; production's root-only predicate is asserted in its own test below.
    monkeypatch.setattr(common, "trusted_entry", lambda m: m.st_uid in (0, os.getuid())
                        and (stat.S_ISDIR(m.st_mode) or stat.S_ISLNK(m.st_mode) or not m.st_mode & 0o022))
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def tree(tmp_path, monkeypatch):
    """A merged-/usr shape under tmp: usr/lib64 (loader), usr/lib (loader), usr/bin, with tmp as the alias parent."""
    base = tmp_path.resolve(strict=True)
    for name in ("usr/lib64", "usr/lib", "usr/bin"):
        (base / name).mkdir(parents=True)
    (base / "usr/lib64/ld-linux-x86-64.so.2").write_bytes(b"amd64 loader")
    (base / "usr/lib/ld-linux-aarch64.so.1").write_bytes(b"arm64 loader")
    monkeypatch.setattr(common, "ALIAS_PARENT", str(base))
    return base


def alias(path, target, root):
    return {"path": path, "target": target, "treeRoot": str(root)}


def roots(base):
    return [str(base / "usr/bin"), str(base / "usr/lib"), str(base / "usr/lib64")]


# --- the record (DESIGN section 2) -----------------------------------------------------------------------------

@pytest.fixture
def v4_inputs(inputs):
    value = copy.deepcopy(inputs)
    value["schemaVersion"] = INPUTS_V4
    value["systemTrees"].append({"root": "/usr/lib64", "inventorySha256": "c" * 64})
    record = {"aliases": [{"path": "/lib64", "target": "usr/lib64", "treeRoot": "/usr/lib64"}],
              "imageDigest": IMAGE, "schemaVersion": "planeon.linux-root-aliases/v1"}
    value["rootAliases"] = {"recordSha256": digest(canonical(record))}
    return value, record


def rebind(inputs, raw):
    inputs["rootAliases"]["recordSha256"] = digest(raw)
    return raw


def test_v4_inputs_and_record_are_accepted(v4_inputs):
    inputs, record = v4_inputs
    assert validate_inputs(inputs) is inputs
    assert root_aliases(canonical(record), inputs) == tuple(record["aliases"])


def test_v3_inputs_are_unchanged_and_take_no_record(inputs, v4_inputs):
    assert validate_inputs(inputs) is inputs
    assert root_aliases(None, inputs) == ()
    with pytest.raises(Refused, match="v3 inputs"):
        root_aliases(canonical(v4_inputs[1]), inputs)
    bad = copy.deepcopy(inputs)
    bad["rootAliases"] = {"recordSha256": "0" * 64}
    with pytest.raises(Refused, match="unknown or missing field"):
        validate_inputs(bad)


def test_v4_inputs_need_their_digest_member(v4_inputs):
    inputs, _ = v4_inputs
    del inputs["rootAliases"]
    with pytest.raises(Refused, match="unknown or missing field"):
        validate_inputs(inputs)


@pytest.mark.parametrize("change, reason", [
    (lambda r: r.pop("imageDigest"), "unknown or missing field"),
    (lambda r: r.update(extra=1), "unknown or missing field"),
    (lambda r: r.update(schemaVersion="planeon.linux-root-aliases/v2"), "record version"),
    (lambda r: r.update(imageDigest="sha256:" + "9" * 64), "image differs"),
    (lambda r: r.update(aliases=[]), "list empty"),
    (lambda r: r["aliases"][0].update(path="/usr/sbin"), "alias path"),
    (lambda r: r["aliases"][0].update(path="/a/b"), "alias path"),
    (lambda r: r["aliases"][0].update(path="/"), "alias path"),
    (lambda r: r["aliases"][0].update(path="/."), "alias path"),
    (lambda r: r["aliases"][0].update(path="/.."), "alias path"),
    (lambda r: r["aliases"][0].update(path="/usr"), "alias path"),
    (lambda r: r["aliases"][0].update(target=""), "alias target"),
    (lambda r: r["aliases"][0].update(target="usr/lib64\x00"), "alias target"),
    (lambda r: r["aliases"][0].update(target="a" * 4097), "alias target"),
    (lambda r: r["aliases"][0].update(treeRoot="/usr/libexec"), "alias tree"),
    (lambda r: r["aliases"][0].update(treeRoot="/opt/planeon/cache/python"), "alias tree"),
    (lambda r: r["aliases"][0].update(treeRoot="/opt/planeon/python/3.12.14"), "alias tree"),
    (lambda r: r["aliases"][0].pop("target"), "unknown or missing field"),
    (lambda r: r["aliases"].append({"path": "/lib64", "target": "usr/lib64", "treeRoot": "/usr/lib"}), "order or duplicate"),
    (lambda r: r["aliases"].insert(0, {"path": "/lib", "target": "usr/lib", "treeRoot": "/usr/lib64"}), "alias tree"),
    (lambda r: r.update(aliases=[{"path": "/lib64", "target": "usr/lib64", "treeRoot": "/usr/lib64"},
                                 {"path": "/lib", "target": "usr/lib", "treeRoot": "/usr/lib"}]), "order or duplicate"),
])
def test_record_rules_refuse(v4_inputs, change, reason):
    inputs, record = v4_inputs
    change(record)
    with pytest.raises(Refused, match=reason):
        root_aliases(rebind(inputs, canonical(record)), inputs)


def test_record_bytes_digest_and_bound(v4_inputs):
    inputs, record = v4_inputs
    with pytest.raises(Refused, match="record digest"):
        root_aliases(canonical(record) + b" ", inputs)
    pretty = rebind(inputs, json.dumps(record, indent=1).encode())
    with pytest.raises(Refused, match="not canonical"):
        root_aliases(pretty, inputs)
    duplicate = rebind(inputs, canonical(record)[:-1] + b',"imageDigest":"' + IMAGE.encode() + b'"}')
    with pytest.raises(Refused, match="duplicate JSON field"):
        root_aliases(duplicate, inputs)
    with pytest.raises(Refused, match="missing or oversized"):
        root_aliases(rebind(inputs, b" " * (64 * 1024 + 1)), inputs)
    with pytest.raises(Refused, match="missing or oversized"):
        root_aliases(None, inputs)


# --- custody (DESIGN section 4, rules 1-5) ----------------------------------------------------------------------

LINK = stat.S_IFLNK | 0o777
DIRECTORY = stat.S_IFDIR | 0o755


@pytest.mark.parametrize("alias_meta, parent_meta", [
    (SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0, st_nlink=1), SimpleNamespace(st_mode=DIRECTORY, st_uid=0, st_gid=0)),
    (SimpleNamespace(st_mode=LINK, st_uid=1001, st_gid=1001, st_nlink=1), SimpleNamespace(st_mode=DIRECTORY, st_uid=0, st_gid=0)),
    (SimpleNamespace(st_mode=LINK, st_uid=0, st_gid=0, st_nlink=2), SimpleNamespace(st_mode=DIRECTORY, st_uid=0, st_gid=0)),
    (SimpleNamespace(st_mode=LINK, st_uid=0, st_gid=0, st_nlink=1), SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=0)),
    (SimpleNamespace(st_mode=LINK, st_uid=0, st_gid=0, st_nlink=1), SimpleNamespace(st_mode=DIRECTORY, st_uid=1001, st_gid=0)),
    (SimpleNamespace(st_mode=LINK, st_uid=0, st_gid=0, st_nlink=1), SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)),
])
def test_production_custody_refuses(alias_meta, parent_meta):
    with pytest.raises(Refused, match="root alias custody"):
        root_alias_custody(alias_meta, parent_meta)


def test_production_constants_and_custody_predicate():
    assert ALIAS_PARENT == "/"
    assert ROOT_ALIASES == "/etc/planeon/linux-runner/root-aliases.json"
    assert ROOT_ALIAS_PATH.fullmatch("/lib64") and not ROOT_ALIAS_PATH.fullmatch("/usr/lib64")
    assert common.VERSION == "1.3.0"
    root_alias_custody(SimpleNamespace(st_mode=LINK, st_uid=0, st_gid=0, st_nlink=1),
                       SimpleNamespace(st_mode=DIRECTORY, st_uid=0, st_gid=0))
    assert not common.trusted_entry(SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=0))


# --- resolution and the inventory entry (rules 6-12) ------------------------------------------------------------

def test_listed_alias_is_admitted_and_bound(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    (base / "lib").symlink_to("usr/lib")
    (base / "usr/bin/ld-amd64").symlink_to(str(base / "lib64/ld-linux-x86-64.so.2"))
    (base / "usr/bin/ld-arm64").symlink_to(str(base / "lib/ld-linux-aarch64.so.1"))
    aliases = (alias("/lib", "usr/lib", base / "usr/lib"), alias("/lib64", "usr/lib64", base / "usr/lib64"))
    result = system_inventories(roots(base), root_aliases=aliases)
    lib64 = {e["path"]: e for e in result[str(base / "usr/lib64")]}
    assert lib64["/lib64"] == {"kind": "rootAlias", "path": "/lib64", "target": "usr/lib64",
                               "resolvedPath": str(base / "usr/lib64")}
    by_bin = {e["path"]: e for e in result[str(base / "usr/bin")]}
    assert by_bin["ld-amd64"]["resolvedPath"] == str(base / "usr/lib64/ld-linux-x86-64.so.2")
    assert by_bin["ld-arm64"]["resolvedPath"] == str(base / "usr/lib/ld-linux-aarch64.so.1")


def test_without_aliases_inventories_are_byte_identical_and_crossing_is_refused(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    clean = system_inventories(roots(base))
    assert clean == system_inventories(roots(base), root_aliases=())
    assert all(e["kind"] != "rootAlias" for records in clean.values() for e in records)
    (base / "usr/bin/ld-amd64").symlink_to(str(base / "lib64/ld-linux-x86-64.so.2"))
    with pytest.raises(Refused, match="uninventoried"):
        system_inventories(roots(base))
    with pytest.raises(Refused, match="uninventoried"):
        inventory(base / "usr/bin", trusted=True, system=True)


@pytest.mark.parametrize("make, record, reason", [
    (lambda b: None, ("/lib64", "usr/lib64"), "root alias custody"),
    (lambda b: (b / "lib64").mkdir(), ("/lib64", "usr/lib64"), "root alias custody"),
    (lambda b: (b / "lib64").symlink_to("usr/lib"), ("/lib64", "usr/lib64"), "target changed"),
    (lambda b: (b / "lib64").symlink_to("usr"), ("/lib64", "usr"), "not inventoried"),
    (lambda b: ((b / "usr/lib64/sub").mkdir(), (b / "lib64").symlink_to("usr/lib64/sub")), ("/lib64", "usr/lib64/sub"),
     "does not resolve"),
    (lambda b: ((b / "lib").symlink_to("usr/lib"), (b / "lib64").symlink_to("lib")), ("/lib64", "lib"), "uninventoried"),
])
def test_alias_custody_and_resolution_refuse(tmp_path, synthetic_owner, monkeypatch, make, record, reason):
    base = tree(tmp_path, monkeypatch)
    make(base)
    with pytest.raises(Refused, match=reason):
        system_inventories(roots(base), root_aliases=(alias(record[0], record[1], base / "usr/lib64"),))


def test_alias_escaping_the_parent_is_refused(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    escape = "../" * len(Path(base).parts) + "usr/lib64"
    (base / "lib64").symlink_to(escape)
    with pytest.raises(Refused, match="escapes root"):
        system_inventories(roots(base), root_aliases=(alias("/lib64", escape, base / "usr/lib64"),))


def test_alias_tree_must_be_declared(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    with pytest.raises(Refused, match="tree not declared"):
        system_inventories(roots(base)[:2], root_aliases=(alias("/lib64", "usr/lib64", base / "usr/lib64"),))


def test_alias_replaced_by_a_new_inode_is_refused(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    link = base / "lib64"
    link.symlink_to("usr/lib64")
    real_readlink = os.readlink
    swapped = []

    def swap(path, *args, **kwargs):
        value = real_readlink(path, *args, **kwargs)
        if str(path) == str(link) and not swapped:
            swapped.append(True)
            link.unlink()
            link.symlink_to("usr/lib64")
        return value
    monkeypatch.setattr(common.os, "readlink", swap)
    with pytest.raises(Refused, match="changed during resolution"):
        system_inventories(roots(base), root_aliases=(alias("/lib64", "usr/lib64", base / "usr/lib64"),))


# --- the authority route (DESIGN section 3) ---------------------------------------------------------------------

def test_descriptor_sets_and_hidden_paths(policy, v4_inputs):
    v4 = copy.deepcopy(policy)
    v4["inputs"] = v4_inputs[0]
    assert len(launcher.authority_files(policy, True)) == 4 and len(launcher.authority_files(policy, False)) == 7
    assert len(launcher.authority_files(v4, True)) == 5 and len(launcher.authority_files(v4, False)) == 8
    assert launcher.authority_files(v4, False)["rootAliases"] == ROOT_ALIASES
    assert ROOT_ALIASES not in launcher.hidden_paths(policy)
    assert launcher.hidden_paths(v4) == launcher.hidden_paths(policy)[:7] + [ROOT_ALIASES] + launcher.hidden_paths(policy)[7:]
    same_trees = copy.deepcopy(v4)
    same_trees["inputs"]["schemaVersion"] = policy["inputs"]["schemaVersion"]
    del same_trees["inputs"]["rootAliases"]
    assert launcher.profile_bytes(v4) == launcher.profile_bytes(same_trees)
    lines = launcher.profile_bytes(v4).decode().splitlines()
    assert not any(line.endswith(" /lib64") for line in lines) and not any(ROOT_ALIASES in line for line in lines)


@pytest.mark.parametrize("preflight_only, names", [
    (True, list(launcher.AUTHORITY_FILES)[:3]),
    (True, [*launcher.AUTHORITY_FILES, "rootAliases", "manifest"]),
    (False, [*launcher.AUTHORITY_FILES, "rootAliases"]),
    (False, [*launcher.NORMAL_AUTHORITY_FILES, "extra"]),
])
def test_internal_descriptor_name_set_is_closed(policy, preflight_only, names):
    context = {"preflightOnly": preflight_only, "policy": policy,
               "authorityDescriptors": {name: 90 + index for index, name in enumerate(names)}}
    with pytest.raises(Refused, match="authority descriptor set"):
        launcher.internal_authority(context)


def test_prepare_requires_the_record_exactly_for_v4(policy, v4_inputs, tmp_path):
    from prepare import prepare
    inputs, record = v4_inputs
    request = {k: v for k, v in policy.items() if k != "profileSha256"}
    with pytest.raises(Refused, match="only and always for v4"):
        prepare(request, tmp_path.resolve() / "v3", 150, canonical(record))
    request_v4 = {**request, "inputs": inputs}
    with pytest.raises(Refused, match="only and always for v4"):
        prepare(request_v4, tmp_path.resolve() / "none", 150)
    with pytest.raises(Refused, match="record digest"):
        prepare(request_v4, tmp_path.resolve() / "digest", 150, canonical(record) + b" ")
    broken = copy.deepcopy(record)
    broken["aliases"][0]["path"] = "/usr"
    inputs["rootAliases"]["recordSha256"] = digest(canonical(broken))
    with pytest.raises(Refused, match="alias path"):
        prepare(request_v4, tmp_path.resolve() / "rule", 150, canonical(broken))
    inputs["rootAliases"]["recordSha256"] = digest(canonical(record))
    result = prepare(request_v4, tmp_path.resolve() / "ok", 150, canonical(record))
    assert result["status"] == "UNSIGNED_CANDIDATE" and result["installed"] is False


# --- more resolution vectors (DESIGN section 6) -----------------------------------------------------------------

@pytest.mark.parametrize("links, listed, reason", [
    ({"lib64": "usr/lib"}, [("/lib64", "usr/lib", "usr/lib64")], "does not resolve"),
    ({"lib": "usr/lib", "lib64": "lib"}, [("/lib", "usr/lib", "usr/lib"), ("/lib64", "lib", "usr/lib64")],
     "uninventoried"),
    ({"lib": "lib64", "lib64": "lib"}, [("/lib", "lib64", "usr/lib"), ("/lib64", "lib", "usr/lib64")],
     "uninventoried"),
    ({"lib64": "."}, [("/lib64", ".", "usr/lib64")], "not inventoried"),
])
def test_listed_alias_resolution_refuses(tmp_path, synthetic_owner, monkeypatch, links, listed, reason):
    # Outside its tree; chained through another listed alias; a cycle among aliases; to the parent bridge.
    base = tree(tmp_path, monkeypatch)
    for name, target in links.items():
        (base / name).symlink_to(target)
    with pytest.raises(Refused, match=reason):
        system_inventories(roots(base), root_aliases=tuple(alias(p, t, base / r) for p, t, r in listed))


def test_in_tree_link_through_an_alias_and_parent_step(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    (base / "lib").symlink_to("usr/lib")
    listed = (alias("/lib", "usr/lib", base / "usr/lib"), alias("/lib64", "usr/lib64", base / "usr/lib64"))
    (base / "usr/bin/cross").symlink_to(str(base / "lib64/../lib/ld-linux-aarch64.so.1"))
    result = system_inventories(roots(base), root_aliases=listed)
    by_bin = {e["path"]: e for e in result[str(base / "usr/bin")]}
    assert by_bin["cross"]["resolvedPath"] == str(base / "usr/lib/ld-linux-aarch64.so.1")
    (base / "usr/bin/up").symlink_to(str(base / "lib64/.."))
    with pytest.raises(Refused, match="target not inventoried"):
        system_inventories(roots(base), root_aliases=listed)


def test_in_tree_cycle_through_an_alias(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    (base / "usr/lib64/loop").symlink_to(str(base / "lib64/loop"))
    with pytest.raises(Refused, match="cyclic or excessive"):
        system_inventories(roots(base), root_aliases=(alias("/lib64", "usr/lib64", base / "usr/lib64"),))


def test_unlisted_root_level_link_stays_refused_beside_a_listed_one(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    (base / "lib").symlink_to("usr/lib")
    (base / "usr/bin/ld-amd64").symlink_to(str(base / "lib64/ld-linux-x86-64.so.2"))
    with pytest.raises(Refused, match="uninventoried"):
        system_inventories(roots(base), root_aliases=(alias("/lib", "usr/lib", base / "usr/lib"),))


def test_link_in_another_bridge_stays_refused(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    (base / "lib64").symlink_to("usr/lib64")
    (base / "usr/lib32").symlink_to("lib")
    (base / "usr/bin/ld").symlink_to(str(base / "usr/lib32/ld-linux-aarch64.so.1"))
    with pytest.raises(Refused, match="uninventoried"):
        system_inventories(roots(base), root_aliases=(alias("/lib64", "usr/lib64", base / "usr/lib64"),))


def test_cache_and_tool_inventories_keep_aliases_forbidden(tmp_path, synthetic_owner, monkeypatch):
    base = tree(tmp_path, monkeypatch)
    cache = base / "cache"
    cache.mkdir()
    (cache / "lib64").symlink_to("../usr/lib64")
    with pytest.raises(Refused):
        inventory(cache)


@pytest.mark.parametrize("path", ["/etc", "/opt"])
def test_record_path_naming_a_root_ancestor_is_refused(v4_inputs, path):
    inputs, record = v4_inputs
    record["aliases"][0]["path"] = path
    with pytest.raises(Refused, match="alias path"):
        root_aliases(rebind(inputs, canonical(record)), inputs)


# --- the authority route: verify_tools, internal_authority, load_authority, main, the manifest gate ----------

class Host:
    """launcher's os module with the named calls replaced; every other name is the real one."""

    def __init__(self, **calls):
        self.__dict__.update(calls)

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.fixture
def v4_policy(policy, v4_inputs):
    value = copy.deepcopy(policy)
    value["inputs"] = v4_inputs[0]
    value["profileSha256"] = digest(launcher.profile_bytes(value))
    return value


def tools_host(monkeypatch, inputs, graph):
    cache = b"pinned loader cache"
    inputs["systemFiles"]["/etc/ld.so.cache"] = digest(cache)
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(launcher.os.path, "lexists", lambda _: False)
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0))
    monkeypatch.setattr(launcher, "root_read", lambda path, **k: cache if path == "/etc/ld.so.cache" else pytest.fail(path))
    monkeypatch.setattr(launcher, "system_inventories", graph)


@pytest.mark.parametrize("version, raw, reason", [
    ("v3", b"{}", "v3 inputs"), ("v4", None, "missing or oversized"), ("v4", b"changed", "record digest")])
def test_verify_tools_binds_the_record_to_the_inputs(inputs, v4_inputs, monkeypatch, version, raw, reason):
    value = inputs if version == "v3" else v4_inputs[0]
    tools_host(monkeypatch, value, lambda *a, **k: pytest.fail("record refusal must come before the graph"))
    with pytest.raises(Refused, match=reason):
        launcher.verify_tools(value, raw)


def test_verify_tools_passes_listed_aliases_to_the_graph(inputs, v4_inputs, monkeypatch):
    calls = []

    def graph(roots, **kwargs):
        calls.append((roots, kwargs))
        raise Refused("synthetic graph stop")
    for value, raw in ((inputs, None), (v4_inputs[0], canonical(v4_inputs[1]))):
        tools_host(monkeypatch, value, graph)
        with pytest.raises(Refused, match="synthetic graph stop"):
            launcher.verify_tools(value, raw)
    assert calls[0][1] == {} and calls[1][1] == {"root_aliases": tuple(v4_inputs[1]["aliases"])}
    assert "/usr/lib64" in calls[1][0] and "/usr/lib64" not in calls[0][0]


def internal(policy, monkeypatch, *, names=None, record=b"", change=None):
    public, candidate = b"synthetic-public", b"candidate"
    policy_raw = canonical(policy)
    blobs = {"anchor": canonical({"schemaVersion": "planeon.linux-runner-custody/v1", "publicKeySha256": digest(public),
                                  "launcherSha256": digest(candidate), "policySha256": digest(policy_raw)}),
             "public": public, "policy": policy_raw, "signature": b"synthetic-signature", "rootAliases": record}
    files = {**launcher.AUTHORITY_FILES, "rootAliases": ROOT_ALIASES}
    fds = {name: 90 + index for index, name in enumerate(names or launcher.authority_files(policy, True))}
    paths = {fd: files[name] for name, fd in fds.items()}
    data = {fd: blobs[name] for name, fd in fds.items()}
    meta = {fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1, st_size=len(data[fd]))
            for fd in fds.values()}
    if change:
        change(fds, paths, meta)
    monkeypatch.setattr(launcher, "os", Host(readlink=lambda p: paths[int(p.rsplit("/", 1)[1])], fstat=meta.__getitem__,
                                             lseek=lambda *a: 0, read=lambda fd, n: data[fd], close=lambda fd: None))
    monkeypatch.setattr(launcher, "root_read", lambda path, **k: candidate)
    monkeypatch.setattr(launcher, "verify_signed", lambda *a, **k: None)
    monkeypatch.setattr(launcher, "pem_public", lambda raw: raw)
    monkeypatch.setattr(launcher.time, "time", lambda: 150)
    return {"preflightOnly": True, "policy": policy, "policySha256": digest(policy_raw),
            "launcherSha256": digest(candidate), "roots": policy["warmRoots"],
            "hiddenPaths": launcher.hidden_paths(policy), "launcher": LAUNCHER, "authorityDescriptors": fds}


def test_internal_authority_returns_the_retained_record(policy, v4_policy, v4_inputs, monkeypatch):
    assert launcher.internal_authority(internal(policy, monkeypatch))[1] is None
    record = canonical(v4_inputs[1])
    context = internal(v4_policy, monkeypatch, record=record)
    assert set(context["authorityDescriptors"]) == {*launcher.AUTHORITY_FILES, "rootAliases"}
    assert launcher.internal_authority(context)[1] == record


def test_internal_record_set_must_match_the_verified_policy(policy, v4_policy, monkeypatch):
    with pytest.raises(Refused, match="authority descriptor set"):
        launcher.internal_authority(internal(policy, monkeypatch, names=[*launcher.AUTHORITY_FILES, "rootAliases"],
                                             record=b"{}"))
    with pytest.raises(Refused, match="authority descriptor set"):
        launcher.internal_authority(internal(v4_policy, monkeypatch, names=list(launcher.AUTHORITY_FILES)))


@pytest.mark.parametrize("change, reason", [
    (lambda fds, paths, meta: paths.update({fds["rootAliases"]: ROOT_ALIASES + ".new"}), "wrong authority descriptor"),
    (lambda fds, paths, meta: setattr(meta[fds["rootAliases"]], "st_mode", stat.S_IFREG | 0o464), "descriptor custody"),
    (lambda fds, paths, meta: setattr(meta[fds["rootAliases"]], "st_nlink", 2), "descriptor custody"),
    (lambda fds, paths, meta: setattr(meta[fds["rootAliases"]], "st_uid", 1001), "descriptor custody"),
])
def test_record_descriptor_custody(v4_policy, v4_inputs, monkeypatch, change, reason):
    context = internal(v4_policy, monkeypatch, record=canonical(v4_inputs[1]), change=change)
    with pytest.raises(Refused, match=reason):
        launcher.internal_authority(context)


def test_internal_context_must_hide_the_record(v4_policy, v4_inputs, monkeypatch):
    context = internal(v4_policy, monkeypatch, record=canonical(v4_inputs[1]))
    context["hiddenPaths"] = [path for path in context["hiddenPaths"] if path != ROOT_ALIASES]
    with pytest.raises(Refused, match="unsigned internal policy substitution"):
        launcher.internal_authority(context)


def test_record_changed_inside_isolation_is_refused(v4_policy, monkeypatch):
    policy, raw = launcher.internal_authority(internal(v4_policy, monkeypatch, record=b"changed"))
    tools_host(monkeypatch, policy["inputs"], lambda *a, **k: pytest.fail("record refusal must come first"))
    with pytest.raises(Refused, match="record digest"):
        launcher.verify_tools(policy["inputs"], raw)


def authority_host(policy, monkeypatch, record, reads, calls):
    from common import ANCHOR, PACKET, POLICY, PROFILE, PUBLIC
    policy = copy.deepcopy(policy)
    policy["packetSha256"] = digest(b"synthetic packet")
    policy_raw, public, candidate = canonical(policy), b"synthetic-public", b"candidate"
    files = {ANCHOR: canonical({"schemaVersion": "planeon.linux-runner-custody/v1", "publicKeySha256": digest(public),
                                "launcherSha256": digest(candidate), "policySha256": digest(policy_raw)}),
             LAUNCHER: candidate, PUBLIC: public, POLICY: policy_raw, POLICY + ".sig": b"synthetic-signature",
             PROFILE: launcher.profile_bytes(policy), PACKET: b"synthetic packet"}
    if record is not None:
        files[ROOT_ALIASES] = record

    def read(path, **kwargs):
        reads.append((path, kwargs))
        if isinstance(files[path], Exception):
            raise files[path]
        return files[path]
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher, "os", Host(getuid=lambda: policy["operatorUid"], geteuid=lambda: policy["operatorUid"]))
    monkeypatch.setattr(launcher.sys, "argv", [LAUNCHER])
    monkeypatch.setattr(launcher, "root_read", read)
    monkeypatch.setattr(launcher, "pem_public", lambda raw: raw)
    monkeypatch.setattr(launcher, "verify_signed", lambda *a, **k: None)
    monkeypatch.setattr(launcher.time, "time", lambda: 150)
    monkeypatch.setattr(launcher, "packet_commands", lambda raw: None)
    monkeypatch.setattr(launcher, "check_workspace_custody", lambda *a, **k: None)
    monkeypatch.setattr(launcher, "check_no_work_mount_aliases", lambda: None)
    monkeypatch.setattr(launcher, "verify_tools", lambda inputs, raw=None: calls.append(raw))
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(Path, "stat", lambda self: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | stat.S_ISUID | 0o755))
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0))
    monkeypatch.setattr(Path, "iterdir", lambda self: [Path(root) for root in policy["warmRoots"]])
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setenv("HARNESS_WARM_SOURCE_ROOTS", "\n".join(policy["warmRoots"]))
    monkeypatch.setenv("GITHUB_WORKSPACE", policy["workspace"])
    monkeypatch.setenv("GITHUB_SHA", policy["inputs"]["source"]["commit"])
    monkeypatch.setenv("GITHUB_REPOSITORY", policy["inputs"]["source"]["repository"])


def test_host_route_reads_the_record_only_for_v4(policy, v4_policy, v4_inputs, monkeypatch):
    record = canonical(v4_inputs[1])
    for value, raw in ((policy, None), (v4_policy, record)):
        reads, calls = [], []
        authority_host(value, monkeypatch, raw, reads, calls)
        launcher.load_authority(bootstrap_preflight=True)
        assert calls == [raw]
        assert ((ROOT_ALIASES, {"maximum": 64 * 1024}) in reads) is (raw is not None)


def test_host_route_root_read_custody_failure_refuses(v4_policy, monkeypatch):
    calls = []
    authority_host(v4_policy, monkeypatch, Refused("trust custody/type/link mismatch"), [], calls)
    with pytest.raises(Refused, match="trust custody"):
        launcher.load_authority(bootstrap_preflight=True)
    assert calls == []


def session(policy, monkeypatch, later, opened):
    from common import PACKET, POLICY
    policy = copy.deepcopy(policy)
    policy["packetSha256"] = digest(b"synthetic packet")
    files = {POLICY: canonical(policy), PACKET: b"synthetic packet"}
    if later is not None:
        files[ROOT_ALIASES] = later
    monkeypatch.setattr(launcher.sys, "argv", [LAUNCHER, "--operator-preflight"])
    monkeypatch.setattr(launcher.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(launcher, "load_authority", lambda **k: (policy, digest(files[POLICY]), digest(b"candidate")))
    monkeypatch.setattr(launcher, "os", Host(readlink=lambda path: "ns:[1]", close=lambda fd: None,
                                             open=lambda path, flags: opened.append(path) or 90 + len(opened)))
    monkeypatch.setattr(launcher, "supervise", lambda argv, **k: 0)
    monkeypatch.setattr(launcher, "root_read", lambda path, **k: files[path])


def test_closing_recheck_binds_the_record(policy, v4_policy, v4_inputs, monkeypatch, capsys):
    record = canonical(v4_inputs[1])
    for value, later, code in ((policy, None, 0), (v4_policy, record, 0), (v4_policy, record + b" ", 2)):
        opened = []
        session(value, monkeypatch, later, opened)
        assert launcher.main() == code
        assert opened == list(launcher.authority_files(value, True).values())
    assert '"reason":"Refused"' in capsys.readouterr().out


def test_v4_evidence_counts_the_record(policy, v4_policy, manifest, monkeypatch):
    from common import PROOFS
    import preflight
    monkeypatch.setattr(launcher, "verify_signed", lambda *a, **k: None)
    monkeypatch.setattr(launcher.platform, "release", lambda: "synthetic-kernel")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.time, "time", lambda: 150)
    payload = canonical(v4_policy)
    manifest["launcher"]["sha256"] = digest(b"candidate")
    manifest["signature"]["publicKeySha256"] = digest(b"public-key-fixture")
    v3_count = len(policy["warmRoots"]) + len(launcher.hidden_paths(policy))
    for count, accepted in ((v3_count + 1, True), (v3_count, False)):
        evidence = {"status": "PASS", "scope": "HOST_ISOLATION_ONLY",
                    "networkCases": {name: True for name in preflight.NETWORK_CASES}, "hiddenPathCount": count,
                    "descendantsChecked": True, **{name: True for name in PROOFS}, "policySha256": digest(payload),
                    "launcherSha256": digest(b"candidate"), "kernel": "synthetic-kernel", "architecture": "x86_64",
                    "observedAt": 140, "nativeLinuxAcceptance": False}
        manifest["preflight"]["evidenceSha256"] = digest(canonical(evidence))

        def check():
            launcher.verify_host_manifest(canonical(manifest), b"synthetic-signature", canonical(evidence),
                                          public=b"synthetic-public", key=b"public-key-fixture",
                                          launcher_bytes=b"candidate", policy_raw=payload, policy=v4_policy)
        if accepted:
            check()
        else:
            with pytest.raises(Refused, match="preflight case closure"):
                check()
