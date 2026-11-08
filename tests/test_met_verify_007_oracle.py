"""D5a oracle tests for MET-VERIFY-007 (slot 283, issue #235): the raw-byte packet reader.

Owner decision D5a: a contract packet carries black-box tests written outside the
candidate by someone who is not its builder. These tests were written from two
sources only, and every expected value below comes from one of them:

* CONTRACT_283 section 2, "The runner fix" (the whole contract's sha256 starts
  f09a21cd; candidate c2 57519c70): one reader ``read_packet_bytes(path) ->
  (raw, text, digest)`` for the first read and every re-read; ``raw`` the bytes
  read once, ``text`` their strict UTF-8 decoding, ``digest`` the sha256 of
  exactly ``raw``; ``read_packet_text(path) -> (text, digest)`` a thin wrapper
  over it; the read step (check 0: ``packet cannot be opened`` for an open
  failure such as a missing path or a symlink refused by O_NOFOLLOW, then
  ``HARNESS_TASK_PACKET must name a regular file``) and checks 1-4 in that order,
  the first failure raising ``PacketTransportError`` with exactly the text shown;
  the five co-occurring pairs; the re-read (the same checks in the same order,
  then the digest comparison ``packet authority changed during execution``); the
  refusal behaviour (exit 2, ``packet transport refused: <text>`` on stderr, the
  non-UTF-8 case exit 2 and not a traceback).
* Facts the operator stated in the oracle brief (sha256 starts dcf6cb69), not all
  of them in the contract: the repository root
  ``Path(__file__).resolve().parents[1]`` and the module path under it; the
  public names ``PacketTransportError``, ``read_packet_bytes``,
  ``read_packet_text``, ``verify_packet_digest`` (re-reads with the same reader,
  returns None, raises the changed-authority text when the digest differs) and
  ``PACKET_ENVIRONMENT`` (``"HARNESS_TASK_PACKET"``); the exception message being
  exactly the contract's text; ``path`` a ``pathlib.Path`` and ``digest`` the
  lowercase hex sha256; the process shape (``sys.executable -I <runner>``, no
  arguments, the packet named in ``HARNESS_TASK_PACKET`` plus ``PATH``; a
  first-read refusal prints exactly one stderr line, nothing on stdout, exit 2;
  a missing variable is refused with ``HARNESS_TASK_PACKET is required``).

The runner is loaded by file path and never patched; every case is built as
files under pytest's ``tmp_path``. A child process gets an explicit, minimal
environment built here.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Operator-stated: the repository root and the module path under it.
ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "ci" / "run_packet_argv.py"
MODULE_NAME = "met_verify_007_oracle_runner"

# Contract section 2: the exact refusal texts (read step, checks 1-4, re-read).
TEXT_CANNOT_OPEN = "packet cannot be opened"
TEXT_NOT_REGULAR = "HARNESS_TASK_PACKET must name a regular file"
TEXT_BOM = "packet starts with a UTF-8 byte order mark"
TEXT_NOT_UTF8 = "packet is not strict UTF-8"
TEXT_CRLF = "packet has CRLF line endings"
TEXT_BARE_CR = "packet has a bare carriage return"
TEXT_CHANGED = "packet authority changed during execution"
REFUSAL_PREFIX = "packet transport refused: "
REFUSAL_EXIT = 2

# Operator-stated: the variable, its missing-variable refusal and the child PATH.
PACKET_VARIABLE = "HARNESS_TASK_PACKET"
TEXT_REQUIRED = "HARNESS_TASK_PACKET is required"
CHILD_PATH = "/usr/bin:/bin"
CHILD_TIMEOUT = 60

READERS = ("read_packet_bytes", "read_packet_text")

BOM = b"\xef\xbb\xbf"
# An LF-only, strict UTF-8 packet with no BOM and one non-ASCII character.
LF_PACKET = b"oracle: v-lf\nnote: caf\xc3\xa9\nsteps:\n  - first\n  - second\n"
# The same packet with exactly one byte changed ("f" -> "g"), still LF strict UTF-8.
CHANGED_PACKET = LF_PACKET.replace(b"oracle: v-lf", b"oracle: v-lg", 1)
CRLF_PACKET = LF_PACKET.replace(b"\n", b"\r\n")

# Checks 1-4, one defect each: (vector id, packet bytes, expected text).
SINGLE_DEFECTS = (
    ("V-BOM", BOM + LF_PACKET, TEXT_BOM),
    ("V-UTF8-ff", LF_PACKET + b"bad: \xff\n", TEXT_NOT_UTF8),
    ("V-UTF8-truncated", LF_PACKET + b"bad: \xe2\x82", TEXT_NOT_UTF8),
    ("V-UTF8-overlong", LF_PACKET + b"bad: \xc0\xaf\n", TEXT_NOT_UTF8),
    ("V-UTF8-surrogate", LF_PACKET + b"bad: \xed\xa0\x80\n", TEXT_NOT_UTF8),
    ("V-CRLF", b"oracle: v-crlf\r\nnote: every line\r\n", TEXT_CRLF),
    ("V-CRLF-one-pair", LF_PACKET + b"pair: here\r\ntail: lf\n", TEXT_CRLF),
    ("V-CR", b"oracle: v-cr\rnote: bare\n", TEXT_BARE_CR),
    ("V-CR-last-byte", LF_PACKET + b"\r", TEXT_BARE_CR),
)

# The contract's five co-occurring pairs (both placements where placement can
# vary) and all four defects at once: the earlier check's text wins.
CO_OCCURRING = (
    ("V-BOM+UTF8", BOM + b"bad: \xff\n", TEXT_BOM),
    ("V-UTF8+CRLF", b"bad: \xff\r\nnext: line\n", TEXT_NOT_UTF8),
    ("V-UTF8+CRLF-pair-first", b"first: line\r\nbad: \xff\n", TEXT_NOT_UTF8),
    ("V-CRLF+CR", b"first: line\r\nbare: \rnext\n", TEXT_CRLF),
    ("V-CRLF+CR-bare-first", b"bare: \rnext\nlast: line\r\n", TEXT_CRLF),
    ("V-BOM+CRLF", BOM + b"first: line\r\nnext: line\r\n", TEXT_BOM),
    ("V-UTF8+CR", b"bad: \xff\rnext\n", TEXT_NOT_UTF8),
    ("V-UTF8+CR-bare-first", b"bare: \rnext\nbad: \xff\n", TEXT_NOT_UTF8),
    ("V-ALL-FOUR", BOM + b"bad: \xff\nbare: \rnext\nlast: line\r\n", TEXT_BOM),
)

# A re-read after a rewrite: the checks run before the digest comparison.
REREAD_DEFECTS = (
    ("V-REREAD-BOM", BOM + LF_PACKET, TEXT_BOM),
    ("V-REREAD-UTF8", LF_PACKET + b"bad: \xff\n", TEXT_NOT_UTF8),
    ("V-REREAD-CR", LF_PACKET.replace(b"\n", b"\r", 1), TEXT_BARE_CR),
    ("V-REREAD-BOM+CRLF", BOM + CRLF_PACKET, TEXT_BOM),
)


def _params(vectors):
    return [pytest.param(raw, text, id=name) for name, raw, text in vectors]


@pytest.fixture(scope="module")
def runner():
    """Load the runner by file path (operator-stated module location), unpatched."""
    spec = importlib.util.spec_from_file_location(MODULE_NAME, RUNNER_PATH)
    assert spec is not None and spec.loader is not None, str(RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    # The documented importlib recipe for a source file: a new, unique name.
    sys.modules[MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(MODULE_NAME, None)


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def _expect_refusal(runner, call, text):
    with pytest.raises(runner.PacketTransportError) as caught:
        call()
    assert str(caught.value) == text


def _build_case(tmp_path: Path, kind: str, raw) -> Path:
    if kind == "missing":
        return tmp_path / "absent-packet.yaml"
    if kind == "symlink":
        target = _write(tmp_path / "target-packet.yaml", LF_PACKET)
        link = tmp_path / "link-packet.yaml"
        link.symlink_to(target)
        return link
    if kind == "directory":
        directory = tmp_path / "packet-directory"
        directory.mkdir()
        return directory
    assert kind == "file", kind
    return _write(tmp_path / "packet.yaml", raw)


def _run_process(tmp_path: Path, packet):
    """Run the runner as the operator states, with an explicit minimal environment."""
    workdir = tmp_path / "child-cwd"
    workdir.mkdir()
    env = {"PATH": CHILD_PATH}
    if packet is not None:
        env[PACKET_VARIABLE] = str(packet)
    return subprocess.run(
        [sys.executable, "-I", str(RUNNER_PATH)],
        env=env,
        cwd=str(workdir),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )


def _assert_process_refused(result, text):
    assert result.returncode == REFUSAL_EXIT, (result.returncode, result.stderr)
    assert result.stdout == b"", result.stdout
    stderr = result.stderr.decode("utf-8")
    line = REFUSAL_PREFIX + text
    assert stderr in (line, line + "\n"), stderr


# --- operator-stated name --------------------------------------------------


def test_packet_environment_name(runner):
    """Operator-stated: PACKET_ENVIRONMENT is the string "HARNESS_TASK_PACKET"."""
    assert runner.PACKET_ENVIRONMENT == PACKET_VARIABLE


# --- check 0: the read step ------------------------------------------------


@pytest.mark.parametrize("reader", READERS)
def test_read_step_missing_path(runner, tmp_path, reader):
    """Contract check 0: "An OSError at open (a missing path, ...) is caught:
    packet cannot be opened". read_packet_text is "a thin wrapper over it"."""
    packet = tmp_path / "absent-packet.yaml"
    _expect_refusal(runner, lambda: getattr(runner, reader)(packet), TEXT_CANNOT_OPEN)


@pytest.mark.parametrize("reader", READERS)
def test_read_step_symlink_to_valid_lf_packet(runner, tmp_path, reader):
    """Contract V-SYMLINK: "a symlink to a valid LF packet gives packet cannot be
    opened" (O_NOFOLLOW). The target itself is accepted by the same reader."""
    target = _write(tmp_path / "target-packet.yaml", LF_PACKET)
    getattr(runner, reader)(target)
    link = tmp_path / "link-packet.yaml"
    link.symlink_to(target)
    _expect_refusal(runner, lambda: getattr(runner, reader)(link), TEXT_CANNOT_OPEN)


@pytest.mark.parametrize("reader", READERS)
def test_read_step_directory(runner, tmp_path, reader):
    """Contract V-NONREGULAR: "a directory gives HARNESS_TASK_PACKET must name a
    regular file" (fstat: a non-regular file)."""
    directory = tmp_path / "packet-directory"
    directory.mkdir()
    _expect_refusal(runner, lambda: getattr(runner, reader)(directory), TEXT_NOT_REGULAR)


@pytest.mark.parametrize("reader", READERS)
def test_read_step_precedes_checks(runner, tmp_path, reader):
    """Contract: "The read step and the checks, in this order; the first that fails
    raises": a symlink to a packet with all four defects gives the read-step text."""
    target = _write(tmp_path / "target-packet.yaml", CO_OCCURRING[-1][1])
    link = tmp_path / "link-packet.yaml"
    link.symlink_to(target)
    _expect_refusal(runner, lambda: getattr(runner, reader)(link), TEXT_CANNOT_OPEN)


# --- checks 1-4 ------------------------------------------------------------


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize(("raw", "text"), _params(SINGLE_DEFECTS))
def test_checks_single_defect(runner, tmp_path, reader, raw, text):
    """Contract checks 1-4, each with "exactly the text shown": a leading UTF-8 BOM
    (EF BB BF); strict UTF-8 decode fails; a CR LF pair anywhere; any other CR byte."""
    packet = _write(tmp_path / "packet.yaml", raw)
    _expect_refusal(runner, lambda: getattr(runner, reader)(packet), text)


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize(("raw", "text"), _params(CO_OCCURRING))
def test_check_order_co_occurring(runner, tmp_path, reader, raw, text):
    """Contract co-occurring defects ("the order above wins"): V-BOM+UTF8 gives the
    BOM text; V-UTF8+CRLF the UTF-8 text; V-CRLF+CR the CRLF text; V-BOM+CRLF the
    BOM text; V-UTF8+CR the UTF-8 text; all four together the first (BOM) text."""
    packet = _write(tmp_path / "packet.yaml", raw)
    _expect_refusal(runner, lambda: getattr(runner, reader)(packet), text)


# --- V-LF ------------------------------------------------------------------


def test_v_lf_read_packet_bytes(runner, tmp_path):
    """Contract V-LF and the reader: "raw is the bytes read once, text their strict
    UTF-8 decoding, and digest the sha256 of exactly raw", which "equals today's
    digest for an LF file". Operator-stated: digest is the lowercase hex sha256."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    raw, text, digest = runner.read_packet_bytes(packet)
    assert isinstance(raw, bytes)
    assert raw == LF_PACKET
    assert isinstance(text, str)
    assert text == LF_PACKET.decode("utf-8")
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
    assert digest == hashlib.sha256(LF_PACKET).hexdigest()
    assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_v_lf_read_packet_text(runner, tmp_path):
    """Contract: "read_packet_text(path) -> (text, digest) stays as a thin wrapper
    over it": the same text and digest as read_packet_bytes for an LF packet."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    _raw, bytes_text, bytes_digest = runner.read_packet_bytes(packet)
    text, digest = runner.read_packet_text(packet)
    assert text == bytes_text == LF_PACKET.decode("utf-8")
    assert digest == bytes_digest == hashlib.sha256(LF_PACKET).hexdigest()


# --- the re-read -----------------------------------------------------------


def test_reread_same_bytes_accepted(runner, tmp_path):
    """Contract V-REREAD-SAME: "identical bytes, accepted". Operator-stated:
    verify_packet_digest re-reads with the same reader and returns None."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    _raw, _text, digest = runner.read_packet_bytes(packet)
    packet.write_bytes(LF_PACKET)
    assert runner.verify_packet_digest(packet, digest) is None


def test_reread_one_byte_changed(runner, tmp_path):
    """Contract V-REREAD-CHANGED: "one byte changed, packet authority changed during
    execution" (the digest comparison after the four checks)."""
    assert len(CHANGED_PACKET) == len(LF_PACKET)
    assert sum(a != b for a, b in zip(CHANGED_PACKET, LF_PACKET)) == 1
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    _raw, _text, digest = runner.read_packet_bytes(packet)
    packet.write_bytes(CHANGED_PACKET)
    _expect_refusal(runner, lambda: runner.verify_packet_digest(packet, digest), TEXT_CHANGED)


def test_reread_crlf_rewrite(runner, tmp_path):
    """Contract V-REREAD-CRLF: "rewritten with CRLF, the CRLF text" (the checks run
    before the digest comparison)."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    _raw, _text, digest = runner.read_packet_bytes(packet)
    packet.write_bytes(CRLF_PACKET)
    _expect_refusal(runner, lambda: runner.verify_packet_digest(packet, digest), TEXT_CRLF)


@pytest.mark.parametrize(("raw", "text"), _params(REREAD_DEFECTS))
def test_reread_checks_before_digest(runner, tmp_path, raw, text):
    """Contract: "At a re-read, the same four checks run in the same order, then the
    digest comparison": a rewrite with a defect gives that check's text, and of two
    defects the earlier check's text."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET)
    _raw, _text, digest = runner.read_packet_bytes(packet)
    packet.write_bytes(raw)
    _expect_refusal(runner, lambda: runner.verify_packet_digest(packet, digest), text)


@pytest.mark.parametrize(
    ("kind", "text"),
    [
        pytest.param("missing", TEXT_CANNOT_OPEN, id="V-REREAD-MISSING"),
        pytest.param("symlink", TEXT_CANNOT_OPEN, id="V-REREAD-SYMLINK"),
        pytest.param("directory", TEXT_NOT_REGULAR, id="V-REREAD-NONREGULAR"),
    ],
)
def test_reread_read_step(runner, tmp_path, kind, text):
    """Contract: "one reader ... used for the first read and for every re-read";
    operator-stated: verify_packet_digest reads again with the same reader. The read
    step refuses even when the bytes behind a symlink carry the expected digest."""
    digest = hashlib.sha256(LF_PACKET).hexdigest()
    packet = _build_case(tmp_path, kind, None)
    _expect_refusal(runner, lambda: runner.verify_packet_digest(packet, digest), text)


# --- the process -----------------------------------------------------------

PROCESS_CASES = [
    pytest.param("missing", None, TEXT_CANNOT_OPEN, id="V-MISSING"),
    pytest.param("symlink", None, TEXT_CANNOT_OPEN, id="V-SYMLINK"),
    pytest.param("directory", None, TEXT_NOT_REGULAR, id="V-NONREGULAR"),
] + [
    pytest.param("file", raw, text, id=name)
    for name, raw, text in SINGLE_DEFECTS + CO_OCCURRING
]


@pytest.mark.parametrize(("kind", "raw", "text"), PROCESS_CASES)
def test_process_first_read_refusal(tmp_path, kind, raw, text):
    """Contract refusal behaviour: "Every refusal exits 2 with packet transport
    refused: <text> on stderr"; a first-read refusal comes before any command.
    Operator-stated: exactly one stderr line and nothing on stdout."""
    packet = _build_case(tmp_path, kind, raw)
    result = _run_process(tmp_path, packet)
    _assert_process_refused(result, text)


def test_process_missing_variable(tmp_path):
    """Operator-stated: a missing HARNESS_TASK_PACKET is refused the same way with
    HARNESS_TASK_PACKET is required (exit 2, one stderr line, empty stdout)."""
    result = _run_process(tmp_path, None)
    _assert_process_refused(result, TEXT_REQUIRED)


def test_process_non_utf8_exit_2_not_traceback(tmp_path):
    """Contract: "The non-UTF-8 case is now exit 2, not a traceback" (today it is an
    uncaught UnicodeDecodeError, exit 1)."""
    packet = _write(tmp_path / "packet.yaml", LF_PACKET + b"bad: \xff\n")
    result = _run_process(tmp_path, packet)
    assert result.returncode != 1
    assert b"Traceback" not in result.stderr
    assert b"UnicodeDecodeError" not in result.stderr
    _assert_process_refused(result, TEXT_NOT_UTF8)
