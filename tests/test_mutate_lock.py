"""The mutation harness must refuse to run beside another copy of itself.

`tests/mutate_check.py` rewrites sources in place and restores each one from a
snapshot. Two overlapping runs mean the second snapshots a file the first has
already mutated, treats that mutation as the original, and restores it as the
source: both exit 0 and the tree keeps the mutation. On 2026-08-26 that left
four live mutations in `bq.py` and `notary.py`, and a review that reported no
issues had measured them.

These tests import that module and call `take_lock()` against a lock path in a
temporary directory. Two earlier designs were worse and an adversarial pass
killed both:

  Running the harness as a subprocess. A guard that stopped working would start
  a real 59-case mutation run from inside this suite, and the timeout meant to
  contain it would kill that run mid-case, leaving the file mutated.

  Skipping when the real lock file exists. Checking and then unlinking the real
  path is a race: a harness that takes the lock after the check has its lock
  overwritten and then deleted by the teardown, which is exactly the concurrency
  this is supposed to prevent. Nothing here touches the real lock at all now.
"""
import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def load_harness():
    """Import mutate_check without running it.

    Its case loop lives under `if __name__ == "__main__"`, so importing is safe.
    Loaded by path rather than by name because `tests/` is not a package.
    """
    spec = importlib.util.spec_from_file_location(
        "mutate_check", REPO / "tests" / "mutate_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def harness(tmp_path, monkeypatch):
    module = load_harness()
    monkeypatch.setattr(module, "LOCK", tmp_path / "mutate_check.lock")
    return module


def refusal(harness, capsys):
    with pytest.raises(SystemExit) as exit_code:
        harness.take_lock()
    assert exit_code.value.code == 2
    return capsys.readouterr().out


def test_a_free_lock_is_taken_and_holds_this_pid(harness):
    harness.take_lock()
    assert harness.LOCK.read_text() == str(os.getpid())


def test_a_second_acquisition_is_refused(harness, capsys):
    harness.take_lock()
    said = refusal(harness, capsys)
    assert "REFUSED" in said
    assert "in progress" in said
    assert str(os.getpid()) in said


def test_a_stale_lock_is_refused_and_left_for_a_human(harness, capsys):
    """A killed run may have left a mutation, so the next one does not take over.

    Taking it over would start mutating a tree that already holds a mutation,
    which is the same corruption one process later. Liveness of a pid says
    nothing about the state of the tree.
    """
    harness.LOCK.write_text("2147483647")  # above every pid_max in use
    said = refusal(harness, capsys)
    assert "REFUSED" in said
    assert "status --short" in said
    assert harness.LOCK.exists(), "a stale lock is left for a human to clear"


@pytest.mark.parametrize("contents", ["", "   ", "not-a-pid", "-1"])
def test_a_lock_that_names_no_pid_is_refused(harness, capsys, contents):
    """An empty or garbled lock file is not permission to start."""
    harness.LOCK.write_text(contents)
    assert "REFUSED" in refusal(harness, capsys)


def test_an_unreadable_lock_is_refused(harness, capsys):
    """A directory where the lock should be. O_EXCL fails, and so must the read."""
    harness.LOCK.mkdir()
    said = refusal(harness, capsys)
    assert "REFUSED" in said
    assert "cannot be read" in said


def test_the_lock_is_released_on_exit(harness, tmp_path):
    """atexit, registered inside take_lock, not a finally around the case loop.

    A signal landing between take_lock returning and that block being entered
    would have left the lock behind with nothing mutated, which costs a human a
    manual check for damage that never happened.
    """
    script = (
        "import importlib.util, pathlib, sys\n"
        f"spec = importlib.util.spec_from_file_location('m', {str(REPO / 'tests' / 'mutate_check.py')!r})\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        f"m.LOCK = pathlib.Path({str(tmp_path / 'exit.lock')!r})\n"
        "m.take_lock()\n"
        "assert m.LOCK.exists()\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr[-400:]
    assert not (tmp_path / "exit.lock").exists()


def test_write_atomically_leaves_no_half_written_file(harness, tmp_path):
    """The source is replaced, never truncated in place.

    `write_text` truncates first, so a signal or a full disk in between leaves an
    empty source and the cleanup then drops the lock that would have said so.
    """
    target = tmp_path / "source.py"
    target.write_text("original\n")
    harness.write_atomically(target, "mutated\n")
    assert target.read_text() == "mutated\n"
    assert list(tmp_path.glob("*.mutating")) == []


def test_the_real_lock_is_ignored_by_git():
    lock = REPO / ".mutate_check.lock"
    ignored = subprocess.run(["git", "check-ignore", "-q", str(lock)], cwd=str(REPO))
    assert ignored.returncode == 0, ".mutate_check.lock must not be committable"


def test_the_case_loop_does_not_run_on_import():
    """If it did, importing this module would start a 59-case mutation run."""
    source = (REPO / "tests" / "mutate_check.py").read_text()
    assert 'if __name__ == "__main__":' in source
    assert "\nsys.exit(main())" not in source, "main() must stay under the guard"
