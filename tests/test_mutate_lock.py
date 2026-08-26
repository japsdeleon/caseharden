"""The mutation harness must refuse to run beside another copy of itself.

`tests/mutate_check.py` rewrites sources in place and restores each one from a
snapshot. Two overlapping runs mean the second snapshots a file the first has
already mutated, treats that mutation as the original, and restores it as the
source: both exit 0 and the tree keeps the mutation. On 2026-08-26 that left
four live mutations in `bq.py` and `notary.py`, and a review that reported no
issues had measured them.

Every test here asserts a refusal, and asserts it quickly. If the guard stops
working, the harness starts for real: 59 mutations, each running this suite,
from inside this suite. Hence the timeouts, which are the point rather than
politeness.
"""
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
HARNESS = REPO / "tests" / "mutate_check.py"
LOCK = REPO / ".mutate_check.lock"

# Long enough for the interpreter to start and read one file, far too short for
# a single mutation case, which runs the whole suite.
REFUSAL_SECONDS = 60


@pytest.fixture
def no_lock():
    """Never clobber a real run's lock: skip rather than delete it."""
    if LOCK.exists():
        pytest.skip(f"{LOCK.name} is held; a mutation run is in progress")
    yield
    LOCK.unlink(missing_ok=True)


def run_harness():
    return subprocess.run([sys.executable, str(HARNESS)], cwd=str(REPO),
                          capture_output=True, text=True, timeout=REFUSAL_SECONDS)


def test_a_live_lock_refuses_the_run(no_lock):
    LOCK.write_text(str(os.getpid()))
    done = run_harness()
    assert done.returncode == 2, done.stdout[-400:]
    assert "REFUSED" in done.stdout
    assert "in progress" in done.stdout


def test_a_stale_lock_refuses_and_says_to_check_the_tree(no_lock):
    """A killed run may have left a mutation, so the next one does not just take over.

    Taking the lock over would start mutating from a tree that already holds a
    mutation, which is the corruption this guard exists to stop, one process
    later.
    """
    LOCK.write_text("999999")  # a pid nothing is using
    done = run_harness()
    assert done.returncode == 2, done.stdout[-400:]
    assert "REFUSED" in done.stdout
    assert "status --short" in done.stdout
    assert LOCK.exists(), "a stale lock is left for a human to clear"


def test_an_unreadable_lock_still_refuses(no_lock):
    """An empty or garbled lock file is not permission to start."""
    LOCK.write_text("")
    done = run_harness()
    assert done.returncode == 2, done.stdout[-400:]
    assert "REFUSED" in done.stdout


def test_the_lock_is_ignored_by_git():
    ignored = subprocess.run(["git", "check-ignore", "-q", str(LOCK)], cwd=str(REPO))
    assert ignored.returncode == 0, ".mutate_check.lock must not be committable"
