#!/usr/bin/env python3
"""The README quotes numbers a reader can reproduce in one command. Hold it to them.

Every re-attestation appends a link, which moves the chain root and adds four
per-link checks to the offline re-check. So the root and the check count in the
README go stale on their own, without anyone editing the file. They already have,
twice. A judge who runs `recheck` and reads a different root than the README
claims has found the record disagreeing with the claim, which is the one thing
this entry cannot afford to look like.

These assertions fail on the next export instead.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(ROOT))

from caseharden.recheck import run_checks  # noqa: E402

FIXTURE = ROOT / "fixtures" / "v5"
README = (ROOT / "README.md").read_text()
CERTIFICATE = json.loads((FIXTURE / "certificate.json").read_text())


def test_the_measured_row_names_the_exported_root():
    row = re.search(r"^\| Active version \|(.+)$", README, re.M)
    assert row, "the Measured table lost its Active version row"
    text = row.group(1)

    links = re.search(r"(\d+) chain links", text)
    assert links, f"no link count in: {text.strip()}"
    assert int(links.group(1)) == len(CERTIFICATE["links"]), (
        f"README says {links.group(1)} chain links, the exported certificate "
        f"carries {len(CERTIFICATE['links'])}"
    )

    root = re.search(r"root `([0-9a-f]+)`", text)
    assert root, f"no root in: {text.strip()}"
    assert CERTIFICATE["root"].startswith(root.group(1)), (
        f"README says root {root.group(1)}, the certificate's root is "
        f"{CERTIFICATE['root'][:12]}. A link hash is not the root: the root is "
        f"the last link's."
    )


def test_the_readme_states_the_check_count_the_recheck_prints():
    # quiet, because this asks the checker how many checks it has, not to narrate.
    actual = len(run_checks(FIXTURE, quiet=True).checks)

    spelled = {"Seventeen": 17, "Forty-five": 45, "Forty-four": 44, "Forty-six": 46}
    prose = re.search(r"\b(" + "|".join(spelled) + r") checks, no credentials", README)
    assert prose, "the re-check section stopped stating its check count in words"
    assert spelled[prose.group(1)] == actual, (
        f"README spells out {prose.group(1)} checks, recheck runs {actual}"
    )

    inline = re.search(r"offline, (\d+) checks", README)
    assert inline, "the Reproduce it block stopped stating the check count"
    assert int(inline.group(1)) == actual, (
        f"the Reproduce it block says {inline.group(1)} checks, recheck runs {actual}"
    )


def test_the_readme_states_the_number_of_tests_there_are():
    # Collected, not run: this test is inside the suite it is counting.
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "--collect-only",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    collected = re.search(r"(\d+) tests? collected", out)
    assert collected, f"could not read a collection count from:\n{out[-500:]}"

    for claimed in re.findall(r"\| Tests \| (\d+) \|", README) + \
                   re.findall(r"pytest tests -q\s+# (\d+) tests", README):
        assert int(claimed) == int(collected.group(1)), (
            f"README says {claimed} tests, the suite collects {collected.group(1)}"
        )


def test_every_command_the_readme_offers_a_judge_exists():
    # The install line is worth nothing if the module behind it moved.
    for module in re.findall(r"python3 -m (caseharden\.[a-z_]+)", README):
        path = ROOT / (module.replace(".", "/") + ".py")
        assert path.exists(), f"README offers `python3 -m {module}`, which is not a module"

    for script in re.findall(r"python3 ((?:infra|generator|tests|docs)/[0-9a-z_]+\.py)", README):
        assert (ROOT / script).exists(), f"README offers `python3 {script}`, which does not exist"

    for script in re.findall(r"bash (infra/[0-9a-z_]+\.sh)", README):
        assert (ROOT / script).exists(), f"README offers `bash {script}`, which does not exist"
