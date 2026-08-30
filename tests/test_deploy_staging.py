#!/usr/bin/env python3
"""What the Copilot's deploy stages, against what its source actually imports.

Why this exists. `agents/copilot/agent.py` gained `from caseharden import
verdicts` when the disposition taxonomy arrived, and
`infra/33_deploy_copilot.sh` still copied `__init__`, `bq` and `creds` into the
staged tree. ADK imports `agent.py` at start-up, so the deployed container would
have exited with ModuleNotFoundError before it listened, leaving the previous
service running and still accepting any disposition string. The change looked
complete in the repo and would have failed only on a deploy nobody had run yet.

The list is derived here rather than restated. A test that hard-codes the four
module names is a second copy of the thing that drifted, and would have passed
just as happily on the day the import was added.

Transitive, because a staged module that imports an unstaged one fails exactly
the same way one frame further in.

run:  python3 -m pytest tests/test_deploy_staging.py -q
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

AGENT = REPO / "agents" / "copilot" / "agent.py"
DEPLOY = REPO / "infra" / "33_deploy_copilot.sh"
PACKAGE = REPO / "caseharden"


def caseharden_imports(path: Path) -> set:
    """The `caseharden` modules this file imports, by name.

    Both spellings: `from caseharden import x` and `import caseharden.x`. The
    repo uses the first, and a test that only understood the first would go
    quiet the day somebody wrote the second.
    """
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            if node.module == "caseharden" and node.level == 0:
                found.update(a.name for a in node.names)
            elif (node.module or "").startswith("caseharden."):
                found.add(node.module.split(".", 1)[1].split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("caseharden."):
                    found.add(alias.name.split(".", 1)[1].split(".")[0])
    # Only names that are modules in the package. `from caseharden import bq`
    # and `from caseharden import PROJECT` parse identically here.
    return {name for name in found if (PACKAGE / f"{name}.py").exists()}


def needed() -> set:
    """Every caseharden module the staged agent reaches, transitively."""
    seen, queue = set(), list(caseharden_imports(AGENT))
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        queue.extend(caseharden_imports(PACKAGE / f"{name}.py") - seen)
    return seen


def staged() -> set:
    match = re.search(r"for module in ([^;]+); do", DEPLOY.read_text())
    assert match, "the staging loop in 33_deploy_copilot.sh has changed shape"
    return set(match.group(1).split())


def test_every_module_the_copilot_imports_is_staged():
    missing = needed() - staged()
    assert not missing, (
        f"33_deploy_copilot.sh does not stage {sorted(missing)}, which "
        f"agents/copilot/agent.py imports. The container exits with "
        f"ModuleNotFoundError before it listens, and the previous service keeps "
        f"serving.")


def test_the_package_initialiser_is_staged():
    """`caseharden/` is a package, and an import of it needs its __init__."""
    assert "__init__" in staged()


def test_the_taxonomy_is_among_them():
    """The module whose absence this test was written for."""
    assert "verdicts" in needed(), (
        "agent.py no longer imports the taxonomy; if the disposition is free "
        "text again, the check the loop branches on has gone")
    assert "verdicts" in staged()
