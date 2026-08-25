#!/usr/bin/env python3
"""One entry point for every deployed service. CASEHARDEN_AGENT picks which.

Eight services run from this image and differ only by environment: four
detectors, the workload agent, the Foreman, the Proposer and the Policy Server.
Building eight images that all had to be kept in step would be eight chances for
one of them to drift, and a fleet that is only nominally one program is a fleet
where the "one template, four deployments" claim is not true.

The Analyst Copilot is the exception and is not built here: it is deployed by
`adk deploy cloud_run --with_ui`, which builds its own image, because the plan
pins the analyst surface to ADK's own unmodified chat window.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

AGENT = os.environ.get("CASEHARDEN_AGENT", "detector")
PORT = int(os.environ.get("PORT", "8080"))


def main() -> int:
    if AGENT == "policy":
        from caseharden.policy_server import main as policy_main

        return policy_main(["--port", str(PORT)])

    directory = os.path.join(HERE, AGENT)
    if not os.path.isdir(directory):
        raise SystemExit(f"no such agent: {AGENT!r}")
    sys.path.insert(0, directory)

    import uvicorn

    # Before the agent is imported, so ADK's own spans are recorded by this
    # provider rather than by the no-op one. Done here rather than in each
    # agent's main.py: every service in this fleet starts through this file, and
    # a per-agent copy is a per-agent chance for one of them to lose its DAG.
    from agents.common import tracing

    tracing.start(os.environ.get("K_SERVICE") or f"caseharden-{AGENT}")

    from main import app  # noqa: E402  (agents/<name>/main.py)

    # Continue the caller's trace across the A2A hop, so an investigation is one
    # trace with the detectors' spans under it rather than five unrelated ones.
    uvicorn.run(tracing.Middleware(app), host="0.0.0.0", port=PORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
