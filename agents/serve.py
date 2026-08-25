#!/usr/bin/env python3
"""One entry point for every deployed service. CASEHARDEN_AGENT picks which.

Six services run from this image and differ only by environment. Building six
images that all had to be kept in step would be six chances for one of them to
drift, and a fleet that is only nominally one program is a fleet where the
"one template, four deployments" claim is not true.
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

    from main import app  # noqa: E402  (agents/<name>/main.py)

    uvicorn.run(app, host="0.0.0.0", port=PORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
