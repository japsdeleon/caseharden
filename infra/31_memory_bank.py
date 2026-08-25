#!/usr/bin/env python3
"""Create or find the Agent Engine that backs Memory Bank, and print its id.

Memory Bank is a feature of an Agent Engine instance, so one has to exist even
though no agent code is deployed to it here. The Foreman writes each completed
investigation back as precedent and reads it with load_memory on the next one.

Nothing is seeded. What the fleet remembers is what the fleet has actually
reviewed, so an empty answer on the first run is the correct answer.

usage:
  python3 infra/31_memory_bank.py                 # create if absent, print the id
  export CASEHARDEN_MEMORY_ENGINE=$(python3 infra/31_memory_bank.py --id-only)
"""

from __future__ import annotations

import argparse
import os
import sys
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
warnings.filterwarnings("ignore")

from caseharden import creds

DISPLAY_NAME = os.environ.get("CASEHARDEN_MEMORY_NAME", "caseharden-memory")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--id-only", action="store_true")
    args = parser.parse_args(argv)

    import vertexai

    credentials, project = creds.credentials()
    client = vertexai.Client(project=project, location=creds.REGION,
                             credentials=credentials)

    for engine in client.agent_engines.list():
        resource = engine.api_resource
        if getattr(resource, "display_name", None) == DISPLAY_NAME:
            engine_id = resource.name.rsplit("/", 1)[-1]
            print(engine_id if args.id_only else f"exists  {resource.name}")
            if not args.id_only:
                print(f"        CASEHARDEN_MEMORY_ENGINE={engine_id}")
            return 0

    engine = client.agent_engines.create(config={
        "display_name": DISPLAY_NAME,
        "description": ("Memory Bank for the Caseharden fleet: the review "
                        "history of past conduct findings."),
    })
    engine_id = engine.api_resource.name.rsplit("/", 1)[-1]
    print(engine_id if args.id_only else f"created {engine.api_resource.name}")
    if not args.id_only:
        print(f"        CASEHARDEN_MEMORY_ENGINE={engine_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
