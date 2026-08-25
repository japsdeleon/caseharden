#!/usr/bin/env python3
"""Serve the Foreman over A2A, with Memory Bank attached.

`to_a2a` builds a Runner with default services when it is not given one, and the
default has no memory. The Foreman's `load_memory` tool would then fail at the
first call, which is a worse outcome than not offering the tool at all: the
report would be missing its precedent line and nothing would say why.

So the Runner is built here, with Vertex AI Memory Bank, and the Foreman writes
its own session back after each investigation. The precedent it surfaces is
therefore the fleet's own review history, accumulated by running, rather than
anything seeded by hand.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

from agent import root_agent

PORT = int(os.environ.get("PORT", "8080"))
PUBLIC = os.environ.get("CASEHARDEN_PUBLIC_URL", "")
ENGINE = os.environ.get("CASEHARDEN_MEMORY_ENGINE", "")
APP_NAME = "caseharden-foreman"


def memory_service():
    """Vertex AI Memory Bank, or None when no engine is configured.

    None rather than a silent in-memory substitute. An in-process memory service
    on a scale-to-zero Cloud Run instance forgets everything on every cold start,
    which looks exactly like a fleet that has never seen this pattern before.
    """
    if not ENGINE:
        return None
    from google.adk.memory.vertex_ai_memory_bank_service import VertexAiMemoryBankService

    from caseharden import creds

    credentials, project = creds.credentials()
    return VertexAiMemoryBankService(
        project=project,
        location=os.environ.get("CASEHARDEN_REGION", "europe-west3"),
        agent_engine_id=ENGINE,
        credentials=credentials,
    )


runner = Runner(
    app_name=APP_NAME,
    agent=root_agent,
    session_service=InMemorySessionService(),
    memory_service=memory_service(),
    auto_create_session=True,
)

app = to_a2a(
    root_agent,
    runner=runner,
    host=PUBLIC.replace("https://", "").replace("http://", "") or "localhost",
    port=443 if PUBLIC.startswith("https://") else PORT,
    protocol="https" if PUBLIC.startswith("https://") else "http",
)
