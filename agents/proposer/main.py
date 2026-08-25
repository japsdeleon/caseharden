#!/usr/bin/env python3
"""Serve the Proposer over A2A, so the loop drives it the way it drives the fleet."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from google.adk.a2a.utils.agent_to_a2a import to_a2a

from agent import root_agent

PORT = int(os.environ.get("PORT", "8080"))
PUBLIC = os.environ.get("CASEHARDEN_PUBLIC_URL", "")

app = to_a2a(
    root_agent,
    host=PUBLIC.replace("https://", "").replace("http://", "") or "localhost",
    port=443 if PUBLIC.startswith("https://") else PORT,
    protocol="https" if PUBLIC.startswith("https://") else "http",
)
