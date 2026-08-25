#!/usr/bin/env python3
"""Serve one detector over A2A, so the Foreman can bind it without knowing it."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from google.adk.a2a.utils.agent_to_a2a import to_a2a

from agent import root_agent

PORT = int(os.environ.get("PORT", "8080"))
# Cloud Run terminates TLS in front of the container, so the card must advertise
# https and the public hostname. Getting this wrong produces an agent that works
# in a browser and is unreachable over A2A.
PUBLIC = os.environ.get("CASEHARDEN_PUBLIC_URL", "")

app = to_a2a(
    root_agent,
    host=PUBLIC.replace("https://", "").replace("http://", "") or "localhost",
    port=443 if PUBLIC.startswith("https://") else PORT,
    protocol="https" if PUBLIC.startswith("https://") else "http",
)
