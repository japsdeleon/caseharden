#!/usr/bin/env python3
"""Model Armor screening, and the one honest translation it needs.

Model Armor answers with a confidence band, `LOW_AND_ABOVE`, `MEDIUM_AND_ABOVE`
or `HIGH`, not a number. The policy DSL's injection field is numeric, because a
band cannot be compared with `at_least` and a policy that cannot express a
threshold cannot be tightened by one. So the band is mapped to a score here, in
one visible table, rather than somewhere a reviewer has to go looking for it.

The mapping is a judgement and is stated as one: HIGH is the only band that
crosses the 0.75 threshold the shipped policies use. A MEDIUM injection is
recorded at 0.70 and does not, on its own, block.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable, Dict, Optional

API = ("https://modelarmor.{region}.rep.googleapis.com/v1/projects/{project}"
       "/locations/{region}/templates/{template}:sanitizeUserPrompt")

TEMPLATE = os.environ.get("CASEHARDEN_ARMOR_TEMPLATE", "caseharden-conduct")

# Band to score. The comment above is the argument for these four numbers.
BAND_SCORE: Dict[str, float] = {
    "CONFIDENCE_LEVEL_UNSPECIFIED": 0.0,
    "LOW_AND_ABOVE": 0.40,
    "MEDIUM_AND_ABOVE": 0.70,
    "HIGH": 0.95,
}


def _band(result: dict, key: str) -> Optional[str]:
    entry = (result.get("filterResults") or {}).get(key) or {}
    for value in entry.values():
        if isinstance(value, dict) and value.get("matchState") == "MATCH_FOUND":
            return value.get("confidenceLevel", "CONFIDENCE_LEVEL_UNSPECIFIED")
        if isinstance(value, dict) and value.get("matchState") == "NO_MATCH_FOUND":
            return None
    return None


def to_fields(sanitization: dict) -> dict:
    """The three DSL fields, from one sanitizeUserPrompt response."""
    result = sanitization.get("sanitizationResult") or {}
    band = _band(result, "pi_and_jailbreak")
    score = BAND_SCORE.get(band, 0.0) if band else 0.0
    matched = result.get("filterMatchState") == "MATCH_FOUND"
    return {
        "ma_prompt_injection_score": score,
        # Model Armor reports prompt injection and jailbreak under one filter and
        # one band. Reporting them as two independent scores would invent a
        # measurement, so both carry the band this screening actually produced.
        "ma_jailbreak_score": score,
        "ma_verdict": "BLOCK" if matched else "ALLOW",
        "ma_band": band or "NO_MATCH_FOUND",
    }


def screener(project: str, region: str,
             token_fn: Callable[[], str],
             template: str = TEMPLATE,
             timeout: float = 8.0) -> Callable[[str], dict]:
    """A callable that screens one string. Wired into Enforcer as `armor`."""

    url = API.format(project=project, region=region, template=template)

    def screen(text: str) -> dict:
        body = json.dumps({"userPromptData": {"text": text}}).encode()
        request = urllib.request.Request(
            url, data=body,
            headers={"Authorization": "Bearer " + token_fn(),
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return to_fields(json.load(response))

    return screen
