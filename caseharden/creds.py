#!/usr/bin/env python3
"""Credentials for anything in this repo that speaks to Google Cloud.

This exists because of a real incident. The machine that builds Caseharden also
holds an employer's Application Default Credentials. Any library that calls
``google.auth.default()`` picks those up silently: the call succeeds, the
identity is wrong, and the employer's project is named as the quota project on a
request that has nothing to do with it. Nothing fails, so nothing tells you.

So this module never uses ADC. It mints a token from one pinned gcloud
configuration and refuses to hand back credentials whose project is not this
project. A caller that wants a Google client asks here or does without.

On Cloud Run there is no gcloud and no employer credential; the attached service
account is the right identity and ADC is correct. ``credentials()`` detects that
case and uses it, after the same project check.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional, Tuple

PROJECT = os.environ.get("CASEHARDEN_PROJECT", "devpost-hackathon-506416")
REGION = os.environ.get("CASEHARDEN_REGION", "europe-west3")
GCLOUD_CONFIG = os.environ.get("CASEHARDEN_GCLOUD_CONFIG", "caseharden")

# Extra project ids to refuse by name, comma separated. The check below already
# refuses everything that is not PROJECT, so this is only useful for making a
# specific wrong answer produce a clearer message. It is read from the
# environment rather than written here: this repo is public and a hard-coded
# list of somebody else's project ids is exactly the kind of infrastructure
# detail a clean-room build has no business carrying.
FORBIDDEN_PROJECTS = tuple(
    p for p in os.environ.get("CASEHARDEN_FORBIDDEN_PROJECTS", "").split(",") if p
)


class WrongIdentity(RuntimeError):
    """The ambient credential is not the one this repo is allowed to use."""


def on_cloud_run() -> bool:
    """True inside a Cloud Run container, where the attached SA is correct."""
    return bool(os.environ.get("K_SERVICE"))


def gcloud_env() -> dict:
    return dict(os.environ, CLOUDSDK_ACTIVE_CONFIG_NAME=GCLOUD_CONFIG)


def _check(project: Optional[str], source: str) -> None:
    if project and project in FORBIDDEN_PROJECTS:
        raise WrongIdentity(
            f"{source} resolves to a project this repo is walled off from. "
            f"Refusing. Expected {PROJECT!r}."
        )
    if project and project != PROJECT:
        raise WrongIdentity(
            f"{source} resolves to project {project!r}, not {PROJECT!r}. "
            "Refusing rather than acting under an unintended identity."
        )


METADATA_TOKEN = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)


def _metadata_token() -> str:
    """The attached service account's token, read from the Cloud Run metadata server."""
    import json as _json
    import urllib.request as _u

    request = _u.Request(METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
    with _u.urlopen(request, timeout=5) as response:
        return _json.load(response)["access_token"]


METADATA_EMAIL = ("http://metadata.google.internal/computeMetadata/v1/"
                  "instance/service-accounts/default/email")


def attached_service_account() -> Optional[str]:
    """The service account this container runs as, or None off Cloud Run."""
    if not on_cloud_run():
        return None
    import urllib.request as _u

    request = _u.Request(METADATA_EMAIL, headers={"Metadata-Flavor": "Google"})
    with _u.urlopen(request, timeout=5) as response:
        return response.read().decode().strip()


def access_token() -> str:
    """A token for this project's identity. Never printed, never logged.

    In a container that is the attached service account. On a workstation it is
    the pinned gcloud configuration, never Application Default Credentials, for
    the reason in this module's docstring.
    """
    if on_cloud_run():
        return _metadata_token()
    _check(active_project(), f"gcloud configuration {GCLOUD_CONFIG!r}")
    out = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True, env=gcloud_env(),
    )
    if out.returncode != 0:
        raise WrongIdentity(
            f"gcloud could not mint a token for configuration {GCLOUD_CONFIG!r}: "
            f"{out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'no output'}"
        )
    return out.stdout.strip()


def active_account() -> str:
    out = subprocess.run(
        ["gcloud", "config", "get-value", "account"],
        capture_output=True, text=True, env=gcloud_env(),
    )
    return out.stdout.strip()


def active_project() -> str:
    out = subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True, text=True, env=gcloud_env(),
    )
    return out.stdout.strip()


def guard_ambient() -> None:
    """Refuse to start if the ambient credential is not this project's.

    ADK and the genai SDK read Application Default Credentials directly, and on
    a workstation that may be a completely unrelated identity. Setting
    GOOGLE_GENAI_USE_VERTEXAI=True is therefore only safe once something has
    checked what ADC actually is. This is that check, and every agent module
    calls it at import.

    In a container ADC is the attached service account and this passes trivially.
    """
    if on_cloud_run():
        return
    try:
        import google.auth
    except ImportError:
        return
    try:
        _, project = google.auth.default()
    except Exception:
        return
    _check(project, "Application Default Credentials")


def credentials() -> Tuple[object, str]:
    """Google credentials and the project they are for, never from bare ADC.

    Returns ``(credentials, project)``. Raises :class:`WrongIdentity` rather
    than falling back to an ambient credential, because falling back is the
    failure this module exists to prevent.
    """
    from google.oauth2.credentials import Credentials  # local: agents venv only

    if on_cloud_run():
        import google.auth

        creds, project = google.auth.default()
        _check(project, "the Cloud Run attached service account")
        return creds, project or PROJECT

    return Credentials(token=access_token()), PROJECT


def genai_client(location: Optional[str] = None):
    """A Vertex genai client pinned to this project, this region, this identity."""
    from google import genai

    creds, project = credentials()
    return genai.Client(
        vertexai=True,
        project=project,
        location=location or REGION,
        credentials=creds,
    )
