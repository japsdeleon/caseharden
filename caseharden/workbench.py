#!/usr/bin/env python3
"""The analyst workbench: an operator console over records something else wrote.

What this is. One HTML page and a standard-library HTTP server, run on the
analyst's own machine. It puts the four things a fraud reviewer needs during a
promotion on one screen: the finding under review, the chain as it is being
written, the version registry, and the live attestation state of the version the
fleet is enforcing.

What this is not, and the distinction is the whole reason it is safe to add this
late. **It is not a security boundary.** Every read it makes is a read the
caller could make with `bq` and a terminal, and its one write is a message to the
deployed Analyst Copilot, which screens the text through Model Armor and writes
the review row itself under `analyst-sa`. Nothing here is trusted by the Notary,
the Examiner, or the Policy Server. Removing this program removes a window, not
a control.

Two rules are load-bearing and are asserted by `tests/test_workbench.py` rather
than left to review:

  1. This program never calls `verify()` and never mints a token for
     `examiner-sa`. Attestation state is read from the Policy Server, which is
     the only component that holds the identity allowed to re-score the sealed
     exam. A console that verified for itself would be a second principal within
     reach of the exam, which is exactly the widening the EVIDENCE link exists
     to make visible.

  2. Its compose box offers a verdict, and that is a statement about what this
     program does, not a constraint on what the Copilot will do. `approve` is a
     tool the Copilot service exposes to whatever is typed at it, here or in its
     own chat window, and this program sends free text. It has no approve
     affordance, no approve call, and no way to write a review row itself. It
     cannot stop an operator who types an approval into it, and the honest claim
     is therefore the narrow one: **the console offers only a verdict and writes
     nothing; deciding what gets stored belongs to the Copilot service, under
     `analyst-sa`.** An adversarial pass rejected the stronger phrasing, and it
     was right to.

It binds loopback by default. It holds a `notary-sa` token in memory and can
drive the Copilot, so it is not something to put on an interface anything else
can reach.

usage:
  python3 -m caseharden.workbench                      live, against the project
  python3 -m caseharden.workbench --fixture fixtures/v5    no credentials at all
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import bq, cases, creds, verdicts
# The same list infra/110_run_loop.py refuses on, imported rather than
# restated: a queue whose idea of unusable screening drifts from the
# driver's shows cases as done that the driver will not proceed with.
from .verdicts import UNUSABLE_SCREENING
from .chain import ChainStore

REPO = Path(__file__).resolve().parent.parent
PAGE = Path(__file__).resolve().parent / "workbench.html"

# The loop driver writes this after the fan-out answers and before it starts
# waiting for the analyst. Nothing reaches `chain.links` until the promotion, so
# a console that polled the chain for work would have no source of truth for the
# only part of the run a human is in.
LIVE_FINDING = REPO / "out" / "finding-live.json"

NOTARY = f"notary-sa@{creds.PROJECT}.iam.gserviceaccount.com"

# An access token is minted by shelling out to gcloud, which takes about a
# second. A console polls. Google issues these for an hour; 50 minutes leaves
# room for a slow request to finish on a token that was fresh when it started.
TOKEN_TTL_SECONDS = 50 * 60

# How much of a link payload reaches the browser. An EVIDENCE link can carry
# thousands of event digests, and the timeline shows a summary of each link with
# the full payload behind a click.
MAX_PAYLOAD_CHARS = 20_000
MAX_LIST_ITEMS = 50


class Tokens:
    """Access tokens per service account, cached under their own lifetime.

    Minting happens under a per-account lock, not outside it. The first version
    released the lock before shelling out to gcloud, so two of the browser's
    concurrent polls both missed the cache and both minted: an adversarial pass
    measured `mints=2`. The whole reason this class exists is that minting is a
    one-second subprocess, so a cache that still mints once per concurrent
    request is not a cache.

    The lock is per account rather than global, so a slow mint for one identity
    does not stall a cached read for another.
    """

    def __init__(self, ttl: int = TOKEN_TTL_SECONDS):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}
        self._cache: Dict[str, Tuple[str, float]] = {}

    def _lock_for(self, service_account: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(service_account, threading.Lock())

    def get(self, service_account: str) -> str:
        with self._lock_for(service_account):
            with self._lock:
                hit = self._cache.get(service_account)
            if hit and time.monotonic() < hit[1]:
                return hit[0]
            token = bq.access_token(service_account)
            # The per-account lock serialises minting for one identity. The
            # shared dict is still touched by threads holding different
            # per-account locks, so its own mutations take the global one.
            with self._lock:
                self._cache[service_account] = (token, time.monotonic() + self.ttl)
            return token


def _trim(value):
    """Shorten the long parts of a payload without hiding that they were there."""
    if isinstance(value, list) and len(value) > MAX_LIST_ITEMS:
        return [_trim(v) for v in value[:MAX_LIST_ITEMS]] + [
            f"... {len(value) - MAX_LIST_ITEMS} more, not sent to the browser"]
    if isinstance(value, list):
        return [_trim(v) for v in value]
    if isinstance(value, dict):
        return {k: _trim(v) for k, v in value.items()}
    if isinstance(value, str) and len(value) > MAX_PAYLOAD_CHARS:
        return value[:MAX_PAYLOAD_CHARS] + f"... [{len(value)} chars]"
    return value


LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def link_row(link) -> dict:
    return {
        "seq": link.seq,
        "kind": link.kind,
        "hash": link.hash,
        "prev_hash": link.prev_hash,
        "written_at": link.written_at,
        "intact": link.intact(),
        "payload": _trim(link.payload),
    }


class Source:
    """Where the panes read from. Two implementations, one interface."""

    mode = "?"

    def state(self, version: Optional[str]) -> dict:
        raise NotImplementedError

    def decision(self, kind: str, subject: str) -> Optional[dict]:
        return None

    def near_miss(self, kind: str, subject: str) -> Optional[dict]:
        return None

    def decided_subjects(self, kind: str) -> Optional[Dict[str, str]]:
        """Each decided subject and when it was last decided, or None for cannot know.

        None and the empty mapping are different answers and the queue draws them
        differently. A source with no warehouse behind it returns None, because
        answering "none of these are decided" would put a claim on the screen
        that nothing checked.

        The timestamp and not just the subject, because "has a verdict" and "has
        a verdict about what is on screen now" are different questions once a
        case can be revised.
        """
        return None

    def versions(self) -> list:
        """The version registry, for checking what a verdict cited against it.

        Empty means cannot say, not none, and `citation_check` reads it that way.
        A source with no registry behind it must never be the reason a citation
        is drawn as unknown to the registry.
        """
        return []


class FixtureSource(Source):
    """An exported fixture, rendered with no credentials and no network.

    This is the path a judge can run, and it is the recovery path if the live
    project is unreachable during the demo. The attestation pane shows the
    offline re-check rather than a live state, because a fixture has no live
    state and showing one would be a lie the console told on its own.
    """

    mode = "fixture"

    def __init__(self, directory: Path):
        self.directory = directory
        if not (directory / "chain.jsonl").exists():
            raise SystemExit(f"{directory} carries no chain.jsonl")

    def state(self, version: Optional[str]) -> dict:
        from .recheck import load_links, run_checks

        links = load_links(self.directory / "chain.jsonl")
        source = {}
        source_path = self.directory / "source.json"
        if source_path.exists():
            source = json.loads(source_path.read_text())
        certificate = json.loads((self.directory / "certificate.json").read_text())

        result = run_checks(self.directory, quiet=True)
        failed = [{"title": t, "detail": d} for ok, t, d in result.checks if not ok]
        attestation = {
            "version": source.get("version") or (links[0].version if links else None),
            "state": "OFFLINE-RECHECK",
            "attested": not failed,
            "promotions": "n/a",
            "offline": True,
            "checks_run": len(result.checks),
            "checks_failed": failed,
            "root": certificate.get("root"),
            "note": ("Hashes and the seal, re-derived from this directory alone. "
                     "Whether the record was true when it was written is what the "
                     "live verify answers, and a fixture cannot."),
        }
        return {
            "mode": self.mode,
            "version": attestation["version"],
            "source": dict(source, directory=str(self.directory)),
            "versions": [{
                "version": attestation["version"],
                "parent": source.get("parent"),
                "active": "",
                "root": certificate.get("root"),
                "certificate_uri": source.get("certificate_uri"),
                "promoted_at": source.get("promoted_at"),
            }],
            "links": [link_row(l) for l in links],
            "attestation": attestation,
        }


class LiveSource(Source):
    """The project. Chain and registry over BigQuery as notary-sa, attestation
    over HTTP from the Policy Server.

    The split matters. Reading the chain is reading a table. Deciding whether a
    version is attested means re-scoring the sealed exam, and the only principal
    allowed to do that is the one the Policy Server runs as. This console asks
    that service for its answer instead of taking the identity.
    """

    mode = "live"

    def __init__(self, project: str, policy_url: str, tokens: Tokens):
        self.project = project
        self.policy_url = policy_url.rstrip("/")
        self.tokens = tokens

    def _store(self) -> ChainStore:
        return ChainStore(self.project, self.tokens.get(NOTARY))

    def attestation(self, version: Optional[str]) -> dict:
        path = f"/policy/{version}" if version else "/policy/active"
        url = self.policy_url + path
        # Everything is inside the try, minting included. Two failures used to
        # escape this function and blank the chain and registry panes that had
        # already read successfully: a truncated response body raises
        # http.client.IncompleteRead, which is neither URLError, OSError nor
        # ValueError, and minting an identity token shells out to gcloud, which
        # raises FileNotFoundError when gcloud is not on PATH. The mint sat
        # outside the try, so even that OSError went uncaught. The deployed
        # Policy Server is the configuration infra/README.md documents, and it
        # is the one that mints.
        try:
            headers = {}
            parts = urllib.parse.urlsplit(url)
            if parts.hostname not in ("127.0.0.1", "localhost", "::1"):
                from agents.common import auth

                token = auth.id_token(auth.origin(url))
                if token:
                    headers["Authorization"] = "Bearer " + token
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                answer = json.load(response)
            # Which of the two answers below the page is holding is not derivable
            # from the value: the unknown state minted in the handler carries the
            # same shape and its own "state". The page says in words who reported
            # the state, so it has to be told, not left to guess from a key.
            answer["policy_server_reached"] = True
            return answer
        except Exception as exc:  # noqa: BLE001 - every failure is the unknown state
            # A console that cannot reach the Policy Server does not know the
            # state, and "unknown" is a state this system already defines. It is
            # never rendered as attested, so a broad catch fails closed.
            # "UNREACHABLE" is minted here, by this console. Nothing answered.
            # The page renders it as not knowing rather than as a Policy Server
            # verdict, which is what policy_server_reached tells it.
            return {"version": version, "attested": False, "state": "UNREACHABLE",
                    "promotions": "FROZEN", "policy_server_reached": False,
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                    "policy_url": url}

    def state(self, version: Optional[str]) -> dict:
        out: dict = {"mode": self.mode, "errors": {},
                     "source": {"project": self.project, "policy_url": self.policy_url}}
        try:
            store = self._store()
            versions = store.versions()
            out["versions"] = versions
            if not version:
                active = [r for r in versions if str(r.get("active")).lower() == "true"]
                version = active[-1]["version"] if active else (
                    versions[-1]["version"] if versions else None)
        except Exception as exc:  # noqa: BLE001 - a pane reports why it is empty
            out["versions"] = []
            out["errors"]["versions"] = f"{type(exc).__name__}: {exc}"[:300]
        out["version"] = version

        try:
            out["links"] = [link_row(l) for l in self._store().read(version)] if version else []
        except Exception as exc:  # noqa: BLE001
            out["links"] = []
            out["errors"]["links"] = f"{type(exc).__name__}: {exc}"[:300]

        out["attestation"] = self.attestation(version)
        return out

    # Named columns, never `*`. The six after `approved` were added to the table
    # by infra/32_analyst_identity.sh: the policy the analyst cited, whether they
    # cited it at all, and the machine advisory as it was displayed beside their
    # verdict box. A row written before that migration carries NULL in all six,
    # which is a different answer from a verdict that cited nothing, and the page
    # draws the two differently.
    DECISION_COLUMNS = (
        "decision_id, FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts) AS ts,"
        " kind, analyst, subject, disposition, rationale, ma_verdict, ma_band,"
        " ma_prompt_injection_score, ma_jailbreak_score, approved,"
        " cited_policy_id, cited_version, citation_source,"
        " advisory_recommendation, advisory_rule, advisory_confidence, advisory_source")

    def versions(self) -> list:
        return self._store().versions()

    def decision(self, kind: str, subject: str) -> Optional[dict]:
        """The review row the Copilot wrote against this exact subject.

        Narrower than what `infra/110_run_loop.py` waits on, which also bounds
        `ts` to the run's start. Unbounded here on purpose: the console has no
        run start to bound by, and a job id is unique per run, so the extra
        reach is a row from the same job and not a different finding.
        """
        rows = bq.query(
            f"SELECT {self.DECISION_COLUMNS}"
            f" FROM `{bq.qualified_table(self.project, 'review', 'decisions')}`"
            f" WHERE kind = @kind AND subject = @subject"
            f" ORDER BY ts DESC LIMIT 1",
            self.project, self.tokens.get(NOTARY),
            params={"kind": kind, "subject": subject})
        return rows[0] if rows else None

    def decided_subjects(self, kind: str) -> Optional[Dict[str, str]]:
        """One query for the whole queue, rather than one per row.

        A queue that could not tell a decided case from a waiting one would list
        every finding ever published as work, which is the state this store was
        built to replace. The decision itself is still not copied anywhere: this
        asks which subjects have a row and keeps no part of the row.

        Grouped rather than filtered by a list of subjects, because
        `caseharden/bq.py` takes scalar named parameters only, and building an
        `IN` list into the SQL text is the interpolation that module exists to
        avoid. The distinct subjects here are the findings that have been
        reviewed, which is the same order of magnitude as the cases on disk.
        """
        rows = bq.query(
            f"SELECT subject,"
            f" FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', latest.ts) AS ts,"
            f" latest.disposition AS disposition,"
            f" latest.ma_verdict AS ma_verdict"
            f" FROM (SELECT subject, ARRAY_AGG(t ORDER BY t.ts DESC LIMIT 1)[OFFSET(0)]"
            f" AS latest FROM `{bq.qualified_table(self.project, 'review', 'decisions')}`"
            f" AS t WHERE kind = @kind GROUP BY subject)",
            self.project, self.tokens.get(NOTARY), params={"kind": kind})
        # The same format `DECISION_COLUMNS` produces, because `_predates`
        # compares these as strings and only a shared fixed-width UTC shape makes
        # that safe.
        # The latest row per subject rather than only its timestamp: whether a
        # verdict closes a case depends on what it says and on whether its
        # screening cleared, and both are on the row.
        return {r["subject"]: r for r in rows}

    def near_miss(self, kind: str, subject: str) -> Optional[dict]:
        """A row about this job filed under a subject the driver will never find.

        The console's outgoing guard constrains the analyst's sentence. It cannot
        constrain the argument the Copilot's model passes to `record_verdict`,
        and the tool's own docstring invites a normalisation: a job id carries a
        location prefix, `europe-west3:job_X`, and `job_X` is the same job to a
        person and a different string to `wait_for`.

        So the divergence is detected rather than assumed away. A row stored
        against a subject that ends with the bare job id, but is not the subject
        the driver polls, is the 900-second stall in progress, and the analyst is
        told while there is still time to re-file it.
        """
        bare = subject.rsplit(":", 1)[-1]
        if not bare or bare == subject:
            return None
        # The bare id itself, or the same id under a different location prefix.
        # Not a plain ENDS_WITH on the bare id: that also matches an unrelated
        # subject that merely ends with those characters, such as
        # `something_job_X`, and reporting an unrelated verdict as this one's
        # near miss would send the analyst to re-file a verdict that is fine.
        rows = bq.query(
            f"SELECT {self.DECISION_COLUMNS}"
            f" FROM `{bq.qualified_table(self.project, 'review', 'decisions')}`"
            f" WHERE kind = @kind AND subject != @subject"
            f" AND (subject = @bare OR ENDS_WITH(subject, CONCAT(':', @bare)))"
            f" ORDER BY ts DESC LIMIT 1",
            self.project, self.tokens.get(NOTARY),
            params={"kind": kind, "subject": subject, "bare": bare})
        return rows[0] if rows else None


def read_finding(path: Path = LIVE_FINDING) -> dict:
    if not path.exists():
        return {"present": False, "path": str(path)}
    try:
        # The age travels with the finding because nothing deletes this file
        # between runs. Without it, yesterday's finding renders exactly like the
        # one under review, and the pane would prefill a verdict against a job
        # nobody is waiting on.
        age = max(0, int(time.time() - path.stat().st_mtime))
        finding = json.loads(path.read_text())
        if not isinstance(finding, dict):
            # The driver writes an object. Anything else is not a finding, and
            # every reader here calls .get on it, which would be an
            # AttributeError two frames away from the file that caused it.
            raise ValueError(f"expected a JSON object, got {type(finding).__name__}")
        return {"present": True, "path": str(path), "age_s": age,
                "finding": _trim(finding)}
    except (ValueError, OSError, RecursionError) as exc:
        # The driver writes this file while the console reads it, so a
        # half-written file is an ordinary race rather than broken evidence.
        # RecursionError is in the list because json.loads raises it, not a
        # JSONDecodeError, on deeply nested input: an adversarial pass crashed
        # this handler with a 1,100-level array. A pane that says why it is
        # empty beats a dropped connection.
        return {"present": False, "path": str(path),
                "error": f"{type(exc).__name__}: {exc}"[:200]}


STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _stamp(value) -> Optional[str]:
    """The value if it is a real instant in the one format both sides use, else None.

    `STAMP_RE` alone counts digits and punctuation, so `2026-99-99T99:99:99Z`
    matched it and `active_at` answered a definite version for a window that
    never happened. An adversarial pass found that. Parsing is what rules out an
    impossible date, and the pattern is kept in front of it so the format itself
    is still the thing being required rather than whatever `strptime` would also
    accept.

    Comparison stays lexicographic afterwards. That is valid only because every
    stamp reaching here is this exact fixed-width UTC format, which is what this
    function is now guaranteeing rather than assuming.
    """
    if not (isinstance(value, str) and STAMP_RE.match(value)):
        return None
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return value


INSTANT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


def _instant(value) -> Optional[datetime.datetime]:
    """One UTC stamp as a moment, at whatever precision it was written with.

    Parsed rather than compared as text, and the two are not the same answer
    once precision is mixed. `2026-08-30T10:00:00.100000Z` sorts BEFORE
    `2026-08-30T10:00:00Z` as a string, because `.` is below `Z`, so the older
    of the two would read as the newer for exactly the records where the
    difference matters.

    Both shapes are accepted because both exist: rows written before the
    timestamps carried microseconds still have to be readable, and a comparison
    that refused them would answer "cannot tell" for the entire history.
    """
    if not (isinstance(value, str) and INSTANT_RE.match(value)):
        return None
    for shape in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(value, shape)
        except ValueError:
            continue
    return None


def _predates(revised_at, decision_ts) -> Optional[bool]:
    """True when the verdict on show was recorded before the evidence changed.

    A case that is revised keeps its id and its verdict lookup, so the pane can
    end up showing revision 1's rows beside a review row filed against revision
    0. Nothing in either record says so, and a month later the pair reads as one
    consistent decision about the evidence above it.

    Both sides are parsed to a moment. They were compared as strings while both
    were second-granularity, and a verdict at 10:00:00.100 with a revision at
    10:00:00.900 then formatted identically and answered "not stale" about
    evidence that had changed after the review. The timestamps now carry
    microseconds at both sources, and `_instant` still reads the second-only
    shape so the records written before that stay comparable.

    Anything it cannot read answers None. A wrong `false` here is the reading
    that hides the mismatch, so not knowing has to be sayable.
    """
    revised = _instant(revised_at)
    decided = _instant(decision_ts)
    if revised is None or decided is None:
        return None
    return decided < revised


DEFAULT_LINE = "conduct-policy"


def active_at(versions: list, when, policy_id: str = DEFAULT_LINE) -> Optional[str]:
    """The version of one policy line that had been promoted most recently at `when`.

    This is the "version active during the finding window" the citation is
    supposed to name, and this function is here because **this is the only
    process that can compute it.** It needs two facts in the same place: the
    finding's window bounds, which arrive from the case store or the live
    finding file, and each version's promotion time, which lives in
    `policy.versions` and is read here under `notary-sa`. The Analyst Copilot,
    which writes the row, has neither. It is handed a job id string and holds
    `analyst-sa`, which has no read on the registry at all, so it stores what
    the analyst named and marks a row that named nothing as naming nothing.

    A read-time check rather than a write-time default, and that ordering is a
    property rather than a compromise: the registry gains versions after a
    verdict is filed, and answering now answers against the registry as it
    stands.

    Scoped to one policy line because "active" is per line: `policy.versions`
    carries a `policy_id` and registration deactivates only within its own
    lineage. A row written before that column existed carries NULL and belongs
    to `conduct-policy`, which is the convention `ChainStore.register` already
    holds.

    Compared as strings, safe only because both sides are the same fixed-width
    UTC format: `infra/110_run_loop.py` writes `window_start` with
    `strftime("%Y-%m-%dT%H:%M:%SZ")` and `ChainStore.versions` formats
    `promoted_at` into the same shape. Both are checked rather than assumed and
    anything else answers None, because a wrong answer here would tell an
    analyst their citation is wrong when nothing checked it.
    """
    if _stamp(when) is None:
        return None
    promoted = [v for v in versions
                if (v.get("policy_id") or DEFAULT_LINE) == policy_id
                and _stamp(v.get("promoted_at")) is not None
                and v["promoted_at"] <= when]
    if not promoted:
        return None
    latest = max(v["promoted_at"] for v in promoted)
    at_latest = [v for v in promoted if v["promoted_at"] == latest]
    # A tie is not a version. `promoted_at` is formatted to the second, so two
    # promotions in the same line inside one second are indistinguishable here,
    # and THREATS.md entry 11 records that concurrent registry writes are
    # possible. Naming whichever row the query returned first would be the
    # console deciding what was in force by list order. An adversarial pass
    # produced the tie and got a definite answer back.
    if len(at_latest) != 1:
        return None
    return str(at_latest[0].get("version") or "") or None


def citation_check(row: Optional[dict], versions: list, window_start=None) -> Optional[dict]:
    """What the recorded citation says, checked against the registry that knows.

    The Copilot validates a citation's shape and stops there, because
    `analyst-sa` cannot read `policy.versions`. The check that the cited version
    exists belongs to an identity that can see the registry, and that is this
    console, holding `notary-sa`. Nothing here is a gate: the row is already
    written, and this only decides what the page says about it.

    Five answers, and they are five because collapsing any pair would put a claim
    on screen that nothing checked:

      `PREDATES-COLUMNS`  both citation fields are NULL, so the row was written
                          before infra/32_analyst_identity.sh added them. Not the
                          same as a verdict that cited nothing.
      `UNCITED`           the row records `citation_source = 'NONE'`. The analyst
                          named no policy and the Copilot invented none.
      `REGISTRY-UNKNOWN`  a version is cited and no registry rows were readable,
                          so this cannot say whether it exists. An empty list is
                          cannot-say, never none.
      `UNREGISTERED`      a version is cited and the registry has no such row in
                          that line. The citation names nothing.
      `REGISTERED`        the registry has it. `active_at_window_start` then says
                          which version was actually in force when the conduct
                          under review happened, and `matches_window` whether the
                          analyst cited that one. False is not an error: an
                          analyst may deliberately cite a later version they are
                          arguing from. It is the difference that is worth
                          showing, not a verdict on it.
    """
    if not row:
        return None
    source = row.get("citation_source")
    version = row.get("cited_version")
    line = row.get("cited_policy_id") or None
    if not version:
        if source is None:
            return {"state": "PREDATES-COLUMNS", "policy_id": None, "version": None}
        return {"state": "UNCITED", "source": source, "policy_id": None, "version": None}
    out = {"source": source, "policy_id": line, "version": version}
    if not versions:
        return dict(out, state="REGISTRY-UNKNOWN")
    # A citation that names no line is matched on the version alone, and the line
    # it resolves to is reported back. Assuming `conduct-policy` for a bare
    # version would report a real `payments-policy` version as naming nothing,
    # which is a false alarm about the one field this pane exists to draw.
    # Version names are unique across lines by a check in `ChainStore.register`,
    # and THREATS.md entry 11 records the read-before-write race in that check,
    # so a duplicate is possible and the first match is taken rather than claimed
    # to be the only one.
    known = [v for v in versions
             if str(v.get("version")) == str(version)
             and (not line or (v.get("policy_id") or DEFAULT_LINE) == line)]
    if not known:
        return dict(out, state="UNREGISTERED")
    resolved = line or (known[0].get("policy_id") or DEFAULT_LINE)
    in_force = active_at(versions, window_start, resolved)
    return dict(out, state="REGISTERED", policy_id=resolved,
                promoted_at=known[0].get("promoted_at"),
                active_at_window_start=in_force,
                matches_window=None if in_force is None else in_force == str(version))


def decision_error(exc: Exception) -> str:
    """The failed decision lookup, said in a way an operator can act on.

    One failure has a fix and no way to discover it. `DECISION_COLUMNS` selects
    the citation and advisory columns, and a console pulled before the migration
    is run queries a table that has none of them: BigQuery answers "Unrecognized
    name", the pane reports a lookup that did not complete, and the compose box
    is withheld until it succeeds. It never succeeds, and nothing on screen
    mentions a schema. The console is the component most likely to be updated
    first, because it runs from the analyst's own checkout.

    Every other failure keeps the message it had. Guessing a cause from an error
    this function does not recognise would be the console inventing a diagnosis.
    """
    said = f"{type(exc).__name__}: {exc}"
    if "Unrecognized name" in said:
        said += (". This console reads columns that review.decisions does not have "
                 "yet. Run infra/32_analyst_identity.sh to add them, then deploy "
                 "the Copilot; until then no verdict can be looked up or filed.")
    return said[:400]


def job_id_of(finding: dict) -> Optional[str]:
    """The job id under review, or None when the file carries no usable one.

    Only a non-empty string is a subject. The driver writes one, but this is a
    file on disk: a hand-edited or half-written one can hold anything JSON
    allows, and a list reaching `job_id in text` is a TypeError two frames from
    the file that caused it, which the handler then reports as a 502. That is
    the same shape as the non-object body that reached `.get` before it, found
    by an adversarial pass rather than by a test.
    """
    job_id = (finding.get("finding") or {}).get("job_id")
    return job_id if isinstance(job_id, str) and job_id else None


def names_the_job(text: str, job_id: str) -> bool:
    """True when the text names this job id, and not a longer one containing it.

    A plain substring test passed `…job_5UcJoBBEaZWU0X` while the finding under
    review was `…job_5UcJoBBEaZWU0`. The driver compares `subject` for equality,
    so the longer id is exactly the subject it will never find, which is the one
    thing this check exists to catch. Requiring a non-identifier character on
    both sides closes it. A trailing colon or full stop still matches, because
    "verdict on <id>: confirmed abuse" is how the sentence is written.
    """
    edge = r"[A-Za-z0-9_-]"
    return bool(re.search(f"(?<!{edge}){re.escape(job_id)}(?!{edge})", text))


# The session name arrives in the request body, so the number of distinct ones
# is chosen by the caller, not by the number of findings reviewed. Bounded, and
# oldest first, so a long-running console cannot be made to hold an unbounded
# map by an endless stream of new session names.
MAX_LATCHED_SESSIONS = 256


class Workbench:
    """Everything the handler needs, so the handler stays a router."""

    def __init__(self, source: Source, finding_path: Path = LIVE_FINDING,
                 chat=None):
        self.source = source
        self.finding_path = finding_path
        # Beside the live finding, because the driver writes both under its
        # `--out` directory and pointing the console at one finding while it
        # listed another run's cases is a confusion with no reason to exist.
        self.cases_dir = finding_path.parent / cases.CASES_DIRNAME
        # Injected so the tests can drive every route without a deployed fleet.
        self._chat = chat
        # Which job id each chat session has already named, for the guard in
        # chat(). Ordered and capped, see MAX_LATCHED_SESSIONS.
        self._named: "OrderedDict[str, str]" = OrderedDict()
        self._named_lock = threading.Lock()

    def state(self, version: Optional[str]) -> dict:
        return self.source.state(version)

    def _citation(self, decision: Optional[dict], window_start=None) -> Optional[dict]:
        """The registry's read of what a decision row cited.

        The registry is fetched only when a version is actually cited, which is
        why this is not a query on every poll. A row that cites nothing needs no
        registry to say so, and today that is every row: the columns are new and
        the fleet has written none since. What the console will not do is spend a
        BigQuery job per poll working out the citation that could have been
        there — that answer changes nothing and costs a query on the exact
        stretch where the console is already polling for a verdict.
        """
        if not decision:
            return None
        try:
            versions = self.source.versions() if decision.get("cited_version") else []
        except Exception as exc:  # noqa: BLE001 - cannot say is a state, not a blank
            return {"state": "REGISTRY-UNKNOWN",
                    "version": decision.get("cited_version"),
                    "policy_id": decision.get("cited_policy_id") or DEFAULT_LINE,
                    "error": f"{type(exc).__name__}: {exc}"[:300]}
        return citation_check(decision, versions, window_start)

    def finding(self) -> dict:
        out = read_finding(self.finding_path)
        job_id = job_id_of(out)
        if job_id:
            try:
                out["decision"] = self.source.decision("VERDICT", job_id)
                if not out["decision"]:
                    out["near_miss"] = self.source.near_miss("VERDICT", job_id)
            except Exception as exc:  # noqa: BLE001
                out["decision"] = None
                out["decision_error"] = decision_error(exc)
            out["citation"] = self._citation(
                out.get("decision"), (out.get("finding") or {}).get("window_start"))
        return out

    def cases(self) -> dict:
        """Every case the store holds, each marked decided, waiting or unknown.

        The store records no disposition, and this does not add one: a
        disposition kept beside the finding would be a second copy of a row
        `review.decisions` owns, free to disagree with it. What travels here is
        one bit, derived at read time from a single query, and nothing is
        written back.

        Six values, not two. A warehouse this console could not reach makes
        every case `unknown`, and a queue that showed those as waiting would
        send an analyst to re-review a case that was closed yesterday.

        `stale` is the fourth, and it is the one a queue cannot do without. A
        case that was decided at ten and revised at eleven carries a verdict
        about evidence nobody has read. Reporting that as `yes` is how an
        analyst skips an unreviewed revision, and the detail route knowing
        better does not help someone who never opens it.

        `blocked` and `escalated` are the other two, and both are cases with a
        verdict on record that nothing has finished with. A blocked rationale is
        a review the driver refuses to act on; an escalated one is the analyst
        saying it was not their call. Each was reported as decided, which is how
        a case leaves the only queue anyone watches with the work still owed.
        """
        listed = cases.list_cases(self.cases_dir)
        decided: Optional[Dict[str, str]] = None
        try:
            decided = self.source.decided_subjects("VERDICT")
        except Exception as exc:  # noqa: BLE001
            listed["decided_error"] = f"{type(exc).__name__}: {exc}"[:300]
        for row in listed["cases"]:
            if "error" in row:
                continue
            row["decided"] = self._decided_state(row, decided)
        return listed

    @staticmethod
    def _decided_state(row: dict, decided: Optional[Dict[str, str]]) -> str:
        """One queue row's review state, from the store's fact and the warehouse's.

        `stale` needs both timestamps to be readable. When either is not, the
        answer is the weaker `yes`: the case is decided, and this cannot say
        whether the decision is about what is on screen. Saying `stale` on a
        comparison that did not happen would be the same invention in the other
        direction.
        """
        if decided is None:
            return "unknown"
        latest = decided.get(row.get("job_id"))
        if latest is None:
            return "no"
        if str(latest.get("ma_verdict") or "").upper() in UNUSABLE_SCREENING:
            # A verdict the driver will not act on. `refuse_unscreened` in
            # infra/110_run_loop.py stops the drafting path on exactly these, so
            # a queue calling the case done sends the analyst past a review that
            # cannot proceed.
            return "blocked"
        if verdicts.member(latest.get("disposition")) == "escalate":
            # Recorded, and deliberately not resolved: the analyst said this was
            # not their call. Reporting it as decided is how a case leaves the
            # only queue anyone watches with the decision still owed.
            return "escalated"
        if _predates(row.get("revised_at"), latest.get("ts")):
            return "stale"
        return "yes"

    def case(self, case_id: str) -> Optional[dict]:
        """One case, with its evidence and the verdict recorded against its job.

        Same lookup `finding()` makes, against the case's own job id rather than
        whichever finding the driver published last. That is the difference the
        store exists for: a case stays answerable after the next run replaces
        the live file.
        """
        found = cases.read_case(self.cases_dir, case_id)
        if found is None:
            return None
        out = {"case": _trim(found)}
        job_id = found.get("job_id")
        if isinstance(job_id, str) and job_id:
            try:
                out["decision"] = self.source.decision("VERDICT", job_id)
                if not out["decision"]:
                    out["near_miss"] = self.source.near_miss("VERDICT", job_id)
            except Exception as exc:  # noqa: BLE001
                out["decision"] = None
                out["decision_error"] = decision_error(exc)
        out["verdict_predates_revision"] = _predates(
            found.get("revised_at"), (out.get("decision") or {}).get("ts"))
        out["citation"] = self._citation(
            out.get("decision"), (found.get("finding") or {}).get("window_start"))
        return out

    def _latch(self, session: str, job_id: str) -> None:
        """Remember that this session may go on talking about this job.

        Called after the Copilot has taken the turn, not before it. Latching
        first meant a first turn the Copilot never accepted still opened the
        session: the analyst's message failed, and the bare "yes" that followed
        was let through on the strength of a turn that never arrived.
        """
        with self._named_lock:
            self._named[session] = job_id
            self._named.move_to_end(session)
            while len(self._named) > MAX_LATCHED_SESSIONS:
                self._named.popitem(last=False)

    def chat(self, text: str, session: str) -> dict:
        """Say one thing to the Copilot, after checking the one thing that stalls a run.

        `infra/110_run_loop.py` waits on a `review.decisions` row whose `subject`
        equals the detector's job id exactly. A verdict recorded against anything
        else stores fine, screens fine, and leaves the driver polling for fifteen
        minutes with nothing to say why. So a message that does not carry the job
        id under review is refused here, where the analyst can still fix it.

        The check is on a session's first turn, not on every turn. Requiring it
        every time refused the turn the write actually needs: the Copilot echoes
        the arguments back and asks, and the answer is "yes", which names no job
        id. That refusal was measured, not predicted, against the deployed
        Copilot on 2026-08-26.

        Latching costs nothing the guard was holding. Only a turn that files a
        verdict can file one against the wrong subject, and a turn that names
        this job id while asking for a different subject was already accepted
        before the latch existed.
        """
        if not text.strip():
            raise Refused("nothing to say")
        if self._chat is None:
            raise Refused(
                "this workbench is running against a fixture. There is no fleet "
                "to talk to and no review row to write.")
        known = self.reviewable_subjects()
        if known:
            named = self._subject_for(session, text, known)
            if named is None:
                raise Refused(
                    "the message does not name a case this desk holds. A verdict "
                    "is stored against a subject, and the only subjects anything "
                    "will look for are the open cases: "
                    + ", ".join(sorted(known)[:8])
                    + (" and others" if len(known) > 8 else "")
                    + ". A verdict filed against anything else is stored and "
                      "never found.")
        reply = self._chat(text, session)
        if known and named:
            self._latch(session, named)
        return {"reply": reply}

    def reviewable_subjects(self) -> set:
        """Every job id a verdict may be filed against from this desk.

        The live finding and every readable case in the store. It was the live
        finding alone, because there was one case: the driver polls for a row
        whose subject equals that job id, so anything else left an analyst
        waiting fifteen minutes with nothing to say why, and the guard existed to
        stop that.

        With a queue that reasoning changed shape. The other cases are detector
        jobs that found real conduct in the same window, and filing a verdict on
        one is a deliberate act on a case that exists, not a typo. What the guard
        still refuses is a subject nothing knows about, which is the failure it
        was written for.

        A verdict on a case the run is not waiting on advances nothing: the
        driver's poll is bounded to its own job id and its own start time, and
        the Notary requires the bundle's verdict row to carry the finding's job
        id. It records a decision and closes that row in the queue, which is what
        the three terminal dispositions are for.
        """
        subjects = set()
        live = job_id_of(read_finding(self.finding_path))
        if live:
            subjects.add(live)
        for row in cases.list_cases(self.cases_dir).get("cases", []):
            job_id = row.get("job_id")
            # The error check is redundant and kept: `list_cases` gives an
            # unreadable case a row carrying only its id, the error and the path,
            # so there is no job id on it to admit. A mutation deleting this test
            # survives the suite for that reason rather than for want of a test.
            # It stays because it says what the loop means, and because a future
            # broken-row shape that did carry a job id would otherwise make an
            # unreadable case reviewable.
            if not row.get("error") and isinstance(job_id, str) and job_id:
                subjects.add(job_id)
        return subjects

    def _subject_for(self, session: str, text: str, known: set) -> Optional[str]:
        """Which open case this turn is about, or None.

        A turn that names one is about that one. A turn that names none is the
        confirmation the Copilot asks for — "yes" names no job id — and is read
        as being about whatever this session named last, provided that case is
        still open.
        """
        named = next((j for j in sorted(known) if names_the_job(text, j)), None)
        if named:
            return named
        with self._named_lock:
            latched = self._named.get(session)
        return latched if latched in known else None


class Refused(Exception):
    """A request the console will not pass on, with the reason the analyst needs."""


def handler_for(workbench: Workbench, allowed_hosts: Tuple[str, ...] = LOOPBACK):
    """Routes, plus the two checks a localhost service does not get for free.

    Binding to 127.0.0.1 keeps other machines out. It does not keep out the
    analyst's own browser, and this process can drive an agent under their
    identity, so any page they have open is in reach of `/api/chat`:

      DNS rebinding. A hostile name that resolves to 127.0.0.1 makes a page
      same-origin with this server. The `Host` header still carries the name the
      browser asked for, so requiring a loopback `Host` refuses it.

      A cross-origin form post. A `fetch` carrying `Content-Type:
      application/json` is preflighted, and this server answers no preflight, so
      the browser blocks it. A plain `<form enctype="text/plain">` is not
      preflighted and can carry a body that `json.loads` accepts. Requiring the
      JSON content type is what closes that, because a form cannot set it.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "caseharden-workbench"

        def _wrong_host(self) -> Optional[str]:
            # A missing Host is refused rather than allowed. HTTP/1.1 requires
            # one, so only a hand-written client omits it, and treating absent
            # as acceptable is how the check above becomes optional.
            #
            # An IPv6 host is bracketed, and rsplit(":", 1) on `[::1]` splits
            # inside the address and yields ":". That failed closed, so it was
            # not a hole, but it was not the check this claims to be either.
            raw = self.headers.get("Host") or ""
            if raw.startswith("["):
                host = raw[1:].partition("]")[0]
            else:
                host = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
            if host not in allowed_hosts:
                return (f"refused a request for host {host!r}. This console serves "
                        f"{', '.join(allowed_hosts)} only.")
            origin = self.headers.get("Origin")
            if origin:
                name = urllib.parse.urlsplit(origin).hostname or ""
                if name.strip("[]") not in allowed_hosts:
                    return f"refused a cross-origin request from {origin!r}."
            return None

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # The page is one file with no external anything. Saying so means a
            # stray script tag fails loudly rather than reaching the network from
            # a page holding an analyst's session.
            #
            # frame-ancestors closes the gap the Host and Content-Type checks
            # leave open. Those stop a hostile page reading from this server or
            # posting to it. Neither stops it framing the console invisibly and
            # letting the analyst's own clicks land on it, which needs no
            # cross-origin read at all. X-Frame-Options repeats it for browsers
            # that predate the CSP directive.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'; connect-src 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, body: dict) -> None:
            self._send(code, json.dumps(body, default=str).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
            wrong = self._wrong_host()
            if wrong:
                return self._json(403, {"error": wrong})
            parts = urllib.parse.urlsplit(self.path)
            path = parts.path.rstrip("/") or "/"
            # Blank values kept, so `?id=` is an id this store could not have
            # written rather than a parameter that was never sent. Without this
            # it was dropped, and a request for one case answered with the whole
            # queue. Every reader below turns an empty string back into "not
            # asked for" where that is what it means.
            query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
            if path == "/":
                return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            if path == "/healthz":
                return self._json(200, {"ok": True, "mode": workbench.source.mode})
            if path == "/api/state":
                version = (query.get("version") or [None])[0] or None
                if version and not version.replace("-", "").replace("_", "").isalnum():
                    return self._json(400, {"error": "not a usable version name"})
                try:
                    return self._json(200, workbench.state(version))
                except Exception as exc:  # noqa: BLE001
                    return self._json(200, {"mode": workbench.source.mode,
                                            "errors": {"state": f"{type(exc).__name__}: {exc}"[:300]},
                                            "versions": [], "links": [],
                                            "attestation": {"state": "UNREACHABLE",
                                                            "attested": False,
                                                            "promotions": "FROZEN"}})
            if path == "/api/finding":
                return self._json(200, workbench.finding())
            if path == "/api/cases":
                case_id = (query.get("id") or [None])[0]
                try:
                    if case_id is None:
                        return self._json(200, workbench.cases())
                    # Checked here as well as in `read_case`, so the shape of
                    # the id is refused at the edge rather than answered as a
                    # missing case. It reaches a path join either way.
                    if not cases.CASE_ID_RE.match(case_id):
                        return self._json(400, {"error": "not a case id"})
                    found = workbench.case(case_id)
                    if found is None:
                        return self._json(404, {"error": "no such case"})
                    return self._json(200, found)
                except Exception as exc:  # noqa: BLE001
                    # Contained like `/api/state`, and for the same reason: this
                    # reads a directory somebody else writes, and a pane that
                    # says why it is empty beats a dropped connection.
                    return self._json(200, {"cases": [], "total": 0,
                                            "unreadable": 0, "truncated": False,
                                            "error": f"{type(exc).__name__}: {exc}"[:300]})
            return self._json(404, {"error": "no such path"})

        def do_POST(self) -> None:  # noqa: N802
            wrong = self._wrong_host()
            if wrong:
                return self._json(403, {"error": wrong})
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path != "/api/chat":
                return self._json(404, {"error": "no such path"})
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() \
                    != "application/json":
                return self._json(415, {"error": "this endpoint takes application/json"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64_000:
                return self._json(413, {"error": "message too long"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, RecursionError):
                # RecursionError, not only JSONDecodeError: json.loads raises it
                # on deeply nested input, and a body small enough to pass the
                # length cap can still be thousands of arrays deep. How deep is
                # version-dependent, which is why the shape check below is the
                # one that actually holds: on 3.12 a body that 3.9 refused parses
                # into a list instead.
                return self._json(400, {"error": "not usable JSON"})
            if not isinstance(body, dict):
                # `[]` and `"x"` are valid JSON and have no .get, so without this
                # they reached the generic handler as an AttributeError and came
                # back 502. A malformed request is the client's fault, and the
                # status has to say so.
                return self._json(400, {"error": "expected a JSON object"})
            try:
                return self._json(200, workbench.chat(str(body.get("text", "")),
                                                      str(body.get("session", ""))))
            except Refused as exc:
                return self._json(409, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"{type(exc).__name__}: {exc}"[:300]})

        def handle_one_request(self) -> None:
            # A browser closing a keep-alive connection raises here, and the
            # default handler prints a traceback for it. This console runs in a
            # terminal that is on camera; a reset socket is not an incident and
            # must not look like one.
            try:
                super().handle_one_request()
            except (ConnectionResetError, BrokenPipeError):
                self.close_connection = True

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def build(args) -> Workbench:
    if args.fixture:
        return Workbench(FixtureSource(Path(args.fixture)),
                         finding_path=Path(args.finding))
    source = LiveSource(args.project, args.policy_url, Tokens())

    def chat(text: str, session: str) -> str:
        from .copilot_client import say

        return say(text, session)

    return Workbench(source, finding_path=Path(args.finding), chat=chat)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="An analyst workbench over the chain, the registry and the finding.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8090")))
    parser.add_argument("--project", default=creds.PROJECT)
    parser.add_argument("--policy-url", default=os.environ.get(
        "CASEHARDEN_POLICY_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--fixture", default="",
                        help="a fixture directory, for example fixtures/v5. "
                             "Uses no credentials and makes no network call.")
    parser.add_argument("--finding", default=str(LIVE_FINDING),
                        help="where the loop driver writes the finding under review")
    args = parser.parse_args(argv)

    workbench = build(args)
    # Loopback, with no flag to change it. This process holds a notary-sa token
    # and can drive the Copilot, and it authenticates nobody: an address other
    # machines can reach would be an unauthenticated console over the chain.
    # A reviewer asked for a bind flag with a warning printed beside it; a
    # warning is not a refusal, and there is no use for this program that needs
    # one. Decision 1 of the sprint keeps it local.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(workbench))
    print(f"caseharden workbench on http://127.0.0.1:{args.port}  mode={workbench.source.mode}")
    if workbench.source.mode == "live":
        print(f"  attestation from {args.policy_url}; this console never verifies for itself")
        print(f"  finding under review: {args.finding}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
