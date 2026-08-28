#!/usr/bin/env python3
"""The provenance chain: links, their hashes, and where they are re-derived from.

A link is a claim about one step of a policy promotion. Its hash covers the
previous link's hash, so the sequence is tamper-evident. That much is ordinary.

What is not ordinary is that two of the link kinds are *derivations* rather than
records. EVIDENCE states which conduct events justified the change and which
principals could read the exam; EXAM states what the deterministic Examiner
measured. Verification re-runs both against the warehouse as it stands now. A
signature proves nobody edited the claim. Re-derivation proves the claim is
still true, which is why a late-arriving event can withdraw a version's
authority though no attacker touched it.

The other kinds are records, protected by the hash chain alone. Section 2 of the
plan claims re-derivation for the evidence and the exam and for nothing else,
and `verify` prints which of the two each link got.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Sequence

from . import bq

# The seven links of a promotion, plus the two that record refusals and the one
# reattest appends. Order here is the order they are written.
KINDS = (
    "EVIDENCE",         # re-derived: the conduct rows and the exam's access list
    "FINDING",          # recorded: what the detectors returned, with job and trace ids
    "VERDICT",          # recorded: the analyst's disposition and its screening result
    "DRAFT",            # recorded: the candidate policy the Proposer emitted
    "DRAFT-REJECTED",   # recorded: a draft that failed schema validation
    "HOLDOUT-DENIED",   # recorded: BigQuery's 403, verbatim
    "EXAM",             # re-derived: the Examiner's measurements and the gate verdict
    "APPROVAL",         # recorded: who approved, and what they approved
    "EVIDENCE-CHANGED", # re-derived: supersedes EVIDENCE after a successful reattest
)

DERIVED_KINDS = ("EVIDENCE", "EVIDENCE-CHANGED", "EXAM")

# Above this many events in the cited window, the link carries the digest alone
# and a break can name a count but not an id.
# ponytail: 5000 covers every window this corpus produces; store a per-day
# digest tree if a real deployment ever cites a wider one.
MAX_CITED_EVENTS = 5000

# Per-row digests are stored one per cited event, so they are truncated. 16 hex
# characters is 64 bits; over the few hundred rows a finding cites, a collision
# is not a risk worth the payload size.
ROW_DIGEST_CHARS = 16

# A link's hash is taken over newline-joined fields. Every other field is either
# drawn from a closed set or is JSON, which escapes its own newlines; `version`
# arrives from a command-line flag. Without this, a version string containing
# newlines could produce the same hash input as a different link.
VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}$")


def canonical(payload: dict) -> str:
    """Byte-stable JSON. The hash is over these exact bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def link_hash(version: str, seq: int, kind: str, prev_hash: Optional[str],
              payload: dict) -> str:
    if not VERSION_RE.match(version):
        raise ValueError(f"not a usable policy version: {version!r}")
    body = "\n".join([version, str(seq), kind, prev_hash or "", canonical(payload)])
    return hashlib.sha256(body.encode()).hexdigest()


def digest_rows(rows: Dict[str, str]) -> str:
    """Order-independent digest of a set of events AND their contents.

    Digesting the ids alone was enough to catch an inserted or deleted row and
    nothing else: an UPDATE that rewrote what the agent did, keeping the id,
    left the version attested. An adversarial pass changed a cited event's
    tool_name to `issue_refund` and its tenant to another tenant, and
    verification stayed green. The evidence a version cites is the content of
    those rows, so the content is what is hashed.
    """
    return hashlib.sha256(
        "\n".join(f"{k}:{rows[k]}" for k in sorted(rows)).encode()
    ).hexdigest()


COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def column_name(column: str) -> str:
    """The bare name of a `name:type` entry, refused unless it is an identifier.

    These names come out of a chain payload and are interpolated into SQL, which
    query parameters cannot carry: a column list is not a value. The hash walk
    proves nobody edited the payload after it was written. It does not prove
    that what was written is safe to concatenate, and the two are different
    claims.
    """
    name = column.split(":", 1)[0]
    if not COLUMN_RE.match(name):
        raise ValueError(f"not a usable column name: {name!r}")
    return name


def digest_schema(columns: Sequence[str]) -> str:
    """Digest of the conduct table's column list, in schema order.

    Order is not sorted away. `TO_JSON_STRING` renders a row in schema order, so
    reordering two columns changes every row digest, and a fingerprint that
    sorted its input would call that reorder no change at all.

    This exists so re-attestation can tell two causes apart. Adding a column
    moves the digest of every cited row, and so does editing one of them. The
    first is a schema change the operator made and the second is the tamper the
    chain exists to survive; without this they are the same EVENT-WINDOW break.
    """
    return hashlib.sha256("\n".join(columns).encode()).hexdigest()[:ROW_DIGEST_CHARS]


def _access_pairs(entries: Sequence[dict]) -> List[str]:
    """A dataset access list reduced to sorted `role:member` strings.

    Kept as its own function because the digest and the break message have to
    agree on what an entry is. If they disagree, a break names a principal that
    the digest never covered.
    """
    def member(e: dict) -> str:
        for key in ("userByEmail", "groupByEmail", "specialGroup", "iamMember", "domain"):
            if e.get(key):
                return f"{key}={e[key]}"
        # An authorized view or routine carries no member at all. Falling back to
        # the whole entry keeps two different ones from reducing to the same pair,
        # which would leave the digest blind to swapping one for the other.
        return canonical({k: v for k, v in sorted(e.items()) if k != "role"})

    return sorted(f"{e.get('role')}:{member(e)}" for e in entries)


def digest_access(entries: Sequence[dict]) -> str:
    """Digest of a BigQuery dataset access list.

    Reduced to (role, member) pairs and sorted, so the digest tracks who may read
    the exam and not the order the API happened to return them in. This is the
    substitute for the IAM deny policy the project cannot create: a later grant
    to the Proposer does not go unnoticed, it breaks the chain.
    """
    return hashlib.sha256("\n".join(_access_pairs(entries)).encode()).hexdigest()


# A dataset access list is not the only way to reach a table. A project-level
# IAM binding grants the same permission and never appears in the dataset's ACL,
# so hashing the ACL alone leaves "a later grant to the Proposer breaks the
# chain" false for the easier of the two ways to make that grant. This project
# demonstrates the gap itself: notary-sa reads the exam's metadata through a
# project-scoped role and is nowhere in the exam's access list.
#
# Matched rather than enumerated: every predefined BigQuery role, and every
# custom role, since a custom role's permissions are not knowable from its name.
# Roles outside this set cannot carry bigquery.tables.getData, so ordinary IAM
# churn does not quarantine a version.
# Which project-level roles could put a principal within reach of the sealed
# exam. The first version of this matched every `roles/bigquery.*` binding by
# name, which is not the same question. Granting roles/bigquery.jobUser to a
# detector quarantined every chain in the project, and reattest then refused to
# clear it, correctly, because clearing it would have recorded a widened access
# list as justified. A check that fires on grants which cannot read the exam
# does not make the exam safer; it makes the real signal unreadable.
#
# So the question asked is now the right one: does this role carry
# bigquery.tables.getData. A role that cannot be expanded still counts as
# reaching, so the failure direction is unchanged.
REACH_ROLE_RE = re.compile(r"^(roles/|projects/[^/]+/roles/|impersonate/)")

# The dataset whose readers are the exam's readers.
SEALED_DATASET = "holdout_sealed"

# Roles that let a principal act as a service account.
IMPERSONATION_ROLES = (
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityUser",
    "roles/owner",
    "roles/editor",
)


def _reach_pairs(bindings: Sequence[dict]) -> List[str]:
    """role:member for every binding handed in.

    The filtering happens in `Evidence.exam_reach`, which has the token needed
    to expand a role into its permissions. This function only formats, so the
    digest is a pure function of what the evidence source returned and the test
    double can hand it a list without a cloud project.
    """
    return sorted(
        f"{b.get('role')}:{member}"
        for b in bindings
        if REACH_ROLE_RE.match(b.get("role") or "")
        for member in b.get("members", [])
    )


def digest_reach(bindings: Sequence[dict]) -> str:
    return hashlib.sha256("\n".join(_reach_pairs(bindings)).encode()).hexdigest()


class Link:
    __slots__ = ("version", "seq", "kind", "payload", "prev_hash", "hash", "written_at")

    def __init__(self, version: str, seq: int, kind: str, payload: dict,
                 prev_hash: Optional[str], hash_: Optional[str] = None,
                 written_at: Optional[str] = None):
        if kind not in KINDS:
            raise ValueError(f"unknown link kind: {kind!r}")
        self.version = version
        self.seq = seq
        self.kind = kind
        self.payload = payload
        # Normalized to "" so a chain built in memory and a chain read back from
        # BigQuery, where NULL arrives as an empty string, walk identically.
        self.prev_hash = prev_hash or ""
        self.written_at = written_at
        # A stored hash is kept as stored. Recomputing it on load would make
        # every chain verify, which is the one thing this class must not do.
        self.hash = hash_ if hash_ is not None else self.recomputed()

    def recomputed(self) -> str:
        return link_hash(self.version, self.seq, self.kind, self.prev_hash, self.payload)

    def intact(self) -> bool:
        return self.hash == self.recomputed()

    def __repr__(self) -> str:
        return f"<Link {self.version} {self.seq} {self.kind} {self.hash[:12]}>"


def root_of(links: Sequence[Link]) -> Optional[str]:
    """The chain root is the last link's hash, which covers every link before it."""
    return links[-1].hash if links else None


def build(version: str, steps: Sequence[tuple]) -> List[Link]:
    """Hash a sequence of (kind, payload) into a chain. Used by seed and by tests."""
    links: List[Link] = []
    prev = None
    for seq, (kind, payload) in enumerate(steps, start=1):
        link = Link(version, seq, kind, payload, prev)
        links.append(link)
        prev = link.hash
    return links


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

class ChainStore:
    """The append-only chain table.

    Append-only is a convention here, not a platform guarantee: WRITER on the
    dataset carries DML delete. What makes an edit detectable is that the root is
    sealed into the retention-locked bucket, which refuses a delete from the
    project owner. THREATS.md carries this distinction rather than the README
    claiming a guarantee BigQuery does not give.
    """

    def __init__(self, project: str, token: str, dataset: str = "chain",
                 table: str = "links"):
        self.project = project
        self.token = token
        self.qualified = bq.qualified_table(project, dataset, table)
        self.dataset = dataset
        self.table = table

    def read(self, version: str) -> List[Link]:
        rows = bq.query(
            # `hash` is a reserved word in BigQuery, so the column is link_hash.
            f"SELECT version, seq, kind, prev_hash, link_hash, payload,"
            f" FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', written_at) AS written_at"
            f" FROM `{self.qualified}` WHERE version = @version ORDER BY seq",
            self.project, self.token, params={"version": version},
        )
        return [
            Link(r["version"], int(r["seq"]), r["kind"], json.loads(r["payload"]),
                 r["prev_hash"], r["link_hash"], r["written_at"])
            for r in rows
        ]

    def next_seq(self, version: str) -> int:
        rows = bq.query(
            f"SELECT IFNULL(MAX(seq), 0) AS n FROM `{self.qualified}` WHERE version = @version",
            self.project, self.token, params={"version": version},
        )
        return int(rows[0]["n"]) + 1

    def append(self, link: Link) -> None:
        bq.query(
            f"INSERT INTO `{self.qualified}`"
            f" (version, seq, kind, written_at, prev_hash, link_hash, payload)"
            f" VALUES (@version, @seq, @kind, CURRENT_TIMESTAMP(), @prev, @hash, @payload)",
            self.project, self.token,
            params={"version": link.version, "seq": link.seq, "kind": link.kind,
                    "prev": link.prev_hash or "", "hash": link.hash,
                    "payload": canonical(link.payload)},
        )

    def append_all(self, links: Sequence[Link]) -> None:
        for link in links:
            self.append(link)

    def versions(self) -> List[dict]:
        return bq.query(
            f"SELECT version, parent, active, root, certificate_uri,"
            f" FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', promoted_at) AS promoted_at, policy"
            f" FROM `{bq.qualified_table(self.project, 'policy', 'versions')}`"
            f" ORDER BY promoted_at",
            self.project, self.token,
        )

    def register(self, version: str, parent: Optional[str], policy_json: str,
                 root: str, certificate_uri: str) -> None:
        """Record the promoted version and the root that justifies it.

        On Day 4 the same root is written as an annotation on the version's Agent
        Registry entry, so the platform's own discovery layer carries the anchor.
        """
        target = bq.qualified_table(self.project, "policy", "versions")
        bq.query(
            f"DELETE FROM `{target}` WHERE version = @version",
            self.project, self.token, params={"version": version},
        )
        bq.query(
            f"UPDATE `{target}` SET active = FALSE WHERE active",
            self.project, self.token,
        )
        bq.query(
            f"INSERT INTO `{target}`"
            f" (version, parent, policy, active, root, certificate_uri, promoted_at)"
            f" VALUES (@version, @parent, @policy, TRUE, @root, @uri, CURRENT_TIMESTAMP())",
            self.project, self.token,
            params={"version": version, "parent": parent or "", "policy": policy_json,
                    "root": root, "uri": certificate_uri},
        )

    def repoint(self, version: str, root: str, certificate_uri: str) -> None:
        """Move a version's root to a new certificate, changing nothing else.

        Re-attestation used `register`, which marks the version it writes active
        and every other version inactive. Re-attesting an OLD version therefore
        put that version back in force: on Day 5 a re-attestation of v4, run as
        part of a proof, silently demoted the freshly promoted v5 and the fleet
        went back to enforcing v4. The Policy Server reported it truthfully,
        which is the only reason it was caught.

        Re-derivation must never change what is enforced. It changes what a
        version can claim, and promotion is the only thing that changes which
        version is in force.
        """
        target = bq.qualified_table(self.project, "policy", "versions")
        bq.query(
            f"UPDATE `{target}` SET root = @root, certificate_uri = @uri"
            f" WHERE version = @version",
            self.project, self.token,
            params={"version": version, "root": root, "uri": certificate_uri},
        )


# --------------------------------------------------------------------------
# The retention-locked seal
# --------------------------------------------------------------------------

def _impersonation(impersonate: Optional[str]) -> List[str]:
    return [f"--impersonate-service-account={impersonate}"] if impersonate else []


def seal(bucket: str, version: str, seq: int, root: str, links: Sequence[Link],
         impersonate: Optional[str] = None) -> str:
    """Write the root to the retention-locked bucket and return its URI.

    Written as notary-sa, which holds objectCreator and objectViewer on the
    bucket and not objectAdmin: the identity that seals a certificate cannot
    delete one.

    A new object per seal, never an overwrite: overwriting is a delete plus a
    create, and the retention policy refuses the delete. So a reattest adds a
    certificate beside the original rather than replacing it, and the original
    stays readable as the state the version was in before the evidence moved.
    """
    uri = f"gs://{bucket}/certificates/{version}/{seq:03d}-{root[:12]}.json"

    # The object name is content-addressed, so sealing the same chain twice
    # addresses the same object. Overwriting it is a delete plus a create, and
    # notary-sa holds objectCreator without objectAdmin: it cannot delete one.
    # That refusal is the design working, so a re-seal reads the existing
    # certificate instead of trying to replace it.
    existing = sealed_root(uri, impersonate)
    if existing is not None:
        if existing.get("root") != root:
            raise RuntimeError(
                f"{uri} already exists and seals root {existing.get('root')}, "
                f"not {root}; refusing to write a second certificate to that name")
        return uri

    body = json.dumps({
        "version": version,
        "seq": seq,
        "root": root,
        "links": [{"seq": l.seq, "kind": l.kind, "hash": l.hash} for l in links],
    }, indent=2)
    out = subprocess.run(["gcloud", "storage", "cp", "-", uri] + _impersonation(impersonate),
                         input=body, capture_output=True, text=True, env=bq.gcloud_env())
    if out.returncode != 0:
        raise RuntimeError(f"could not seal the root: {out.stderr.strip()}")
    return uri


GCS_OBJECT = "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{name}?alt=media"


def sealed_root(uri: str, impersonate: Optional[str] = None) -> Optional[dict]:
    """Read a sealed certificate back. None when the object is not there.

    Over REST rather than `gcloud storage cat`, because the deployed Policy
    Server reads certificates and a container has no gcloud. subprocess.run
    raises FileNotFoundError there, which surfaced as a version stuck in the
    unknown state with `No such file or directory: 'gcloud'` as its reason.
    Writing a certificate still goes through gcloud; only the Notary seals, and
    the Notary runs on a workstation.
    """
    if not uri.startswith("gs://"):
        return None
    bucket, _, name = uri[len("gs://"):].partition("/")
    if not bucket or not name:
        return None
    url = GCS_OBJECT.format(bucket=urllib.parse.quote(bucket, safe=""),
                            name=urllib.parse.quote(name, safe=""))
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + bq.access_token(impersonate)})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError:
        return None


# --------------------------------------------------------------------------
# Where verification re-derives from
# --------------------------------------------------------------------------

def row_digest(event: dict) -> str:
    """The local counterpart of the BigQuery row digest.

    The two are not comparable to each other, and do not need to be: a chain is
    re-derived by the same evidence source that recorded it. What both must do is
    change whenever any field of the row changes.
    """
    return hashlib.sha256(canonical(event).encode()).hexdigest()[:ROW_DIGEST_CHARS]


class Evidence:
    """The two reads and one re-score that verification needs.

    Two implementations: BigQueryEvidence against the warehouse, LocalEvidence
    against dicts so the state machine is testable without a cloud project. Both
    are held to the same interface by tests/test_chain.py.
    """

    def cited_events(self, dataset: str, start: str, end: str) -> Dict[str, str]:
        """Event id to a digest of that event's whole row."""
        raise NotImplementedError

    def schema_columns(self, dataset: str) -> List[str]:
        """The conduct table's columns as `name:type`, in schema order."""
        raise NotImplementedError

    def projected_events(self, dataset: str, start: str, end: str,
                         columns: Sequence[str]) -> Dict[str, str]:
        """Row digests computed over `columns` only, ignoring any others.

        This is what makes "the table gained a column" a provable claim rather
        than an assumed one. Under a schema change every whole-row digest moves,
        so comparing them says nothing; re-derived over the columns the chain
        was sealed against, an unedited row still digests to its sealed value
        and an edited one still does not.
        """
        raise NotImplementedError

    def access_list(self, dataset: str) -> List[dict]:
        raise NotImplementedError

    def exam_reach(self) -> List[dict]:
        """Project-level IAM bindings that could reach the sealed exam."""
        raise NotImplementedError

    def score(self, policy):
        """Returns an examiner.Score. Re-running the Examiner is what makes the
        EXAM link a derivation rather than a stored number."""
        raise NotImplementedError

    def widened(self, candidate, current) -> int:
        """Turns the candidate re-allows that the current version denies.

        The empirical cross-check on the structural monotonicity decision. The
        gate prints it, so it is measured here rather than assumed to be zero.
        """
        raise NotImplementedError


class BigQueryEvidence(Evidence):
    """Re-derives from the warehouse.

    The exam re-score runs as examiner-sa, which is the only principal that may
    read the sealed holdout. Everything else runs as the caller. Reading *who*
    may read the exam is bigquery.datasets.get, which is metadata and not data,
    so the Notary can check the access list and still be refused the rows in it.
    """

    def __init__(self, project: str, token: str, examiner_token: Optional[str] = None):
        self.project = project
        self.token = token
        self.examiner_token = examiner_token or token
        self._access_cache: Dict[str, List[dict]] = {}

    def cited_events(self, dataset: str, start: str, end: str) -> Dict[str, str]:
        # TO_JSON_STRING renders the row in schema order, so the digest is stable
        # across runs and changes whenever any column of the row changes. The
        # scan is bounded to the finding's window, which is the partition key.
        table = bq.qualified_table(self.project, dataset)
        rows = bq.query(
            f"SELECT event_id,"
            f" SUBSTR(TO_HEX(SHA256(TO_JSON_STRING(t))), 1, {ROW_DIGEST_CHARS}) AS row_digest"
            f" FROM `{table}` t"
            f" WHERE ts >= TIMESTAMP(@start) AND ts < TIMESTAMP(@end)"
            f" ORDER BY event_id",
            self.project, self.token, params={"start": start, "end": end},
        )
        return {r["event_id"]: r["row_digest"] for r in rows}

    def schema_columns(self, dataset: str) -> List[str]:
        # INFORMATION_SCHEMA rather than a tables.get, because the row digest
        # above is computed by BigQuery and this has to agree with what BigQuery
        # thinks the row is. ordinal_position is the order TO_JSON_STRING uses.
        rows = bq.query(
            f"SELECT column_name, data_type"
            f" FROM `{self.project}.{dataset}.INFORMATION_SCHEMA.COLUMNS`"
            f" WHERE table_name = 'turns'"
            f" ORDER BY ordinal_position",
            self.project, self.token,
        )
        return [f"{r['column_name']}:{r['data_type']}" for r in rows]

    def projected_events(self, dataset: str, start: str, end: str,
                         columns: Sequence[str]) -> Dict[str, str]:
        # TO_JSON_STRING(STRUCT(t.a, t.b, ...)) over the full column list in
        # schema order is byte-identical to TO_JSON_STRING(t): checked against
        # conduct_live, 43 rows, zero differing. So a projection onto the sealed
        # column list reproduces the sealed digest exactly.
        names = [column_name(c) for c in columns]
        table = bq.qualified_table(self.project, dataset)
        struct = ", ".join(f"t.{n}" for n in names)
        rows = bq.query(
            f"SELECT event_id,"
            f" SUBSTR(TO_HEX(SHA256(TO_JSON_STRING(STRUCT({struct})))), 1,"
            f" {ROW_DIGEST_CHARS}) AS row_digest"
            f" FROM `{table}` t"
            f" WHERE ts >= TIMESTAMP(@start) AND ts < TIMESTAMP(@end)"
            f" ORDER BY event_id",
            self.project, self.token, params={"start": start, "end": end},
        )
        return {r["event_id"]: r["row_digest"] for r in rows}

    def access_list(self, dataset: str) -> List[dict]:
        """The dataset's access list, read once per verification.

        Memoised because verification asks for it twice: once as the evidence
        link's own check, and once to find which service accounts to look up
        impersonation for. Two identical round trips inside a 5s budget is one
        too many.
        """
        cached = self._access_cache.get(dataset)
        if cached is None:
            cached = bq.get_dataset(self.project, dataset, self.token).get("access", [])
            self._access_cache[dataset] = cached
        return cached

    def exam_reach(self) -> List[dict]:
        """Project bindings whose role could read the sealed exam's rows.

        Filtered here, not by name in chain.py, because deciding whether a role
        reaches the exam means expanding it into its permissions and that needs
        a token. A role that cannot be expanded is kept, so the failure
        direction stays "assume it reaches".
        """
        # Two independent lookups, overlapped, because both run inside the
        # verify SLO. Expanding roles serially cost more than the whole rest of
        # verification; adding the impersonation lookup after it then pushed the
        # p95 to 5.81s, past the 5s the README publishes.
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            impersonation = pool.submit(self._impersonation_reach)
            bindings = bq.project_iam_bindings(self.project, self.token)
            roles = sorted({b.get("role") or "" for b in bindings})
            answers = dict(zip(roles, pool.map(
                lambda r: bq.reads_table_data(r, self.token), roles)))
            reaching = [b for b in bindings if answers.get(b.get("role") or "")]
            return reaching + impersonation.result()

    def _impersonation_reach(self) -> List[dict]:
        """Who can act as the principals the exam's access list names.

        A project binding is not the only way to reach a sealed table. Holding
        roles/iam.serviceAccountTokenCreator on its sole reader mints a token as
        that reader, and neither the dataset access list nor the project IAM
        policy shows it. An adversarial pass found this by naming the exact
        grant, and this project had a live instance of it.

        Returned as ordinary-looking bindings whose role names the impersonated
        account, so the digest covers them and a break says which account and
        which principal.
        """
        readers = sorted({
            entry.get("userByEmail") for entry in self.access_list(SEALED_DATASET)
            if str(entry.get("userByEmail", "")).endswith(".iam.gserviceaccount.com")
        })

        def one(reader: str) -> List[dict]:
            try:
                policy = bq.service_account_iam(reader, self.token)
            except Exception:
                # Unreadable, so unknown, so recorded as unknown rather than as
                # empty. An empty answer here reads as "nobody can impersonate
                # the exam's reader", which is a claim this could not check.
                return [{"role": f"impersonate/{reader}", "members": ["UNREADABLE"]}]
            return [{"role": f"impersonate/{reader}",
                     "members": sorted(binding.get("members", []))}
                    for binding in policy
                    if "TokenCreator" in binding.get("role", "")
                    or binding.get("role") in IMPERSONATION_ROLES]

        if not readers:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return [entry for group in pool.map(one, readers) for entry in group]

    def score(self, policy):
        from .examiner import score_bq
        return score_bq(policy, self.project, self.examiner_token)

    def widened(self, candidate, current) -> int:
        from .examiner import monotonic_bq
        _, count = monotonic_bq(candidate, current, self.project, self.examiner_token)
        return count


class LocalEvidence(Evidence):
    """Re-derives from dicts. The test double, and the offline path for CI."""

    def __init__(self, events: Dict[str, List[dict]], access: Dict[str, List[dict]],
                 reach: Optional[List[dict]] = None):
        self.events = events
        self.access = access
        self.reach = reach or []

    def cited_events(self, dataset: str, start: str, end: str) -> Dict[str, str]:
        return {
            e["event_id"]: row_digest(e)
            for e in self.events.get(dataset, [])
            if start <= e["ts"] < end
        }

    def schema_columns(self, dataset: str) -> List[str]:
        # A local row is a dict and `row_digest` canonicalises it, which sorts
        # the keys. So the local schema is the sorted union of the keys, and it
        # moves when a field is added exactly as the BigQuery one does. No types:
        # a dict has none, and inventing them would make the double disagree
        # with production about what a schema change is.
        return sorted({k for e in self.events.get(dataset, []) for k in e})

    def projected_events(self, dataset: str, start: str, end: str,
                         columns: Sequence[str]) -> Dict[str, str]:
        keep = {column_name(c) for c in columns}
        return {
            e["event_id"]: row_digest({k: v for k, v in e.items() if k in keep})
            for e in self.events.get(dataset, [])
            if start <= e["ts"] < end
        }

    def access_list(self, dataset: str) -> List[dict]:
        return self.access.get(dataset, [])

    def exam_reach(self) -> List[dict]:
        return self.reach

    def score(self, policy):
        from .examiner import local_corpora, score_local
        return score_local(policy, local_corpora())

    def widened(self, candidate, current) -> int:
        from .examiner import local_corpora, monotonic
        corpora = local_corpora()
        _, count = monotonic(
            candidate, current, corpora["benign_corpus"] + corpora["holdout_sealed"])
        return count
