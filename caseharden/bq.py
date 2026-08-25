#!/usr/bin/env python3
"""A very small BigQuery client: an access token and one POST.

Standard library plus the gcloud CLI, deliberately. The Examiner runs as
examiner-sa and its whole point is that a reviewer can read every line of it,
so the fewer moving parts between the compiled predicate and the service, the
better. The token is minted by impersonation and never printed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

API = "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/queries"
DATASET_API = "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{dataset}"
INSERT_API = (
    "https://bigquery.googleapis.com/bigquery/v2/projects/{project}"
    "/datasets/{dataset}/tables/{table}/insertAll"
)

# A project or dataset name reaches both a URL and a backtick-quoted SQL
# identifier. The DSL's own literals are constrained at parse time, but these
# arrive from a command-line flag or an environment variable, and a backtick in
# one closes the identifier and appends whatever follows to the query.
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,60}[a-z0-9]$")


def qualified_table(project: str, dataset: str, table: str = "turns") -> str:
    for part in (project, dataset, table):
        if not NAME_RE.match(part):
            raise ValueError(f"not a usable BigQuery name: {part!r}")
    return f"{project}.{dataset}.{table}"


class IncompleteResult(RuntimeError):
    """The response carried no error and also no complete answer.

    jobs.query returns jobComplete=false with no rows and no error when the
    query outruns timeoutMs, and returns a pageToken when there are more rows
    than one response carries. Both look exactly like "nothing matched" to a
    caller that only reads `rows`, and "nothing matched" on the benign corpus is
    a 100 percent pass rate. The gate would promote an over-blocking candidate on
    a timeout, so neither case is allowed to return quietly.
    """


class BigQueryError(RuntimeError):
    """A refusal from BigQuery, carried verbatim.

    The 403 on the sealed holdout is evidence the chain records, so the
    service's own words are kept rather than paraphrased.
    """

    def __init__(self, payload: dict):
        self.payload = payload
        error = payload.get("error", {})
        super().__init__(f"HTTP {error.get('code')} {error.get('status')}: {error.get('message')}")


# Every gcloud call this package makes is pinned to one named configuration.
# The machine that builds this has other gcloud configurations on it, and the
# active one is not this project. Without the pin, a token minted from a shell
# that did not source infra/env.sh is a token for whatever account happened to be
# active. Set CASEHARDEN_GCLOUD_CONFIG to use a different one.
GCLOUD_CONFIG = os.environ.get("CASEHARDEN_GCLOUD_CONFIG", "caseharden")


def gcloud_env() -> dict:
    return dict(os.environ, CLOUDSDK_ACTIVE_CONFIG_NAME=GCLOUD_CONFIG)


def access_token(impersonate: Optional[str] = None) -> str:
    """A token, for this identity or for one it may impersonate.

    Inside a container there is no gcloud and no impersonation: the attached
    service account is the identity, full stop. A caller that asks for a
    different one is told so rather than quietly handed the attached token,
    because being handed the wrong identity is how a service ends up believing
    it verified something it never had the access to verify.
    """
    from . import creds

    if creds.on_cloud_run():
        attached = creds.attached_service_account()
        if impersonate and impersonate != attached:
            raise RuntimeError(
                f"this container runs as {attached}; it cannot act as "
                f"{impersonate}. Deploy it under the identity it needs.")
        return creds.access_token()

    cmd = ["gcloud", "auth", "print-access-token"]
    if impersonate:
        cmd.append(f"--impersonate-service-account={impersonate}")
    out = subprocess.run(cmd, capture_output=True, text=True, env=gcloud_env())
    if out.returncode != 0:
        raise RuntimeError(f"could not mint a token: {out.stderr.strip()}")
    return out.stdout.strip()


_PARAM_TYPES = {bool: "BOOL", int: "INT64", float: "FLOAT64", str: "STRING"}


def _parameters(params: dict) -> List[dict]:
    """Named query parameters, so a payload never reaches the SQL text.

    The chain writes JSON documents containing quotes, newlines and whatever the
    Proposer produced. Interpolating those into an INSERT is how a payload
    becomes a statement. Everything the Notary writes goes through here.
    """
    out = []
    for name, value in sorted(params.items()):
        kind = _PARAM_TYPES.get(type(value))
        if kind is None:
            raise ValueError(f"parameter {name!r} has unsupported type {type(value).__name__}")
        out.append({
            "name": name,
            "parameterType": {"type": kind},
            "parameterValue": {"value": None if value is None else str(value).lower()
                               if kind == "BOOL" else str(value)},
        })
    return out


def query(sql: str, project: str, token: str, location: str = "europe-west3",
          params: Optional[dict] = None) -> List[dict]:
    """Run a query, return rows as plain dicts of strings.

    Values come back as strings whatever the column type; the caller converts.
    That is BigQuery's REST encoding, not a shortcut here.
    """
    if not NAME_RE.match(project):
        raise ValueError(f"not a usable project id: {project!r}")
    request_body = {
        "query": sql, "useLegacySql": False, "location": location, "timeoutMs": 120_000,
    }
    if params:
        request_body["parameterMode"] = "NAMED"
        request_body["queryParameters"] = _parameters(params)
    body = json.dumps(request_body).encode()
    request = urllib.request.Request(
        API.format(project=project),
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None
    if "error" in payload:
        raise BigQueryError(payload)
    if not payload.get("jobComplete", False):
        raise IncompleteResult("BigQuery did not finish the query within timeoutMs")
    if payload.get("pageToken"):
        raise IncompleteResult("BigQuery returned a partial page; this client does not paginate")
    fields = [f["name"] for f in payload.get("schema", {}).get("fields", [])]
    return [dict(zip(fields, [cell["v"] for cell in row["f"]])) for row in payload.get("rows", [])]


def _decode(field: dict, cell: dict):
    """One BigQuery REST cell, using its schema field.

    The wire format nests: a repeated column arrives as a list of cells, a
    record as an object with its own `f`. `query` above flattens everything to
    strings, which is right for the scalar-only queries the Notary runs and
    wrong for a detector that aggregates event ids into an array.
    """
    value = cell.get("v")
    if field.get("mode") == "REPEATED":
        inner = dict(field, mode="NULLABLE")
        return [_decode(inner, item) for item in (value or [])]
    if field.get("type") == "RECORD":
        if value is None:
            return None
        sub = field.get("fields", [])
        return {f["name"]: _decode(f, c) for f, c in zip(sub, value.get("f", []))}
    return value


def query_job(sql: str, project: str, token: str, location: str = "europe-west3",
              params: Optional[dict] = None, timeout_ms: int = 120_000):
    """Like `query`, but returns the job id alongside the rows, and decodes arrays.

    The job id is the point. A detector's finding is only re-checkable if a
    reviewer can re-run the exact job that produced it, so the id travels into
    the chain's FINDING link rather than staying in a log line.
    """
    if not NAME_RE.match(project):
        raise ValueError(f"not a usable project id: {project!r}")
    request_body = {
        "query": sql, "useLegacySql": False, "location": location,
        "timeoutMs": timeout_ms,
    }
    if params:
        request_body["parameterMode"] = "NAMED"
        request_body["queryParameters"] = _parameters(params)
    request = urllib.request.Request(
        API.format(project=project),
        data=json.dumps(request_body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None
    if "error" in payload:
        raise BigQueryError(payload)
    if not payload.get("jobComplete", False):
        raise IncompleteResult("BigQuery did not finish the query within timeoutMs")
    if payload.get("pageToken"):
        raise IncompleteResult("BigQuery returned a partial page; this client does not paginate")
    fields = payload.get("schema", {}).get("fields", [])
    rows = [
        {f["name"]: _decode(f, c) for f, c in zip(fields, row.get("f", []))}
        for row in payload.get("rows", [])
    ]
    reference = payload.get("jobReference") or {}
    job_id = reference.get("jobId", "")
    if reference.get("location") and job_id:
        job_id = f"{reference['location']}:{job_id}"
    return rows, job_id


def get_dataset(project: str, dataset: str, token: str) -> dict:
    """Dataset metadata, including its access list.

    A REST call with the caller's own token rather than a shell out to `bq`,
    which would use whatever gcloud credentials happen to be ambient. The Notary
    runs on Cloud Run with no gcloud at all, and the identity that reads the
    access list has to be the identity the chain claims read it.

    datasets.get is metadata. It does not carry tables.getData, so this succeeds
    for the Notary on holdout_sealed while a read of the rows still returns 403.
    """
    for part in (project, dataset):
        if not NAME_RE.match(part):
            raise ValueError(f"not a usable BigQuery name: {part!r}")
    request = urllib.request.Request(
        DATASET_API.format(project=project, dataset=dataset),
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None


IAM_API = ("https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy")


def project_iam_bindings(project: str, token: str) -> List[dict]:
    """The project's IAM bindings.

    Needs resourcemanager.projects.getIamPolicy, which is granted to notary-sa
    through a custom role carrying that one permission. Reading who holds which
    role is not reading any data.
    """
    if not NAME_RE.match(project):
        raise ValueError(f"not a usable project id: {project!r}")
    request = urllib.request.Request(
        IAM_API.format(project=project), data=b"{}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response).get("bindings", [])
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None


ROLE_API = "https://iam.googleapis.com/v1/{role}"
# The permission that reads table rows. A role that does not carry it cannot read
# the sealed exam, whatever else it can do.
EXAM_READ_PERMISSION = "bigquery.tables.getData"


def role_permissions(role: str, token: str) -> Optional[List[str]]:
    """The permissions a role carries, or None when they cannot be read.

    None is not an empty list. A caller that cannot expand a role has to treat
    it as reaching, because assuming a role it could not read is harmless is how
    a widening goes unnoticed.
    """
    if not re.match(r"^(roles/[A-Za-z0-9_.]+|projects/[a-z0-9-]+/roles/[A-Za-z0-9_.]+)$", role):
        return None
    request = urllib.request.Request(
        ROLE_API.format(role=role),
        headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return list(json.load(response).get("includedPermissions", []))
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return None


# owner, editor and viewer all read table data, and roles.get does not say so:
# it answers for them with a permission list that omits it. Expanding them and
# believing the answer produced `roles/owner reaches=False`, which is exactly
# backwards and would have hidden the widest grant in the project.
BASIC_ROLES = ("roles/owner", "roles/editor", "roles/viewer")


# A PREDEFINED role's permissions are fixed by Google, so one process never
# needs to expand the same one twice. Without this, verify made one serial API
# round trip per distinct binding and went from 2.9s to 16.7s.
#
# A CUSTOM role is not fixed. Its permission set is editable at any time, so
# caching it lets a widening stay invisible for the life of the process: grant a
# harmless custom role to a principal, then add bigquery.tables.getData to that
# role, and a long-running Policy Server keeps excluding the binding and keeps
# serving `attested`. Custom roles are re-expanded every time.
_ROLE_CACHE: dict = {}


def _cacheable(role: str) -> bool:
    """Predefined roles only. projects/*/roles/* and organizations/*/roles/* are not."""
    return role.startswith("roles/")


def reads_table_data(role: str, token: str, cache: Optional[dict] = None) -> bool:
    """Whether this role could read table rows. Unknown counts as yes."""
    if cache is not None and role in cache:
        return cache[role]
    if _cacheable(role) and role in _ROLE_CACHE:
        answer = _ROLE_CACHE[role]
        if cache is not None:
            cache[role] = answer
        return answer
    if role in BASIC_ROLES:
        answer = True
    else:
        permissions = role_permissions(role, token)
        # Unexpandable, so unknown, so treated as reaching. A caller without
        # iam.roles.get sees every custom role as a possible reader, which is
        # noisy and safe, in that order.
        answer = permissions is None or EXAM_READ_PERMISSION in permissions
    if _cacheable(role):
        _ROLE_CACHE[role] = answer
    if cache is not None:
        cache[role] = answer
    return answer


SA_IAM_API = ("https://iam.googleapis.com/v1/projects/-/serviceAccounts/"
              "{email}:getIamPolicy")


def service_account_iam(email: str, token: str) -> List[dict]:
    """Who may act as this service account.

    A second route to a sealed table that a dataset access list cannot show and
    a project IAM binding does not describe: hold
    roles/iam.serviceAccountTokenCreator on the one principal that may read the
    exam and you can mint a token as it. The access list still says one reader,
    truthfully, and it is no longer the whole answer.
    """
    if not re.match(r"^[a-z0-9-]{1,100}@[a-z0-9.-]{1,120}$", email):
        raise ValueError(f"not a usable service account address: {email!r}")
    request = urllib.request.Request(
        SA_IAM_API.format(email=urllib.parse.quote(email, safe="")), data=b"{}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response).get("bindings", [])
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None


def insert_rows(rows: List[dict], project: str, dataset: str, table: str, token: str) -> None:
    """Streaming insert. The tamper path, and nothing else here uses it.

    tabledata.insertAll answers 200 with an `insertErrors` array rather than an
    HTTP error when individual rows are rejected, so a caller reading only the
    status code records a tamper that never landed and then reports a chain that
    verifies as proof of nothing.
    """
    for part in (project, dataset, table):
        if not NAME_RE.match(part):
            raise ValueError(f"not a usable BigQuery name: {part!r}")
    body = json.dumps({"rows": [{"json": r} for r in rows]}).encode()
    request = urllib.request.Request(
        INSERT_API.format(project=project, dataset=dataset, table=table),
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise BigQueryError(json.load(exc)) from None
    if payload.get("insertErrors"):
        raise BigQueryError({"error": {"code": 400, "status": "INSERT_ERRORS",
                                       "message": json.dumps(payload["insertErrors"])}})
