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
