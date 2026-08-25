#!/usr/bin/env python3
"""A very small BigQuery client: an access token and one POST.

Standard library plus the gcloud CLI, deliberately. The Examiner runs as
examiner-sa and its whole point is that a reviewer can read every line of it,
so the fewer moving parts between the compiled predicate and the service, the
better. The token is minted by impersonation and never printed.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from typing import List, Optional

API = "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/queries"

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


def access_token(impersonate: Optional[str] = None) -> str:
    cmd = ["gcloud", "auth", "print-access-token"]
    if impersonate:
        cmd.append(f"--impersonate-service-account={impersonate}")
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"could not mint a token: {out.stderr.strip()}")
    return out.stdout.strip()


def query(sql: str, project: str, token: str, location: str = "europe-west3") -> List[dict]:
    """Run a query, return rows as plain dicts of strings.

    Values come back as strings whatever the column type; the caller converts.
    That is BigQuery's REST encoding, not a shortcut here.
    """
    if not NAME_RE.match(project):
        raise ValueError(f"not a usable project id: {project!r}")
    body = json.dumps(
        {"query": sql, "useLegacySql": False, "location": location, "timeoutMs": 120_000}
    ).encode()
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
