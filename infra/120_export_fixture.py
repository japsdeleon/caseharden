#!/usr/bin/env python3
"""Export one promoted version's chain and its sealed certificate, for offline re-checking.

The point of the fixture is that somebody who is not the entrant can check the
record. `caseharden verify` needs this project's BigQuery, this project's
holdout and two impersonated service accounts. Nobody outside the project can
run it, which makes every green line in this repo a claim about a machine only
one person has.

What this exports can be re-checked by anyone with the repository and a Python
interpreter: the link hashes, the walk, the root against the sealed certificate,
the chain's shape, and the Examiner's own measurements, replayed from the
committed seeded generator rather than from BigQuery. `caseharden/recheck.py`
does that, and a GitHub Action runs it on a clean checkout.

What it does NOT export, on purpose: the sealed holdout, and the conduct rows
themselves. The holdout stays sealed. The rows are already digested inside the
EVIDENCE link, and re-deriving a BigQuery digest offline would mean reproducing
`TO_JSON_STRING` byte for byte, which is a promise this repo does not make.

usage: python3 infra/120_export_fixture.py --version v5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from caseharden import bq, chain, creds
from caseharden.chain import ChainStore

REPO = Path(__file__).resolve().parent.parent


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", default=str(REPO / "fixtures"))
    args = parser.parse_args(argv)

    notary = f"notary-sa@{creds.PROJECT}.iam.gserviceaccount.com"
    token = bq.access_token(notary)
    store = ChainStore(creds.PROJECT, token)

    links = store.read(args.version)
    if not links:
        raise SystemExit(f"{args.version} has no chain")
    rows = [r for r in store.versions() if r["version"] == args.version]
    if not rows or not rows[0].get("certificate_uri"):
        raise SystemExit(f"{args.version} has no sealed certificate")
    certificate = chain.sealed_root(rows[0]["certificate_uri"], notary)
    if certificate is None:
        raise SystemExit(f"could not read {rows[0]['certificate_uri']}")

    out = Path(args.out) / args.version
    out.mkdir(parents=True, exist_ok=True)

    # One JSON object per line, in seq order, with the hash exactly as stored.
    # Not re-computed on the way out: a fixture that recomputes its own hashes
    # would verify no matter what the table holds.
    with (out / "chain.jsonl").open("w") as fh:
        for link in links:
            fh.write(json.dumps({
                "version": link.version,
                "seq": link.seq,
                "kind": link.kind,
                "prev_hash": link.prev_hash,
                "link_hash": link.hash,
                "written_at": link.written_at,
                "payload": link.payload,
            }, sort_keys=True) + "\n")

    (out / "certificate.json").write_text(json.dumps(certificate, indent=2) + "\n")
    (out / "source.json").write_text(json.dumps({
        "project": creds.PROJECT,
        "region": creds.REGION,
        "version": args.version,
        "parent": rows[0].get("parent"),
        "certificate_uri": rows[0]["certificate_uri"],
        "promoted_at": rows[0].get("promoted_at"),
        "exported_by": "infra/120_export_fixture.py",
        "note": ("The sealed holdout is not here and never will be. The Examiner's "
                 "numbers are re-derived offline from the committed seeded "
                 "generator, which produces the same corpora BigQuery was loaded "
                 "from."),
    }, indent=2) + "\n")

    print(f"wrote {out}/chain.jsonl        {len(links)} links")
    print(f"wrote {out}/certificate.json   root {certificate.get('root', '')[:16]}")
    print(f"wrote {out}/source.json")
    print()
    print(f"re-check it with no cloud access at all:")
    print(f"  python3 -m caseharden.recheck {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
