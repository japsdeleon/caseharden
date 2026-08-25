#!/usr/bin/env python3
"""The certificate viewer: one chain rendered to a static HTML page.

No JavaScript, no framework, no server. The page is the attestation as it stood
when the page was written, which is the point: a certificate is a statement
about a moment, and the live state comes from the Policy Server instead.

usage: python -m caseharden.notary certificate --version v4 --out out/v4.html
"""

from __future__ import annotations

import html
from typing import Sequence

CSS = """
body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;
color:#c9d1d9;margin:0;padding:40px}
main{max-width:900px;margin:0 auto}
h1{font-size:19px;font-weight:600;margin:0 0 4px}
.sub{color:#8b949e;margin:0 0 28px}
.state{display:inline-block;padding:5px 12px;border-radius:4px;font-weight:600;
letter-spacing:.06em}
.attested{background:#16351f;color:#4ade80;border:1px solid #2ea043}
.quarantined{background:#3a1618;color:#f87171;border:1px solid #da3633}
.unknown{background:#3a2f13;color:#fbbf24;border:1px solid #9e6a03}
table{width:100%;border-collapse:collapse;margin:22px 0}
td{padding:9px 10px;border-bottom:1px solid #21262d;vertical-align:top}
td.seq{color:#6e7681;width:34px}
td.kind{width:170px}
td.mark{width:74px;font-weight:600}
.ok{color:#4ade80}.break{color:#f87171}.sup{color:#6e7681}
.mode{color:#6e7681;font-size:12px}
.root{word-break:break-all;color:#8b949e;margin-top:6px}
.note{color:#8b949e;border-left:2px solid #30363d;padding-left:12px;margin-top:26px}
"""

MARK_CLASS = {"OK": "ok", "BREAK": "break", "SUPERSEDED": "sup", "SKIPPED": "sup"}


def render(att, links: Sequence) -> str:
    e = html.escape
    rows = []
    hashes = {l.seq: l.hash for l in links}
    for r in att.results:
        cls = MARK_CLASS.get(r.status, "sup")
        rows.append(
            f'<tr><td class="seq">{r.seq}</td><td class="kind">{e(r.kind)}</td>'
            f'<td class="mark {cls}">{e(r.status)}</td>'
            f'<td>{e(r.detail)}<div class="mode">{e(r.mode)} &middot; '
            f'{e(hashes.get(r.seq, "")[:16])}</div></td></tr>'
        )
    banner = att.state.upper()
    if att.break_code:
        banner += f" &mdash; break at link {att.break_seq} {e(att.break_code)}"
    detail = f'<p class="root">{e(att.break_detail)}</p>' if att.break_detail else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Caseharden certificate {e(att.version)}</title><style>{CSS}</style></head>
<body><main>
<h1>conduct-policy@{e(att.version)}</h1>
<p class="sub">Provenance chain, re-derived in {att.elapsed_s:.1f}s</p>
<span class="state {att.state}">{banner}</span>
<table>{"".join(rows)}</table>
<p class="root">root {e(att.root or "none")}</p>
{detail}
<p class="note">Links marked <span class="ok">re-derived</span> were recomputed from the
warehouse as it stands now: the conduct events the finding cited, the access list of the
sealed exam, and the Examiner's measurements over that exam. Links marked
<span class="sup">recorded</span> are protected by the hash chain alone.
Quarantine withdraws this version's standing as justified and freezes promotion on top of
it. It does not stop the version enforcing.</p>
</main></body></html>
"""
