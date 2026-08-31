#!/usr/bin/env python3
"""Emit docs/architecture.svg.

The diagram is generated rather than drawn, for the same reason the corpora are:
an asset nobody can regenerate is an asset nobody can check. Run from the repo
root. docs/architecture.png is rendered from the SVG, and the README uses the SVG.
"""
import html, pathlib

W, H = 1560, 1130
BLUE, DEEP, RED, YEL, GRN = "#4285F4", "#1A73E8", "#EA4335", "#FBBC04", "#34A853"
INK, MUTE, LINE, PANEL, BG = "#202124", "#5F6368", "#DADCE0", "#FFFFFF", "#F1F3F4"
FONT = "'Google Sans','Roboto',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
o = []
def add(s): o.append(s)

def esc(t): return html.escape(t, quote=True)

def panel(x, y, w, h, label, accent=BLUE):
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{PANEL}" '
        f'stroke="{LINE}" stroke-width="1.5"/>')
    add(f'<rect x="{x}" y="{y}" width="{w}" height="4" rx="2" fill="{accent}"/>')
    add(f'<text x="{x+18}" y="{y+27}" font-family="{FONT}" font-size="12.5" '
        f'font-weight="600" fill="{MUTE}" letter-spacing="0.8">{esc(label)}</text>')

def node(x, y, w, h, icon, title, sub="", note="", accent=BLUE, dashed=False):
    dash = ' stroke-dasharray="5 4"' if dashed else ''
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#FFFFFF" '
        f'stroke="{accent if dashed else LINE}" stroke-width="{2 if dashed else 1.3}"{dash}/>')
    add(f'<use href="#{icon}" x="{x+16}" y="{y+16}"/>')
    tx = x + 60
    add(f'<text x="{tx}" y="{y+32}" font-family="{FONT}" font-size="14.5" '
        f'font-weight="600" fill="{INK}">{esc(title)}</text>')
    if sub:
        add(f'<text x="{tx}" y="{y+51}" font-family="{FONT}" font-size="11.5" '
            f'fill="{MUTE}">{esc(sub)}</text>')
    if note:
        add(f'<text x="{tx}" y="{y+69}" font-family="{FONT}" font-size="11.5" '
            f'fill="{accent}" font-weight="600">{esc(note)}</text>')

def edge(d, color=MUTE, dashed=False, width=1.6):
    dash = ' stroke-dasharray="6 5"' if dashed else ''
    head = "arrow-red" if color == RED else ("arrow-grn" if color == GRN else "arrow")
    add(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{dash} '
        f'stroke-linejoin="round" marker-end="url(#{head})"/>')

def label(x, y, text, color=INK, size=11.5, weight="500"):
    w = len(text) * size * 0.53 + 14
    add(f'<rect x="{x-w/2}" y="{y-11}" width="{w}" height="20" rx="10" fill="#FFFFFF" '
        f'stroke="{LINE}" stroke-width="1"/>')
    add(f'<text x="{x}" y="{y+3.5}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{color}" text-anchor="middle">{esc(text)}</text>')

# ---------- icons, stylised in Google Cloud's palette ----------
add(f'''<defs>
<marker id="arrow" markerWidth="9" markerHeight="9" refX="7.5" refY="3.2" orient="auto">
  <path d="M0,0 L7.5,3.2 L0,6.4 z" fill="{MUTE}"/></marker>
<marker id="arrow-red" markerWidth="9" markerHeight="9" refX="7.5" refY="3.2" orient="auto">
  <path d="M0,0 L7.5,3.2 L0,6.4 z" fill="{RED}"/></marker>
<marker id="arrow-grn" markerWidth="9" markerHeight="9" refX="7.5" refY="3.2" orient="auto">
  <path d="M0,0 L7.5,3.2 L0,6.4 z" fill="{GRN}"/></marker>

<g id="ic-run">
  <rect width="34" height="34" rx="8" fill="#E8F0FE"/>
  <path d="M9 10 L9 24 L19 17 Z" fill="{BLUE}"/>
  <circle cx="24" cy="12.5" r="2.4" fill="{DEEP}"/>
  <circle cx="24" cy="17" r="2.4" fill="{DEEP}"/>
  <circle cx="24" cy="21.5" r="2.4" fill="{DEEP}"/>
</g>
<g id="ic-bq">
  <rect width="34" height="34" rx="8" fill="#E8F0FE"/>
  <circle cx="16" cy="16" r="8.5" fill="none" stroke="{BLUE}" stroke-width="2.6"/>
  <rect x="14.6" y="11" width="2.8" height="10" rx="1.4" fill="{DEEP}"/>
  <rect x="19" y="14" width="2.8" height="7" rx="1.4" fill="{DEEP}"/>
  <path d="M22 22 L27 27" stroke="{BLUE}" stroke-width="2.8" stroke-linecap="round"/>
</g>
<g id="ic-bq-sealed">
  <rect width="34" height="34" rx="8" fill="#FCE8E6"/>
  <circle cx="16" cy="16" r="8.5" fill="none" stroke="{RED}" stroke-width="2.6"/>
  <rect x="14.6" y="11" width="2.8" height="10" rx="1.4" fill="{RED}"/>
  <rect x="19" y="14" width="2.8" height="7" rx="1.4" fill="{RED}"/>
  <path d="M22 22 L27 27" stroke="{RED}" stroke-width="2.8" stroke-linecap="round"/>
</g>
<g id="ic-gcs">
  <rect width="34" height="34" rx="8" fill="#FEF7E0"/>
  <path d="M8 11 H26 L23.5 25 H10.5 Z" fill="none" stroke="#F9AB00" stroke-width="2.4"
        stroke-linejoin="round"/>
  <rect x="12" y="15.5" width="10" height="2.6" rx="1.3" fill="#F9AB00"/>
  <path d="M17 19.5 v4 M14.6 21.6 h4.8" stroke="#EA8600" stroke-width="2" stroke-linecap="round"/>
</g>
<g id="ic-armor">
  <rect width="34" height="34" rx="8" fill="#FCE8E6"/>
  <path d="M17 8 L25 11.5 V17 c0 5-3.4 8.2-8 9.6 -4.6-1.4-8-4.6-8-9.6 V11.5 Z"
        fill="none" stroke="{RED}" stroke-width="2.3" stroke-linejoin="round"/>
  <path d="M13.4 17.2 l2.6 2.6 l4.8-5.2" fill="none" stroke="{RED}" stroke-width="2.3"
        stroke-linecap="round" stroke-linejoin="round"/>
</g>
<g id="ic-hex">
  <rect width="34" height="34" rx="8" fill="#E6F4EA"/>
  <path d="M17 8 L24.8 12.5 V21.5 L17 26 L9.2 21.5 V12.5 Z" fill="none"
        stroke="{GRN}" stroke-width="2.3" stroke-linejoin="round"/>
  <circle cx="17" cy="17" r="3.2" fill="{GRN}"/>
</g>
<g id="ic-brain">
  <rect width="34" height="34" rx="8" fill="#E6F4EA"/>
  <circle cx="12" cy="13" r="3.1" fill="none" stroke="{GRN}" stroke-width="2.1"/>
  <circle cx="22" cy="13" r="3.1" fill="none" stroke="{GRN}" stroke-width="2.1"/>
  <circle cx="17" cy="22" r="3.1" fill="none" stroke="{GRN}" stroke-width="2.1"/>
  <path d="M14.6 14.8 L15.6 19.4 M19.4 14.8 L18.4 19.4 M15.1 13 h3.8"
        stroke="{GRN}" stroke-width="1.9" stroke-linecap="round"/>
</g>
<g id="ic-trace">
  <rect width="34" height="34" rx="8" fill="#E8F0FE"/>
  <path d="M9 22 L15 15 L20 19 L26 11" fill="none" stroke="{BLUE}" stroke-width="2.3"
        stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="9" cy="22" r="2.3" fill="{DEEP}"/><circle cx="15" cy="15" r="2.3" fill="{DEEP}"/>
  <circle cx="20" cy="19" r="2.3" fill="{DEEP}"/><circle cx="26" cy="11" r="2.3" fill="{DEEP}"/>
</g>
<g id="ic-iam">
  <rect width="34" height="34" rx="8" fill="#FEF7E0"/>
  <circle cx="17" cy="13.5" r="4" fill="none" stroke="#F9AB00" stroke-width="2.3"/>
  <path d="M9.5 26 c0-4.4 3.4-7.2 7.5-7.2 s7.5 2.8 7.5 7.2" fill="none"
        stroke="#F9AB00" stroke-width="2.3" stroke-linecap="round"/>
</g>
<g id="ic-build">
  <rect width="34" height="34" rx="8" fill="#E8F0FE"/>
  <rect x="9" y="12" width="16" height="11" rx="2.4" fill="none" stroke="{BLUE}" stroke-width="2.2"/>
  <path d="M13 12 V9.5 h8 V12" fill="none" stroke="{BLUE}" stroke-width="2.2"/>
  <path d="M13 17.5 h8" stroke="{DEEP}" stroke-width="2.2" stroke-linecap="round"/>
</g>
<g id="ic-console">
  <rect width="34" height="34" rx="8" fill="{BG}"/>
  <rect x="7.5" y="10" width="19" height="13" rx="2.2" fill="none" stroke="{MUTE}" stroke-width="2.2"/>
  <path d="M5 26 h24" stroke="{MUTE}" stroke-width="2.2" stroke-linecap="round"/>
  <path d="M11 14.5 l3 2.2 l-3 2.2" fill="none" stroke="{MUTE}" stroke-width="1.9"
        stroke-linecap="round" stroke-linejoin="round"/>
</g>
</defs>''')

add(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
add(f'<text x="40" y="46" font-family="{FONT}" font-size="26" font-weight="700" '
    f'fill="{INK}">Caseharden</text>')
add(f'<text x="40" y="70" font-family="{FONT}" font-size="13.5" fill="{MUTE}">'
    f'One Google Cloud project, europe-west3. Every Cloud Run service is private, '
    f'deployed --no-allow-unauthenticated.</text>')

panel(30, 100, 250, 275, "THE HUMAN", MUTE)
panel(310, 100, 710, 265, "THE GOVERNED FLEET", BLUE)
panel(310, 520, 710, 150, "THE GOVERNANCE PLANE", BLUE)
panel(310, 705, 710, 148, "THE RECORD", MUTE)
panel(1110, 100, 420, 512, "THE EVIDENCE", YEL)

node(48, 150, 214, 88, "ic-console", "review console", "runs on the analyst's",
     "own machine", MUTE)
node(48, 265, 214, 88, "ic-run", "Analyst Copilot", "ADK web UI", "analyst-sa")

node(330, 145, 320, 88, "ic-run", "Foreman", "orchestrator", "foreman-sa")
node(680, 145, 320, 88, "ic-run", "support agent", "the customer-facing workload",
     "workload-sa")
node(330, 262, 320, 88, "ic-run", "4 detectors", "one image, four families", "detector-sa")
node(680, 262, 320, 88, "ic-run", "Proposer", "drafts candidate policy", "proposer-sa")

node(430, 395, 320, 88, "ic-armor", "Model Armor", "screens the turn before",
     "the policy is evaluated", RED)

node(330, 565, 206, 88, "ic-run", "Policy Server", "serves and attests", "examiner-sa")
node(561, 565, 206, 88, "ic-run", "Examiner", "deterministic", "no model call")
node(792, 565, 206, 88, "ic-run", "Notary", "writes the chain", "notary-sa")

node(330, 748, 206, 88, "ic-bq", "chain.links", "BigQuery", "append-only")
node(561, 748, 206, 88, "ic-bq", "review.decisions", "BigQuery", "the human's rows")
node(792, 748, 206, 88, "ic-gcs", "sealed root", "Cloud Storage", "retention-locked")

node(1130, 150, 380, 88, "ic-bq", "conduct_live", "BigQuery",
     "every turn, with its ma_verdict")
node(1130, 270, 380, 88, "ic-bq", "conduct_train", "BigQuery", "the Proposer may read this")
node(1130, 390, 380, 88, "ic-bq-sealed", "holdout_sealed", "BigQuery",
     "one reader: examiner-sa", RED, dashed=True)
for i, t in enumerate([
        "The sealed exam has exactly one entry in its access",
        "list, and that list is hashed into the chain. Granting",
        "the Proposer access later breaks the chain instead",
        "of going unnoticed."]):
    add(f'<text x="1130" y="{525 + i*19}" font-family="{FONT}" font-size="11.5" '
        f'fill="{MUTE}">{esc(t)}</text>')

for i, (ic, t, sb) in enumerate([
        ("ic-hex", "Agent Registry", "7 agents, each with a chain root"),
        ("ic-brain", "Agent Engine", "Memory Bank"),
        ("ic-trace", "Cloud Trace", "one trace per fan-out"),
        ("ic-iam", "IAM", "8 service accounts"),
        ("ic-build", "Cloud Build", "and Artifact Registry")]):
    node(30 + i * 304, 910, 284, 76, ic, t, sb, "", MUTE)

# the support agent's three steps, in the order enforcement.py fixes them
edge("M680,189 H660 V370 H590 V395", RED, width=2)
label(660, 340, "1  screens the turn", RED, weight="600")

edge("M680,196 H668 V505 H510 V565")
label(600, 505, "2  evaluate the active policy")

edge("M1000,189 H1130")
label(1063, 189, "3  record the turn")

edge("M262,309 H340 V439 H430", RED)
label(340, 392, "the verdict text", RED, weight="600")

edge("M155,238 V265")
edge("M155,353 V875 H664 V836")
label(430, 875, "the Copilot writes the row, the console does not")

edge("M490,233 V262")
label(490, 247, "A2A fan-out")

edge("M330,189 H295 V948 H314")
label(295, 690, "list_agents()")

edge("M490,350 V380 H1032 V194 H1130")
label(760, 380, "governed SQL")

edge("M1000,300 H1050 V314 H1130")
label(1090, 314, "SELECT")

edge("M1000,330 H1068 V412 H1130", RED, dashed=True, width=2)
label(1064, 376, "403, recorded as a link", RED, weight="600")

edge("M536,609 H561")

edge("M664,653 V690 H1086 V455 H1130", GRN)
label(870, 690, "the only reader", GRN, weight="600")

edge("M433,653 V748")
label(433, 684, "re-derives at serve time")

edge("M895,653 V720 H370 V748")

edge("M935,653 V737 H664 V748")
label(800, 737, "reads the human's rows")

edge("M975,653 V705 H895 V748")

add(f'<rect x="1150" y="1000" width="380" height="80" rx="10" fill="#FFFFFF" '
    f'stroke="{LINE}" stroke-width="1.3"/>')
add(f'<path d="M1172,1030 h34" stroke="{MUTE}" stroke-width="1.8" marker-end="url(#arrow)"/>')
add(f'<text x="1216" y="1034" font-family="{FONT}" font-size="11.5" fill="{INK}">'
    f'permitted, and recorded</text>')
add(f'<path d="M1172,1058 h34" stroke="{RED}" stroke-width="2" stroke-dasharray="6 5" '
    f'marker-end="url(#arrow-red)"/>')
add(f'<text x="1216" y="1062" font-family="{FONT}" font-size="11.5" fill="{INK}">'
    f'refused, and recorded as a link</text>')

add(f'<text x="30" y="1025" font-family="{FONT}" font-size="12.5" font-weight="600" '
    f'fill="{INK}">Screening runs before the policy, because the policy can key on '
    f'its verdict.</text>')
add(f'<text x="30" y="1047" font-family="{FONT}" font-size="12" fill="{MUTE}">'
    f'ma_verdict is a predicate in the policy DSL, so a turn that was not screened is '
    f'not the same as one that screened clean. When a policy keys on</text>')
add(f'<text x="30" y="1065" font-family="{FONT}" font-size="12" fill="{MUTE}">'
    f'screening and Model Armor is unavailable, the call is refused with '
    f'SCREENING-UNAVAILABLE rather than allowed.</text>')
add(f'<text x="30" y="1092" font-family="{FONT}" font-size="12" fill="{MUTE}">'
    f'Two guarantees sit outside this code: BigQuery IAM produces the 403, a Cloud '
    f'Storage retention lock refuses the owner\u2019s delete. infra/70_prove_seal.sh and</text>')
add(f'<text x="30" y="1110" font-family="{FONT}" font-size="12" fill="{MUTE}">'
    f'infra/71_prove_immutability.sh assert them, and exit non-zero if either stops '
    f'holding. Icons are stylised in Google Cloud\u2019s palette, not the official set.</text>')

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
       f'viewBox="0 0 {W} {H}" role="img" aria-label="Caseharden architecture">\n'
       + "\n".join(o) + "\n</svg>\n")
pathlib.Path("docs/architecture.svg").write_text(svg)
print(f"wrote docs/architecture.svg  {len(svg)} bytes")
