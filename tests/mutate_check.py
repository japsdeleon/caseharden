"""Break each attestation property in the source, and confirm the suite notices.

A passing suite says the tests agree with the code. It does not say the tests
would notice if the code stopped doing what it claims. Two adversarial passes
found assertions here that were vacuous, and one of them was vacuous twice over,
so each property is broken on purpose and the suite is re-run against the break.

The counterpart to generator/mutate_check.py, which does the same for the corpus.

run:  python3 tests/mutate_check.py     (exits non-zero if any mutation survives)
"""
import pathlib, subprocess, sys

CASES = [
 ("notary.py", "    if sealed is None:\n        return done(QUARANTINED, results, NO_CERTIFICATE, links[-1].seq,",
  "    if False:\n        return done(QUARANTINED, results, NO_CERTIFICATE, links[-1].seq,",
  "a chain with no sealed certificate attests"),
 ("chain.py", 'VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}$")',
  'VERSION_RE = re.compile(r"^.*$", re.S)', "a version string can forge a link hash"),
 ("chain.py", 'return sorted(f"{e.get(\'role\')}:{member(e)}" for e in entries)',
  'return sorted(f"{e.get(\'role\')}:x" for e in entries)', "access entries collapse to one string"),
 ("chain.py", '"\\n".join(f"{k}:{rows[k]}" for k in sorted(rows)).encode()',
  '"\\n".join(sorted(rows)).encode()', "cited event contents are not hashed"),
 ("notary.py", "    shape = _required_shape(links)\n    if shape:", "    shape = None\n    if shape:",
  "the chain grammar is not required"),
 ("notary.py", '    for required in ("EXAM", "APPROVAL"):', '    for required in ():',
  "an exam and an approval are not required"),
 ("notary.py", "                _shape_of_payload(link)", "                pass",
  "payload shapes are not checked"),
 ("policy_server.py", "            if current is None or started > current[0]:", "            if True:",
  "a stale refresh overwrites a newer one"),
 ("notary.py", 'altered = sorted(k for k in set(actual) & set(stored) if actual[k] != stored[k])',
  'altered = []', "altered rows are not named"),
 ("bq.py", '        request_body["queryParameters"] = _parameters(params)', '        pass',
  "named query parameters are dropped"),
 ("bq.py", '    if payload.get("insertErrors"):', '    if False:', "rejected streamed rows read as success"),
 ("notary.py", '                if link.seq == (exam_source or (None,))[0]:', '                if False:',
  "the exam is not re-derived after a re-attestation"),
 ("notary.py", '                problem = _describe_reach(payload, evidence)', '                problem = None',
  "project-level grants on the exam go unnoticed"),
 ("notary.py", '                problem = _describe_approval(payload, links)', '                problem = None',
  "the approval is not bound to its exam"),
 ("notary.py", '''    rows = [r for r in store.versions() if r["version"] == parent]
    if rows and not rows[0].get("root"):
        return f"{parent} is the registered genesis version and carries no chain", None
    return None, None''',
  '    return f"{parent} is the genesis version and carries no chain", None',
  "any parent name is accepted as genesis"),
 ("notary.py", '        if not attestation.attested:\n            return None, attestation',
  '        if False:\n            return None, attestation', "a quarantined parent is accepted"),
 ("policy_server.py", '            att["policy"] = _attested_policy(links)', '            att["policy"] = registered',
  "the policy is served from the registry, not the chain"),
 ("policy_server.py", '            if not att["registry_agrees"]:\n                att["attested"] = False',
  '            if False:\n                att["attested"] = False', "a registry mismatch does not freeze"),
 ("policy_server.py", '            att["last_known"] = last', '            att["last_known"] = None',
  "unknown drops the last known state"),
 ("notary.py", '''    if before.break_code in NOT_REATTESTABLE:''', '''    if False:''',
  "re-attestation launders an edited record"),
 ("notary.py", '''    if before.break_code == HOLDOUT_ACCESS and "granted since promotion" in before.break_detail:''',
  '''    if False:''', "re-attestation blesses a widened exam access list"),
]

def suite():
    r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "--no-header"],
                       capture_output=True, text=True, cwd=".")
    return r.returncode == 0

survived = []
for f, old, new, name in CASES:
    p = pathlib.Path("caseharden") / f
    s = p.read_text()
    if old not in s:
        print(f"  !! {name}: target text not found in {f}")
        survived.append(name)
        continue
    p.write_text(s.replace(old, new, 1))
    ok = suite()
    p.write_text(s)
    print(f"  {'SURVIVED <-- untested' if ok else 'caught':22s} {name}")
    if ok:
        survived.append(name)

print(f"\n{len(CASES)} mutations, {len(CASES) - len(survived)} caught, {len(survived)} survived")
sys.exit(1 if survived else 0)
