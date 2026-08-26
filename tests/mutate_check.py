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
 # Day 5. Re-derivation must not change what is enforced, and a chain link
 # that records a refusal must record a refusal.
 ("chain.py", 'f" WHERE version = @version",',
  'f", active = TRUE WHERE version = @version",',
  "re-attestation puts an old version back in force"),
 ("notary.py", '        if link.kind == "HOLDOUT-DENIED" and str(p["http_code"]) != "403":',
  '        if False:', "a HOLDOUT-DENIED link can record something other than a refusal"),
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

 # Day 4. Paths containing a slash are relative to the repo root; the rest are
 # under caseharden/.
 ("agents/common/enforcement.py", '        out["state"] = state.lower()', '        out["state"] = state',
  "the served state is compared case-sensitively, so every block reads unattested"),
 ("agents/common/enforcement.py", "            reason_attested=bool(rule) and attested,",
  "            reason_attested=attested,", "an allow claims an attestation"),
 ("agents/common/enforcement.py", '        attested = bool(answer.get("attested")) and state == ATTESTED',
  '        attested = bool(answer.get("attested"))',
  "the served attested flag is believed without its state"),
 ("agents/common/enforcement.py", '            stale["attested"] = False', '            stale["attested"] = True',
  "a stale policy answer still claims to be attested"),
 ("agents/common/enforcement.py", "        if raw_policy is None:", "        if False:",
  "a call proceeds with no policy at all"),
 ("agents/common/conduct.py", "    return {k: v for k, v in row.items() if k in COLUMNS}",
  "    return dict(row)", "any key is written to the conduct table"),
 ("bq.py", "    if role in BASIC_ROLES:\n        answer = True",
  "    if role in BASIC_ROLES:\n        answer = False",
  "roles/owner is not counted as reaching the sealed exam"),
 ("bq.py", "        answer = permissions is None or EXAM_READ_PERMISSION in permissions",
  "        answer = permissions is not None and EXAM_READ_PERMISSION in permissions",
  "a role that cannot be expanded is assumed harmless"),

 # From the Day 4 adversarial pass.
 ("agents/common/enforcement.py",
  """        if armor.get("ma_verdict") in UNSCREENED and needs_screening(policy):""",
  "        if False:",
  "losing Model Armor becomes a bypass for the rule it feeds"),
 ("agents/common/enforcement.py",
  """            if getattr(predicate, "field", None) in SCREENING_FIELDS:\n                return True""",
  """            if False:\n                return True""",
  "no policy is considered to depend on screening"),
 ("chain.py", """            return reaching + impersonation.result()""", "            return reaching",
  "impersonating the exam reader is not counted as reach"),
 ("chain.py",
  """                return [{"role": f"impersonate/{reader}", "members": ["UNREADABLE"]}]""",
  "                return []",
  "an unreadable impersonation policy reads as nobody"),
 ("agents/detector/families.py", "    if not TABLE_RE.match(table):", "    if False:",
  "a table identifier can close the quote and append a statement"),

 # From the Day 4 in-house validation pass.
 ("agents/common/enforcement.py",
  """        if not text:
            # A turn with no text cannot be screened, which is not the same as a""",
  """        if False:
            # A turn with no text cannot be screened, which is not the same as a""",
  "an unscreened empty turn passes as a clean one"),
 ("agents/common/enforcement.py", '        if answer.get("expired"):', "        if False:",
  "the staleness bound is recorded and never acted on"),
 ("bq.py", "    if _cacheable(role) and role in _ROLE_CACHE:", "    if role in _ROLE_CACHE:",
  "a mutable custom role is cached for the life of the process"),
 ("chain.py",
  """        reaching = [b for b in bindings if answers.get(b.get("role") or "")]""",
  "        reaching = list(bindings)",
  "exam_reach keeps every binding regardless of permission"),

 # Day 7. The wire format of a Cloud Trace span. Each of these is a reason
 # traces:batchWrite answers 400, and one refused batch loses every span in it.
 # The export path this replaced reported success and delivered nothing, so a
 # silent break here is the exact failure the module was rewritten to end.
 ("agents/common/tracing.py",
  """        "name": f"projects/{project}/traces/{trace_id}/spans/{span_id}",""",
  """        "name": f"projects/{project}/spans/{span_id}",""",
  "a span is written with no trace to belong to"),
 ("agents/common/tracing.py",
  """    if isinstance(value, bool):\n        return {"boolValue": value}""",
  """    if False:\n        return {"boolValue": value}""",
  "a boolean span attribute is written as an integer"),
 ("agents/common/tracing.py",
  """    if len(raw) <= limit:\n        return {"value": str(text), "truncatedByteCount": 0}""",
  """    if True:\n        return {"value": str(text), "truncatedByteCount": 0}""",
  "a value over the API's byte limit is sent unchanged"),
 ("agents/common/tracing.py", "        if len(kept) >= MAX_ATTRIBUTES:", "        if False:",
  "more attributes than the API accepts are sent"),
 ("agents/common/tracing.py",
  """    return {"value": kept, "truncatedByteCount": len(raw) - len(kept.encode("utf-8"))}""",
  """    return {"value": kept, "truncatedByteCount": len(raw) - limit}""",
  "a cut inside a character under-counts the bytes it dropped"),
 ("agents/common/tracing.py", "        name_key = _clip(key, KEY_BYTES)",
  "        name_key = str(key)[:KEY_BYTES]",
  "an attribute key is limited by characters, so a multi-byte key exceeds the API's limit"),
 ("agents/common/tracing.py",
  """        if name_key in kept:
            dropped += 1
            continue""",
  """        if False:
            dropped += 1
            continue""",
  "two keys that collide after truncation silently overwrite, losing one uncounted"),
 ("agents/common/tracing.py",
  """    if parent_id:\n        payload["parentSpanId"] = parent_id""",
  """    payload["parentSpanId"] = str(parent_id or "")""",
  "a root span claims an empty parent"),
 # Day 8. The workbench's two rules. Both are the kind that keeps working
 # visibly after it has stopped working: a verdict filed against the wrong
 # subject still stores and still screens, and a console that answers any Host
 # still serves the analyst correctly.
 ("workbench.py", "        if job_id and not self._named_the_job(session, job_id, text):",
  "        if False:",
  "a verdict may be filed against a subject the Notary will never look for"),
 ("workbench.py", "            return self._named.get(session) == job_id",
  "            return session in self._named",
  "a session latched to one finding confirms a verdict on the next one"),
 ("workbench.py", '    edge = r"[A-Za-z0-9_-]"\n    return bool(re.search(f"(?<!{edge}){re.escape(job_id)}(?!{edge})", text))',
  "    return job_id in text",
  "a longer job id containing this one passes as this one"),
 ("workbench.py", "    return job_id if isinstance(job_id, str) and job_id else None",
  "    return job_id",
  "a finding whose job id is not a string crashes the console instead of having no subject"),
 ("workbench.py", '        reply = self._chat(text, session)\n        if job_id:\n            self._latch(session, job_id)',
  '        if job_id:\n            self._latch(session, job_id)\n        reply = self._chat(text, session)',
  "a session is latched by a turn the Copilot never took"),
 ("workbench.py", "            while len(self._named) > MAX_LATCHED_SESSIONS:",
  "            while False:",
  "the latch map grows without bound on caller-chosen session names"),
 ("workbench.py", "            if host not in allowed_hosts:",
  "            if False:",
  "a rebound hostname reaches the console, and through it the Copilot"),
 ("workbench.py", '                    != "application/json":',
  '                    != "":',
  "a cross-origin form post reaches the Copilot without a preflight"),
 # Day 8, second pass. Three the first two adversarial passes did not reach.
 ("workbench.py", '''        except Exception as exc:  # noqa: BLE001 - every failure is the unknown state''',
  '''        except (urllib.error.URLError, OSError, ValueError) as exc:''',
  "a truncated Policy Server body blanks the chain and registry panes"),
 ("workbench.py", '''                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")''',
  '''                             "base-uri 'none'; form-action 'none'")''',
  "the console can be framed, so the analyst's clicks land on it"),
 ("recheck.py", "        except Exception as exc:  # noqa: BLE001 - a crash is a failed check",
  "        except NotImplementedError as exc:",
  "a tampered payload crashes the re-check instead of failing a check"),
]

def suite():
    r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "--no-header"],
                       capture_output=True, text=True, cwd=".")
    return r.returncode == 0

survived = []
for f, old, new, name in CASES:
    p = pathlib.Path(f) if "/" in f else pathlib.Path("caseharden") / f
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
