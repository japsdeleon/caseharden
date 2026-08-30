"""Break each attestation property in the source, and confirm the suite notices.

A passing suite says the tests agree with the code. It does not say the tests
would notice if the code stopped doing what it claims. Two adversarial passes
found assertions here that were vacuous, and one of them was vacuous twice over,
so each property is broken on purpose and the suite is re-run against the break.

The counterpart to generator/mutate_check.py, which does the same for the corpus.

run:  python3 tests/mutate_check.py     (exits non-zero if any mutation survives)
"""
import atexit, os, pathlib, signal, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parent.parent
LOCK = REPO / ".mutate_check.lock"


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Someone else's process, so it exists.
        return True
    return True


def take_lock() -> None:
    """Refuse to start unless this run is the only writer of the sources.

    This harness rewrites files in place and restores each one from a snapshot
    it took a moment earlier. That is correct only while nothing else writes
    them. Two overlapping runs mean the second snapshots a file the first has
    already mutated, treats that mutation as the original text, and restores it
    AS the source. Both processes then exit 0 and the tree keeps the mutation.

    That happened on 2026-08-26: a review subagent launched this twice in the
    background, `bq.py` and `notary.py` were left holding four live mutations,
    and the clean review measured against that tree meant nothing. Neither run
    reported anything wrong, which is why this is a lock and not a warning.
    """
    try:
        fd = os.open(str(LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        try:
            held = LOCK.read_text().strip() or "?"
        except OSError as exc:
            # Owned by another user, or a directory where a file should be.
            # Unreadable is not permission to start.
            print(f"REFUSED. {LOCK.name} exists and cannot be read: "
                  f"{type(exc).__name__}: {exc}")
            raise SystemExit(2)
        running = held.isdigit() and alive(int(held))
        print(f"REFUSED. {LOCK.name} is held by pid {held}, "
              + ("which is still running." if running else "which is gone."))
        if running:
            print("  Another mutation run is in progress. Wait for it to finish.")
            print("  Two runs restore each other's mutations as source, and both")
            print("  exit 0 while the tree keeps them.")
        else:
            print("  That run was killed before it restored anything. It may have")
            print("  left a mutation in the tree, so check before running again:")
            print(f"    git -C {REPO} status --short")
            print(f"  Then delete {LOCK} and re-run.")
        raise SystemExit(2)
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    # Registered here rather than in a `finally` around the loop below. There is
    # a window between this function returning and that `try` being entered, and
    # a signal landing in it would leave the lock behind with nothing mutated.
    #
    # `path` binds the lock taken here. Read as a global at exit time instead,
    # this unlinked whatever LOCK named by then: the tests monkeypatch it to a
    # temporary path, monkeypatch restores the real path on teardown, and every
    # suite run therefore deleted the live harness's own lock on case 1. The
    # remaining 64 cases then ran unprotected, and a killed run left no stale
    # lock to tell a human a mutation might still be in the tree.
    atexit.register(lambda path=LOCK: path.unlink(missing_ok=True))


# Without these, a plain `kill` skips every `finally` below: the lock survives
# and the case in flight stays mutated. SIGINT already raises KeyboardInterrupt.
# SIGKILL cannot be caught, which is the case the stale-lock refusal exists for.
for _signal in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(_signal, lambda *_: sys.exit(1))


def write_atomically(path: pathlib.Path, text: str) -> None:
    """Replace a file's contents with no window in which it holds neither version.

    `write_text` truncates and then writes. A signal or a full disk in between
    leaves the source empty or half written, and the cleanup would then drop the
    lock that is the only thing telling the next run to look.
    """
    scratch = path.with_name(f"{path.name}.{os.getpid()}.mutating")
    try:
        scratch.write_text(text)
        os.replace(str(scratch), str(path))
    finally:
        if scratch.exists():
            scratch.unlink()


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
 ("notary.py", '''    if registered and not registered[0].get("root"):
        return f"{parent} is the registered genesis version and carries no chain", None
    return None, None''',
  '    return f"{parent} is the genesis version and carries no chain", None',
  "any parent name is accepted as genesis"),
 ("notary.py", '        if not attestation.attested:\n            return None, attestation',
  '        if False:\n            return None, attestation', "a quarantined parent is accepted"),

 # Day 10. The policy-line boundary: THREATS.md entry 11. Each of these is a
 # way one line could reach into another, and each must be a test failure.
 ("chain.py",
  '''            f"UPDATE `{target}` SET active = FALSE"
            f" WHERE active AND IFNULL(policy_id, 'conduct-policy') = @policy_id",''',
  '''            f"UPDATE `{target}` SET active = FALSE WHERE active",''',
  "a promotion in one line deactivates every other line"),
 ("chain.py", "            if owner != policy_id:", "            if False:",
  "a genesis in one line silently swallows another line's version"),
 ("notary.py",
  '''    if registered and (registered[0].get("policy_id")
                       or "conduct-policy") != policy_id:''',
  '''    if False:''',
  "a parent from another line is accepted as a baseline"),
 ("policy_server.py",
  '''                and (r.get("policy_id") or "conduct-policy") == policy_id]''',
  '''                and True]''',
  "the active version is resolved across all lines at once"),
 ("policy_server.py",
  '''            if att.get("policy_line") not in (None, line):''',
  '''            if False:''',
  "a version is served through another line's route"),
 ("chain.py", "        if not LINE_RE.match(policy_id):", "        if False:",
  "an empty line name registers and hides from its own scoped deactivation"),
 ("infra/29_register_fleet.py",
  '''                and (r.get("policy_id") or "conduct-policy") == "conduct-policy"]''',
  '''                and True]''',
  "the roster is annotated with whichever line registered last"),
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
 ("workbench.py", "            named = self._subject_for(session, text, known)\n            if named is None:",
  "            named = self._subject_for(session, text, known)\n            if False:",
  "a verdict may be filed against a subject nothing will ever look for"),
 ("workbench.py", "        return latched if latched in known else None",
  "        return latched",
  "a session latched to a case that has since closed confirms a verdict on it"),
 ("workbench.py", '    edge = r"[A-Za-z0-9_-]"\n    return bool(re.search(f"(?<!{edge}){re.escape(job_id)}(?!{edge})", text))',
  "    return job_id in text",
  "a longer job id containing this one passes as this one"),
 ("workbench.py", "    return job_id if isinstance(job_id, str) and job_id else None",
  "    return job_id",
  "a finding whose job id is not a string crashes the console instead of having no subject"),
 ("workbench.py", '        reply = self._chat(text, session)\n        if known and named:\n            self._latch(session, named)',
  '        if known and named:\n            self._latch(session, named)\n        reply = self._chat(text, session)',
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
 # Day 9. Re-attestation may re-derive over evidence that moved. It may never
 # re-derive over evidence that was edited, and a schema change is not licence
 # to stop checking which of the two happened.
 ("notary.py", "    refusal = _content_edit_refusal(prior, events, evidence)",
  "    refusal = None", "re-attestation launders an edited conduct row"),
 ("notary.py", "        missing = [c for c in sealed_columns if c not in current]",
  "        return None", "a new column is licence to re-attest over an edited row"),
 ("notary.py", '    for key in ("event_digest", "access_digest", "exam_reach_digest"):',
  '    for key in ("event_digest",):',
  "a grant landing during refresh is restated as the justified baseline"),
 ("chain.py", "    if not COLUMN_RE.match(name):", "    if False:",
  "a column name out of a chain payload is concatenated into SQL unchecked"),
 ("chain.py", "        if event_id in out:", "        if False:",
  "two rows sharing one event id collapse and the changed one is not hashed"),
 ("notary.py", "    if len(seqs) != len(set(seqs)):", "    if False:",
  "a chain with a duplicated sequence is sealed and repointed anyway"),
 # Day 11. The exam-guard and the Draftsman's report logic.
 ("notary.py",
  '    """A promotion is refused on an unattested parent. That is the freeze."""\n'
  '    if args.policy_id not in LINE_EXAMS:',
  '    """A promotion is refused on an unattested parent. That is the freeze."""\n'
  '    if False:',
  "promote gates an unexamined line against the wrong exam"),
 ("notary.py",
  "    output, run now, under examiner-sa.\n"
  '    """\n'
  "    if args.policy_id not in LINE_EXAMS:",
  "    output, run now, under examiner-sa.\n"
  '    """\n'
  "    if False:",
  "seed writes a chain for a line with no sealed exam"),
 ("notary.py",
  'LINE_EXAMS = {"conduct-policy": "holdout_sealed"}',
  'LINE_EXAMS = {"conduct-policy": "holdout_sealed",\n'
  '              "payments-policy": "holdout_sealed"}',
  "a line silently borrows another line's sealed exam"),
 ("draftsman.py", "                if active_keys == draft_keys:", "                if False:",
  "a duplicated rule is not reported as a duplicate"),
 ("draftsman.py", "                elif active_keys <= draft_keys:", "                elif False:",
  "a redundant draft rule is not reported as covered"),
 ("draftsman.py", "                elif draft_keys < active_keys:", "                elif False:",
  "a draft wider than another line's rule raises no ownership question"),
 ("draftsman.py", '            verdict = "EARNING" if denials else "DORMANT"',
  '            verdict = "EARNING"', "a rule that denies nothing reads as earning its place"),
 ("draftsman.py",
  '        if str(row.get("active")).lower() != "true":\n            continue',
  '        if False:\n            continue',
  "inactive registry rows join the overlap and rot reports"),
 ("draftsman.py",
  '        print(f"nothing written to {args.out}")\n        return 2',
  '        print(f"nothing written to {args.out}")\n        return 0',
  "an invalid draft exits as if it were written"),
 # The adversarial scope review's fixes must themselves be load-bearing.
 ("notary.py", "    if taken:", "    if False:",
  "a second genesis replaces a live floor with no exam and no chain"),
 ("draftsman.py", '    if sa.startswith("examiner-sa@"):', '    if False:',
  "the bench runs as the sealed exam's one reader"),
 ("draftsman.py", '    if args.dataset in ("holdout_sealed", "benign_corpus"):',
  '    if False:', "the bench reads exam material through patterns"),
]

def suite():
    # Anchored to REPO, like the paths below. Run from another directory, `cwd="."`
    # pointed pytest at whatever was there, and a relative case path mutated a
    # different checkout of this repo entirely.
    r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "--no-header"],
                       capture_output=True, text=True, cwd=str(REPO))
    return r.returncode == 0


def main() -> int:
    take_lock()
    survived = []
    for f, old, new, name in CASES:
        p = REPO / f if "/" in f else REPO / "caseharden" / f
        original = p.read_text()
        if old not in original:
            print(f"  !! {name}: target text not found in {f}")
            survived.append(name)
            continue
        try:
            # The mutating write is inside the `try`, not before it. Outside, a
            # signal between the write and entering the block skipped the
            # restore, and the file stayed mutated.
            write_atomically(p, original.replace(old, new, 1))
            ok = suite()
        finally:
            write_atomically(p, original)
        print(f"  {'SURVIVED <-- untested' if ok else 'caught':22s} {name}")
        if ok:
            survived.append(name)

    print(f"\n{len(CASES)} mutations, {len(CASES) - len(survived)} caught, "
          f"{len(survived)} survived")
    return 1 if survived else 0


if __name__ == "__main__":
    # Guarded so the lock logic can be tested by importing this module and
    # calling take_lock() directly. The previous tests ran this file as a
    # subprocess, which meant a broken guard started a real mutation run from
    # inside the test suite.
    sys.exit(main())
