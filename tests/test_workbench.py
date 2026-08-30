#!/usr/bin/env python3
"""The workbench, pinned to the two rules that make it safe to add.

The console is a window, so most of what it does is not worth a test. Three
things are, and they are the reasons it can be added to a finished entry without
weakening it:

  it never verifies for itself. `verify` re-scores the sealed exam and needs
  `examiner-sa`, the only principal allowed to read it. A console that held that
  identity would be a second reader of the exam that the EVIDENCE link's access
  digest was built to make visible. `test_holds_no_examiner_identity` asserts
  this against the parsed module rather than against a promise in a docstring.

  it refuses a verdict that names the wrong subject. `infra/110_run_loop.py`
  waits on a review row whose subject equals the detector's job id exactly. A
  verdict filed against anything else stores fine, screens fine, and leaves the
  driver polling for fifteen minutes with no way to say why.

  fixture mode touches no credential. That is the judge-runnable path and the
  recovery path, so a test mints an exception instead of a token and the whole
  page still renders.

run:  python3 -m pytest tests -q
"""

from __future__ import annotations

import ast
import http.client
import json
import re
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "generator"))

from caseharden import cases, workbench  # noqa: E402
from caseharden.chain import KINDS  # noqa: E402

FIXTURE = REPO / "fixtures" / "v5"


# --------------------------------------------------------------------------
# The identity rule
# --------------------------------------------------------------------------

def _executable_names(path: Path):
    """Every name, attribute and non-docstring string literal in a module.

    Docstrings and comments are excluded on purpose. The rule under test is
    about what the code does, and a docstring that explains the rule would
    otherwise fail a plain substring search for it.
    """
    tree = ast.parse(path.read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))

    names, strings = set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                strings.append(node.value)
    return names, strings


def test_holds_no_examiner_identity():
    names, strings = _executable_names(Path(workbench.__file__))
    offending = [s for s in strings if "examiner" in s.lower()]
    assert not offending, (
        "the workbench names examiner-sa in executable code. Attestation state "
        f"comes from the Policy Server and nowhere else: {offending}")
    assert not [n for n in names if "examiner" in n.lower()]


def test_never_calls_verify():
    names, _ = _executable_names(Path(workbench.__file__))
    assert "verify" not in names, (
        "the workbench calls verify. Re-deriving the exam is the Policy "
        "Server's job, under the one identity allowed to read it.")
    assert "reattest" not in names
    imported = ast.parse(Path(workbench.__file__).read_text())
    modules = [n.module or "" for n in ast.walk(imported) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if "notary" in m], (
        "the workbench imports the Notary, which is where verify lives")


def test_the_page_makes_no_outbound_request():
    """No CDN, no font host, no analytics. The page is one file or it is not local."""
    page = workbench.PAGE.read_text()
    for scheme in ("http://", "https://", "//cdn", "integrity="):
        assert scheme not in page.replace("http://127.0.0.1", ""), (
            f"the page references {scheme!r}; it must load nothing it was not served with")


# --------------------------------------------------------------------------
# Fixture mode: the offline path
# --------------------------------------------------------------------------

def test_fixture_mode_renders_the_committed_chain(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("fixture mode minted a credential")

    monkeypatch.setattr(workbench.bq, "access_token", refuse)

    state = workbench.FixtureSource(FIXTURE).state(None)
    assert state["mode"] == "fixture"
    assert state["version"] == "v5"
    assert len(state["links"]) == 7
    assert [l["kind"] for l in state["links"]][0] == "EVIDENCE"
    assert all(l["kind"] in KINDS for l in state["links"])
    assert all(l["intact"] for l in state["links"])

    attestation = state["attestation"]
    assert attestation["offline"] is True
    assert attestation["attested"] is True, attestation["checks_failed"]
    assert attestation["checks_run"] >= 17
    assert attestation["root"].startswith("e2a559358933")
    # A fixture has no live state and the console must not imply one.
    assert attestation["promotions"] == "n/a"
    assert "state" not in attestation or attestation["state"] == "OFFLINE-RECHECK"


def test_fixture_mode_reports_a_tampered_chain(tmp_path):
    directory = tmp_path / "v5"
    directory.mkdir()
    for name in ("chain.jsonl", "certificate.json", "source.json"):
        (directory / name).write_text((FIXTURE / name).read_text())

    lines = (directory / "chain.jsonl").read_text().splitlines()
    row = json.loads(lines[1])
    row["payload"]["edited"] = "by something that did not understand it"
    lines[1] = json.dumps(row, sort_keys=True)
    (directory / "chain.jsonl").write_text("\n".join(lines) + "\n")

    attestation = workbench.FixtureSource(directory).state(None)["attestation"]
    assert attestation["attested"] is False
    assert attestation["checks_failed"], "an edited payload must fail a check"


def test_fixture_directory_without_a_chain_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        workbench.FixtureSource(tmp_path)


# --------------------------------------------------------------------------
# The token cache
# --------------------------------------------------------------------------

def test_tokens_are_minted_once_per_account(monkeypatch):
    calls = []

    def mint(service_account):
        calls.append(service_account)
        return "token-for-" + service_account

    monkeypatch.setattr(workbench.bq, "access_token", mint)
    tokens = workbench.Tokens(ttl=60)
    assert tokens.get("a@x") == "token-for-a@x"
    assert tokens.get("a@x") == "token-for-a@x"
    assert tokens.get("b@x") == "token-for-b@x"
    assert calls == ["a@x", "b@x"], "a cached token was re-minted"


def test_an_expired_token_is_re_minted(monkeypatch):
    calls = []
    monkeypatch.setattr(workbench.bq, "access_token",
                        lambda sa: (calls.append(sa), "t")[1])
    tokens = workbench.Tokens(ttl=0)
    tokens.get("a@x")
    tokens.get("a@x")
    assert len(calls) == 2


def test_concurrent_requests_mint_one_token(monkeypatch):
    """The server is threaded, so the cache has to hold under concurrent misses.

    Minting used to happen outside the lock. Two of the browser's polls arriving
    together therefore both missed and both shelled out to gcloud, which is the
    cost this cache exists to remove. An adversarial pass measured two mints.
    """
    calls = []
    barrier = threading.Barrier(8)

    def slow_mint(service_account):
        calls.append(service_account)
        time.sleep(0.05)
        return "token"

    monkeypatch.setattr(workbench.bq, "access_token", slow_mint)
    tokens = workbench.Tokens(ttl=600)

    def race():
        barrier.wait()
        tokens.get("a@x")

    threads = [threading.Thread(target=race) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1, f"{len(calls)} concurrent mints for one account"


def test_one_slow_mint_does_not_block_another_account(monkeypatch):
    """The lock is per account, so a slow gcloud for one identity is not a stall for all."""
    started = threading.Event()

    def mint(service_account):
        if service_account == "slow@x":
            started.set()
            time.sleep(0.4)
        return "token-" + service_account

    monkeypatch.setattr(workbench.bq, "access_token", mint)
    tokens = workbench.Tokens(ttl=600)
    slow = threading.Thread(target=lambda: tokens.get("slow@x"))
    slow.start()
    assert started.wait(2.0)
    began = time.monotonic()
    assert tokens.get("fast@x") == "token-fast@x"
    assert time.monotonic() - began < 0.3, "a different account waited on the slow mint"
    slow.join()


# --------------------------------------------------------------------------
# What reaches the browser
# --------------------------------------------------------------------------

def test_a_long_list_is_trimmed_and_says_so():
    trimmed = workbench._trim({"events": list(range(500))})
    assert len(trimmed["events"]) == workbench.MAX_LIST_ITEMS + 1
    assert "more, not sent to the browser" in trimmed["events"][-1]


def test_a_long_string_is_trimmed_and_says_so():
    trimmed = workbench._trim({"report": "x" * (workbench.MAX_PAYLOAD_CHARS + 10)})
    assert trimmed["report"].endswith(f"[{workbench.MAX_PAYLOAD_CHARS + 10} chars]")


def test_a_half_written_finding_is_not_an_error_page(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text('{"job_id": "europe-west3:job_abc", "fam')
    out = workbench.read_finding(path)
    assert out["present"] is False
    assert "error" in out


def test_a_missing_finding_reads_as_absent(tmp_path):
    out = workbench.read_finding(tmp_path / "nothing.json")
    assert out == {"present": False, "path": str(tmp_path / "nothing.json")}


def test_a_deeply_nested_finding_does_not_crash_the_pane(tmp_path):
    """json.loads raises RecursionError, not JSONDecodeError, on deep input.

    An adversarial pass dropped the handler with a 1,100-level array. Catching
    only JSONDecodeError left it escaping as a dropped connection.
    """
    path = tmp_path / "finding-live.json"
    path.write_text("[" * 1200 + "]" * 1200)
    out = workbench.read_finding(path)
    assert out["present"] is False
    assert "error" in out


# How deep json.loads tolerates before RecursionError is version-dependent:
# 3.9 refuses 1,200 levels and 3.12 parses 10,000. Deep enough to refuse on
# both, and still inside the handler's 64KB length cap at two bytes per level.
DEEP = 20_000


def test_a_deeply_nested_chat_body_is_a_400(served):
    body = "[" * DEEP + "]" * DEEP
    assert len(body) < 64_000, "the length cap would answer 413 before the parse"
    connection = http.client.HTTPConnection(*served, timeout=30)
    connection.request("POST", "/api/chat", body=body.encode(),
                       headers={"Content-Type": "application/json"})
    assert connection.getresponse().status == 400
    connection.close()


@pytest.mark.parametrize("body", ["[]", '"a string"', "42", "null", "[1,2,3]"])
def test_valid_json_that_is_not_an_object_is_a_400(served, body):
    """`[]` is valid JSON with no .get.

    It used to reach the generic handler as an AttributeError and come back 502,
    which blames the server for a malformed request. Found by running the suite
    on 3.12, where a body 3.9 had refused outright parses cleanly instead.
    """
    connection = http.client.HTTPConnection(*served, timeout=30)
    connection.request("POST", "/api/chat", body=body.encode(),
                       headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    raw = response.read()
    assert response.status == 400, f"{body!r} returned {response.status}"
    assert b"object" in raw
    connection.close()


@pytest.mark.parametrize("content", ["[]", '"a string"', "42", "[{\"job_id\": \"x\"}]"])
def test_a_finding_file_that_is_not_an_object_reads_as_absent(tmp_path, content):
    path = tmp_path / "finding-live.json"
    path.write_text(content)
    out = workbench.read_finding(path)
    assert out["present"] is False
    assert "error" in out


def test_a_finding_file_that_is_not_an_object_does_not_break_the_pane(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text("[]")
    bench = workbench.Workbench(workbench.FixtureSource(FIXTURE), finding_path=path)
    out = bench.finding()
    assert out["present"] is False


# --------------------------------------------------------------------------
# The subject guard
# --------------------------------------------------------------------------

JOB = "europe-west3:job_5UcJoBBEaZWU0"


def _bench(tmp_path, chat=None, finding=None):
    path = tmp_path / "finding-live.json"
    if finding is not None:
        path.write_text(json.dumps(finding))
    return workbench.Workbench(workbench.FixtureSource(FIXTURE),
                               finding_path=path, chat=chat)


def test_a_verdict_that_names_the_wrong_subject_is_refused(tmp_path):
    bench = _bench(tmp_path, chat=lambda text, session: "stored",
                   finding={"job_id": JOB, "family": "cross_account"})
    with pytest.raises(workbench.Refused) as exc:
        bench.chat("Confirmed abuse, record it against job_WRONG.", "s1")
    assert JOB in str(exc.value)


def test_a_verdict_that_names_the_finding_is_passed_on(tmp_path):
    seen = {}

    def chat(text, session):
        seen["text"], seen["session"] = text, session
        return "recorded vd_0001"

    bench = _bench(tmp_path, chat=chat, finding={"job_id": JOB})
    out = bench.chat(f"Record my verdict on {JOB}: confirmed abuse.", "s1")
    assert out == {"reply": "recorded vd_0001"}
    assert seen["session"] == "s1"


def test_an_empty_message_is_refused(tmp_path):
    bench = _bench(tmp_path, chat=lambda t, s: "", finding={"job_id": JOB})
    with pytest.raises(workbench.Refused):
        bench.chat("   ", "s1")


def test_fixture_mode_has_nothing_to_say_to(tmp_path):
    bench = _bench(tmp_path, chat=None, finding={"job_id": JOB})
    with pytest.raises(workbench.Refused) as exc:
        bench.chat("anything at all", "s1")
    assert "fixture" in str(exc.value)


def test_without_a_finding_any_message_is_passed_on(tmp_path):
    """No finding on disk means no subject to check, not a closed console."""
    bench = _bench(tmp_path, chat=lambda t, s: "ok")
    assert bench.chat("Where do I file this?", "s1") == {"reply": "ok"}


CONFIRM = "Yes. Store it exactly as you listed, with those arguments."


def test_the_confirmation_turn_is_allowed_once_the_session_named_the_job(tmp_path):
    """The Copilot echoes the arguments back and asks. The answer is "yes".

    That answer names no job id, so the guard refused it and the console could
    not complete the write it exists to make. Checking the session's first turn
    is what the guard is for; every turn after it is talking about the same
    finding in the same session.
    """
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": JOB})
    assert bench.chat(f"Record a verdict on {JOB}: confirmed abuse.", "s1")
    assert bench.chat(CONFIRM, "s1") == {"reply": "ok"}


def test_a_session_that_never_named_the_job_is_still_refused(tmp_path):
    """One session naming it does not speak for another."""
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": JOB})
    bench.chat(f"Record a verdict on {JOB}: confirmed abuse.", "s1")
    with pytest.raises(workbench.Refused) as exc:
        bench.chat(CONFIRM, "s2")
    assert JOB in str(exc.value)


def test_a_new_finding_makes_the_session_name_it_again(tmp_path):
    """The latch is to one job id, not to the session.

    The driver overwrites the finding file when the next run answers. A session
    left open across that boundary is now looking at a different job, and a
    bare "yes" in it would confirm a verdict on the wrong one.
    """
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    bench = workbench.Workbench(workbench.FixtureSource(FIXTURE),
                                finding_path=path, chat=lambda t, s: "ok")
    bench.chat(f"Record a verdict on {JOB}: confirmed abuse.", "s1")

    later = "europe-west3:job_LATERRUN00001"
    path.write_text(json.dumps({"job_id": later}))
    with pytest.raises(workbench.Refused) as exc:
        bench.chat(CONFIRM, "s1")
    assert later in str(exc.value)
    assert bench.chat(f"Record a verdict on {later}: false positive.", "s1")
    assert bench.chat(CONFIRM, "s1") == {"reply": "ok"}


def test_a_longer_job_id_containing_this_one_is_refused(tmp_path):
    """The driver compares `subject` for equality, so a longer id is the miss.

    A plain substring test passed `<job>X` while the finding under review was
    `<job>`, which is precisely the subject `wait_for` will never find.
    """
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": JOB})
    with pytest.raises(workbench.Refused):
        bench.chat(f"Record a verdict on {JOB}X: confirmed abuse.", "s1")
    with pytest.raises(workbench.Refused):
        bench.chat(f"Record a verdict on X{JOB}: confirmed abuse.", "s1")


@pytest.mark.parametrize("sentence", [
    "Record a verdict on {job}: confirmed abuse.",
    "Confirmed abuse on {job}.",
    "The finding is {job}, and I am calling it a false positive.",
    "{job}",
])
def test_the_sentence_an_analyst_actually_writes_is_accepted(tmp_path, sentence):
    """Punctuation around the id is normal. Only identifier characters are not."""
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": JOB})
    assert bench.chat(sentence.format(job=JOB), "s1") == {"reply": "ok"}


@pytest.mark.parametrize("bad", [["a"], {"a": 1}, 12345, True])
def test_a_finding_whose_job_id_is_not_a_string_has_no_subject(tmp_path, bad):
    """It reached `job_id in text` and raised TypeError, which the handler sent as 502.

    The file is on disk and the driver is not the only thing that can write it.
    No usable subject means no check, the same as no finding at all.
    """
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": bad})
    assert bench.chat("anything at all", "s1") == {"reply": "ok"}
    assert bench.finding().get("decision") is None


def test_a_first_turn_the_copilot_refused_does_not_latch_the_session(tmp_path):
    """The latch used to be taken before the Copilot had the turn.

    So a message that never arrived still opened the session, and the bare "yes"
    after it was let through on the strength of a turn that did not happen.
    """
    def boom(text, session):
        raise RuntimeError("the Copilot did not take it")

    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    bench = workbench.Workbench(workbench.FixtureSource(FIXTURE),
                                finding_path=path, chat=boom)
    with pytest.raises(RuntimeError):
        bench.chat(f"Record a verdict on {JOB}: confirmed abuse.", "s1")

    bench._chat = lambda text, session: "ok"
    with pytest.raises(workbench.Refused):
        bench.chat(CONFIRM, "s1")


def test_the_latch_map_is_bounded_by_caller_chosen_session_names(tmp_path):
    """`session` comes out of the request body, so the caller picks how many.

    The comment here used to say one small entry per session and nothing needing
    eviction. The number of sessions is not the number of findings.
    """
    bench = _bench(tmp_path, chat=lambda t, s: "ok", finding={"job_id": JOB})
    for i in range(workbench.MAX_LATCHED_SESSIONS * 3):
        bench.chat(f"Record a verdict on {JOB}.", f"session-{i}")
    assert len(bench._named) == workbench.MAX_LATCHED_SESSIONS

    newest = f"session-{workbench.MAX_LATCHED_SESSIONS * 3 - 1}"
    assert bench.chat(CONFIRM, newest) == {"reply": "ok"}
    with pytest.raises(workbench.Refused):
        bench.chat(CONFIRM, "session-0")


# --------------------------------------------------------------------------
# The live source, when the project answers badly
# --------------------------------------------------------------------------

class _Boom(RuntimeError):
    pass


def test_an_unreachable_policy_server_is_never_attested(monkeypatch):
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v5", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read", lambda self, v: [])
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "http://127.0.0.1:1", workbench.Tokens())
    state = source.state(None)
    assert state["attestation"]["attested"] is False
    assert state["attestation"]["state"] == "UNREACHABLE"
    assert state["attestation"]["promotions"] == "FROZEN"


def test_a_failed_chain_read_leaves_the_reason_on_the_page(monkeypatch):
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: (_ for _ in ()).throw(_Boom("403 on chain.links")))
    monkeypatch.setattr(workbench.LiveSource, "attestation",
                        lambda self, v: {"attested": False, "state": "UNREACHABLE"})
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "http://127.0.0.1:1", workbench.Tokens())
    state = source.state(None)
    assert state["versions"] == []
    assert "403 on chain.links" in state["errors"]["versions"]


# --------------------------------------------------------------------------
# The routes, over a real socket
# --------------------------------------------------------------------------

@pytest.fixture
def served(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB, "family": "cross_account",
                                "rows": [{"session_id": "s_1", "turns": "2"}]}))
    bench = workbench.Workbench(workbench.FixtureSource(FIXTURE), finding_path=path)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), workbench.handler_for(bench))
    except (PermissionError, OSError) as exc:
        # A sandbox that forbids binding a socket is not a failing repository.
        # The offline promise is that anyone can re-check this on a clean
        # checkout, and some of those checkouts run where listen() is denied.
        pytest.skip(f"cannot bind a loopback socket here: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()


def _request(address, method, path, body=None):
    connection = http.client.HTTPConnection(*address, timeout=30)
    payload = json.dumps(body).encode() if body is not None else None
    connection.request(method, path, body=payload,
                       headers={"Content-Type": "application/json"} if payload else {})
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, response.getheader("Content-Type"), raw


def test_the_page_is_served(served):
    status, content_type, raw = _request(served, "GET", "/")
    assert status == 200
    assert content_type.startswith("text/html")
    assert b"analyst workbench" in raw


def test_state_carries_the_chain(served):
    status, _, raw = _request(served, "GET", "/api/state")
    assert status == 200
    body = json.loads(raw)
    assert body["mode"] == "fixture"
    assert len(body["links"]) == 7


def test_finding_carries_the_job_under_review(served):
    status, _, raw = _request(served, "GET", "/api/finding")
    assert status == 200
    body = json.loads(raw)
    assert body["present"] is True
    assert body["finding"]["job_id"] == JOB


def test_a_bad_version_name_is_refused(served):
    status, _, raw = _request(served, "GET", "/api/state?version=v5%60DROP")
    assert status == 400


def test_an_unknown_path_is_a_404(served):
    assert _request(served, "GET", "/api/whatever")[0] == 404
    assert _request(served, "POST", "/api/whatever")[0] == 404


def test_chat_in_fixture_mode_answers_409_with_a_reason(served):
    status, _, raw = _request(served, "POST", "/api/chat",
                              {"text": f"verdict on {JOB}", "session": "s1"})
    assert status == 409
    assert "fixture" in json.loads(raw)["error"]


def test_a_message_that_is_not_json_is_refused(served):
    connection = http.client.HTTPConnection(*served, timeout=30)
    connection.request("POST", "/api/chat", body=b"{not json",
                       headers={"Content-Type": "application/json"})
    assert connection.getresponse().status == 400
    connection.close()


# --------------------------------------------------------------------------
# What a browser can be made to do to a localhost service
# --------------------------------------------------------------------------

def _raw(address, lines: str):
    """One request with headers written by hand, so Host can be a lie."""
    import socket

    sock = socket.create_connection(address, timeout=30)
    sock.sendall(lines.encode())
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return int(raw.split(b" ")[1])


def test_a_rebound_hostname_is_refused(served):
    """A name that resolves to 127.0.0.1 makes an attacker's page same-origin.

    The browser still sends the name it was given in Host, so that is what this
    refuses on. Without it, any page the analyst has open can read the chain and
    speak to the Copilot.
    """
    status = _raw(served, "GET /api/state HTTP/1.1\r\nHost: workbench.attacker.example"
                          "\r\nConnection: close\r\n\r\n")
    assert status == 403


def test_a_cross_origin_post_is_refused(served):
    status = _raw(served,
                  "POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  "Origin: https://attacker.example\r\n"
                  "Content-Type: application/json\r\nContent-Length: 2\r\n"
                  "Connection: close\r\n\r\n{}")
    assert status == 403


def test_a_form_post_cannot_reach_the_copilot(served):
    """`<form enctype="text/plain">` is the one cross-origin POST with no preflight.

    Its body can be made to parse as JSON, so the content type is what refuses
    it: a form cannot send application/json.
    """
    body = '{"text": "confirmed abuse", "session": "x"}'
    status = _raw(served,
                  f"POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                  f"Connection: close\r\n\r\n{body}")
    assert status == 415


def test_the_page_itself_is_still_served(served):
    status = _raw(served, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    assert status == 200


def test_a_request_with_no_host_at_all_is_refused(served):
    """Absent must not read as acceptable, or the check above is optional."""
    status = _raw(served, "GET /api/state HTTP/1.1\r\nConnection: close\r\n\r\n")
    assert status == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8090", "localhost",
                                  "[::1]", "[::1]:8090"])
def test_every_loopback_spelling_is_accepted(served, host):
    """`rsplit(':', 1)` splits inside a bracketed IPv6 address and yielded ':'.

    It failed closed, so it was never a hole. It was also not the check it
    claimed to be, and a console that refuses `[::1]` is one an operator debugs
    at the wrong moment.
    """
    status = _raw(served, f"GET /healthz HTTP/1.1\r\nHost: {host}\r\n"
                          f"Connection: close\r\n\r\n")
    assert status == 200, f"loopback spelled {host!r} was refused"


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8090",
                                  "[dead::beef]", "127.0.0.1.evil.example"])
def test_no_other_host_is_accepted(served, host):
    status = _raw(served, f"GET /healthz HTTP/1.1\r\nHost: {host}\r\n"
                          f"Connection: close\r\n\r\n")
    assert status == 403, f"host {host!r} reached the console"


def test_the_console_refuses_to_be_framed(served):
    """The Host and content-type checks stop a hostile page reading or posting.

    Neither stops it framing the console invisibly and letting the analyst's own
    clicks land on it, which needs no cross-origin read at all.
    """
    connection = http.client.HTTPConnection(*served, timeout=30)
    connection.request("GET", "/", headers={"Host": "127.0.0.1"})
    response = connection.getresponse()
    response.read()
    csp = response.getheader("Content-Security-Policy") or ""
    assert "frame-ancestors 'none'" in csp, csp
    assert (response.getheader("X-Frame-Options") or "").upper() == "DENY"
    connection.close()


# --------------------------------------------------------------------------
# An attestation failure must not take the panes that read fine with it
# --------------------------------------------------------------------------

def test_a_thrown_attestation_does_not_blank_the_other_panes(monkeypatch):
    """IncompleteRead is not URLError, OSError or ValueError, and the token mint
    used to sit outside the try, so a missing gcloud escaped too. Either one
    blanked the chain and registry panes that had already read successfully."""
    import http.client as httplib

    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v6", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read",
                        lambda self, v: chain_build_all_kinds()[:2])

    def truncated(*_a, **_k):
        raise httplib.IncompleteRead(b"{\"versi")

    monkeypatch.setattr(workbench.urllib.request, "urlopen", truncated)
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "https://policy.example.run.app", workbench.Tokens())
    state = source.state(None)
    assert state["versions"], "a working registry read was discarded"
    assert state["links"], "a working chain read was discarded"
    assert state["attestation"]["attested"] is False
    assert state["attestation"]["state"] == "UNREACHABLE"


def test_a_missing_gcloud_during_the_mint_is_the_unknown_state(monkeypatch):
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v6", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read", lambda self, v: [])

    import agents.common.auth as auth

    monkeypatch.setattr(auth, "id_token", lambda audience: (_ for _ in ()).throw(
        FileNotFoundError(2, "No such file or directory: 'gcloud'")))
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "https://policy.example.run.app", workbench.Tokens())
    attestation = source.state(None)["attestation"]
    assert attestation["attested"] is False
    assert "FileNotFoundError" in attestation["error"]


def chain_build_all_kinds():
    from caseharden.chain import build

    return build("v6", [(k, {"k": k}) for k in KINDS])


# --------------------------------------------------------------------------
# The subject divergence the guard cannot prevent
# --------------------------------------------------------------------------

BARE = JOB.split(":")[-1]


class _Rows(workbench.Source):
    """A review table holding whatever a test says it holds."""

    mode = "live"

    def __init__(self, rows):
        self.rows = rows

    def state(self, version):
        return {"mode": "live", "versions": [], "links": [], "attestation": {}}

    def decision(self, kind, subject):
        return next((r for r in self.rows
                     if r["kind"] == kind and r["subject"] == subject), None)

    def near_miss(self, kind, subject):
        bare = subject.rsplit(":", 1)[-1]
        return next((r for r in self.rows if r["kind"] == kind
                     and r["subject"] != subject and r["subject"].endswith(bare)), None)


def _finding_bench(tmp_path, rows):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    return workbench.Workbench(_Rows(rows), finding_path=path)


def test_a_verdict_filed_without_the_location_prefix_is_surfaced(tmp_path):
    """The stall the console exists to prevent, made visible rather than assumed away.

    The guard constrains the analyst's sentence. It cannot constrain the argument
    the Copilot's model passes, and `job_X` is the same job to a person and a
    different string to `wait_for`.
    """
    bench = _finding_bench(tmp_path, [
        {"kind": "VERDICT", "subject": BARE, "decision_id": "vd_1", "ts": "now",
         "disposition": "confirmed abuse"}])
    out = bench.finding()
    assert out["decision"] is None
    assert out["near_miss"]["subject"] == BARE
    assert out["near_miss"]["decision_id"] == "vd_1"


def test_the_right_subject_reports_no_near_miss(tmp_path):
    bench = _finding_bench(tmp_path, [
        {"kind": "VERDICT", "subject": JOB, "decision_id": "vd_2", "ts": "now",
         "disposition": "confirmed abuse"}])
    out = bench.finding()
    assert out["decision"]["decision_id"] == "vd_2"
    assert "near_miss" not in out, "a found row must not also report a near miss"


def test_an_unrelated_job_is_not_a_near_miss(tmp_path):
    bench = _finding_bench(tmp_path, [
        {"kind": "VERDICT", "subject": "europe-west3:job_SOMETHINGELSE",
         "decision_id": "vd_3", "ts": "now", "disposition": "false positive"}])
    out = bench.finding()
    assert out["decision"] is None
    assert out["near_miss"] is None


def test_a_subject_with_no_prefix_has_no_bare_form(tmp_path):
    """near_miss must not match everything when the subject carries no prefix."""
    source = workbench.LiveSource("devpost-hackathon-506416", "http://127.0.0.1:1",
                                  workbench.Tokens())
    assert source.near_miss("VERDICT", "v6") is None


def test_the_near_miss_query_requires_a_prefix_boundary(monkeypatch):
    """`something_job_X` is not a near miss of `europe-west3:job_X`.

    A plain ENDS_WITH on the bare id matches any subject ending in those
    characters, and telling an analyst to re-file a verdict that was already
    correct is its own failure.
    """
    seen = {}

    def fake_query(sql, project, token, **kwargs):
        seen["sql"] = sql
        seen["params"] = kwargs.get("params")
        return []

    monkeypatch.setattr(workbench.bq, "query", fake_query)
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    source = workbench.LiveSource("devpost-hackathon-506416", "http://127.0.0.1:1",
                                  workbench.Tokens())
    assert source.near_miss("VERDICT", JOB) is None
    assert "subject = @bare" in seen["sql"]
    assert "CONCAT(':', @bare)" in seen["sql"], (
        "an unanchored ENDS_WITH matches an unrelated subject")
    assert seen["params"]["bare"] == BARE
    # The id itself never reaches the SQL text.
    assert BARE not in seen["sql"]


# --------------------------------------------------------------------------
# A stale file must not pose as the finding under review
# --------------------------------------------------------------------------

def test_a_finding_carries_its_age(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    out = workbench.read_finding(path)
    assert out["age_s"] >= 0
    assert out["age_s"] < 60


def test_an_old_finding_reports_a_large_age(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    import os

    old = time.time() - 7200
    os.utime(path, (old, old))
    assert workbench.read_finding(path)["age_s"] > 3600


# --------------------------------------------------------------------------
# Every link kind the chain defines must survive the trip to the browser
# --------------------------------------------------------------------------

def test_all_nine_link_kinds_reach_the_browser():
    """DRAFT-REJECTED and EVIDENCE-CHANGED are in no fixture, so nothing else draws them.

    ponytail: still a text assertion, because the suite runs no JavaScript. It is a
    stronger one than it was. The previous version asserted only that `.k-<KIND>`
    appeared somewhere in the file, so it passed against a stylesheet no element ever
    carried: measured in a browser, all nine kinds drew as the same grey. A rule
    existing is not a rule reaching anything. Executing renderStrip is the real
    check and wants a DOM this suite does not have.
    """
    from caseharden.chain import build

    links = build("v9", [(kind, {"kind_under_test": kind}) for kind in KINDS])
    rows = [workbench.link_row(l) for l in links]
    assert [r["kind"] for r in rows] == list(KINDS)
    assert len(KINDS) == 9
    assert all(r["intact"] for r in rows)
    assert all(r["hash"] and r["seq"] for r in rows)

    page = workbench.PAGE.read_text()
    for kind in KINDS:
        assert f".k-{kind}" in page, f"the timeline has no styling for {kind}"

    # The styling has to reach an element. Nothing above proves that, and for as
    # long as this test was only the loop above, nothing did.
    assert 'el("div", "kind k-" + kindClass(l.kind), l.kind)' in page, \
        "the strip no longer puts the kind's class on the element it draws"
    assert 'el("div", "kind", l.kind)' not in page, \
        "the unstyled kind label is back"

    # And it has to win the cascade. `.step .kind` sets a colour at two classes,
    # so a bare `.k-KIND` rule loses to it and is dead while still being present,
    # which is exactly what this test used to accept.
    for selector in re.findall(r"\.k-[A-Z-]+", page):
        assert f".kind{selector}" in page, \
            f"{selector} is written without .kind and loses to `.step .kind`"


# --------------------------------------------------------------------------
# The offline re-check must report a crash as a failed check
# --------------------------------------------------------------------------

def test_a_malformed_exam_payload_is_a_failed_check_not_a_traceback(tmp_path):
    """These checks index into payloads a tamper controls.

    Deleting the `benign` key made check_exam raise a KeyError that walked past
    every remaining check and out of the program. In the workbench that is a
    blank pane; on the command line it is a traceback where a FAIL line belongs.
    """
    from caseharden.recheck import run_checks

    directory = tmp_path / "v5"
    directory.mkdir()
    for name in ("chain.jsonl", "certificate.json", "source.json"):
        (directory / name).write_text((FIXTURE / name).read_text())

    lines = (directory / "chain.jsonl").read_text().splitlines()
    for i, line in enumerate(lines):
        row = json.loads(line)
        if row["kind"] == "EXAM":
            row["payload"].get("exam", row["payload"]).pop("benign", None)
            lines[i] = json.dumps(row, sort_keys=True)
    (directory / "chain.jsonl").write_text("\n".join(lines) + "\n")

    result = run_checks(directory, quiet=True)
    assert result.failed, "a crashing check recorded nothing"
    assert any("could be run" in title or "KeyError" in str(detail)
               for _ok, title, detail in result.failed)


def test_the_workbench_renders_a_fixture_whose_exam_is_malformed(tmp_path):
    """Fixture mode is the recovery path, so it must survive a broken fixture."""
    directory = tmp_path / "v5"
    directory.mkdir()
    for name in ("chain.jsonl", "certificate.json", "source.json"):
        (directory / name).write_text((FIXTURE / name).read_text())
    lines = (directory / "chain.jsonl").read_text().splitlines()
    for i, line in enumerate(lines):
        row = json.loads(line)
        if row["kind"] == "EXAM":
            row["payload"].get("exam", row["payload"]).pop("benign", None)
            lines[i] = json.dumps(row, sort_keys=True)
    (directory / "chain.jsonl").write_text("\n".join(lines) + "\n")

    state = workbench.FixtureSource(directory).state(None)
    assert state["attestation"]["attested"] is False
    assert state["attestation"]["checks_failed"]


def test_skip_replay_does_not_claim_the_replay(tmp_path, capsys):
    """--skip-replay used to end on 'The Examiner replay proves its measurements
    were not invented', which is the one claim that flag turns off."""
    from caseharden.recheck import recheck

    assert recheck(FIXTURE, skip_replay=True) == 0
    out = capsys.readouterr().out
    assert "NOT run" in out
    assert "replay proves its measurements were not invented" not in out


def test_a_full_recheck_still_claims_the_replay(capsys):
    from caseharden.recheck import recheck

    assert recheck(FIXTURE) == 0
    out = capsys.readouterr().out
    assert "replay proves its measurements were not invented" in out


# --------------------------------------------------------------------------
# The console never states an outcome it did not receive from the server.
# Two more defects of that family, found by a review on 2026-08-29.
# --------------------------------------------------------------------------

class _Answered:
    """A Policy Server that answers. `json.load` reads through `read`."""

    def __init__(self, payload):
        self._payload = payload

    def read(self):
        import json as _json
        return _json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def test_the_unknown_state_is_marked_as_this_consoles_own_word(monkeypatch):
    """UNREACHABLE is minted in the exception handler. Nothing reported it.

    The page says who reported the state, in words, so the payload has to carry
    which of the two it is. Without this flag the console printed 'State reported
    by the Policy Server: UNREACHABLE' for a server that never answered.
    """
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v5", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read", lambda self, v: [])
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "http://127.0.0.1:1", workbench.Tokens())
    att = source.state(None)["attestation"]
    assert att["policy_server_reached"] is False
    assert att["error"], "the only account of what failed was dropped"
    assert att["policy_url"]


def test_a_policy_server_that_answers_is_marked_reached(monkeypatch):
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v5", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read", lambda self, v: [])
    monkeypatch.setattr(workbench.urllib.request, "urlopen",
                        lambda *_a, **_k: _Answered(
                            {"version": "v5", "attested": True, "state": "ATTESTED"}))
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "https://policy.example.run.app", workbench.Tokens())
    att = source.state(None)["attestation"]
    assert att["policy_server_reached"] is True
    assert att["state"] == "ATTESTED"


def test_the_flag_tracks_who_answered_not_what_they_said(monkeypatch):
    """A Policy Server is allowed to report UNREACHABLE about something else.

    That answer came from the server and may be attributed to it. A flag keyed on
    the value rather than on provenance would call this one unreached, which is
    the same confusion in the other direction.
    """
    monkeypatch.setattr(workbench.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(workbench.ChainStore, "versions",
                        lambda self: [{"version": "v5", "active": "true"}])
    monkeypatch.setattr(workbench.ChainStore, "read", lambda self, v: [])
    monkeypatch.setattr(workbench.urllib.request, "urlopen",
                        lambda *_a, **_k: _Answered(
                            {"version": "v5", "attested": False, "state": "UNREACHABLE"}))
    source = workbench.LiveSource("devpost-hackathon-506416",
                                  "https://policy.example.run.app", workbench.Tokens())
    att = source.state(None)["attestation"]
    assert att["policy_server_reached"] is True
    assert att["state"] == "UNREACHABLE"


def _before(page, needle, window=900):
    """The slice of page text leading up to `needle`, for a coupling assertion."""
    at = page.find(needle)
    assert at != -1, f"{needle!r} is no longer on the page"
    return page[max(0, at - window):at]


def test_a_delivery_claim_is_coupled_to_a_row_the_send_produced():
    """ponytail: text assertions, because the suite runs no JavaScript.

    Weaker than executing the branch, and named so rather than dressed up. The
    upgrade path is a node harness over the page's pure functions; node is on
    this machine but adding a JS runner to the suite two days before submission
    buys less than it risks. What these do catch is the exact regression: a claim
    of delivery that is not guarded by the freshness comparison.
    """
    page = workbench.PAGE.read_text()
    assert "const decisionBefore = box.decision" in page, "the baseline is gone"
    assert "fresh: S(row.decision_id) !== decisionBefore" in page
    for claim in ("A verdict is on this case now.",
                  "Recorded. A verdict row is there now."):
        assert "back.fresh" in _before(page, claim), \
            f"{claim!r} is no longer guarded by the freshness check"
    assert "if (later && later.decision && !later.decision_error) stored" not in page, \
        "the old any-row-is-proof readback is back"

    # A 200 is not a finding. read_finding answers present:false with an `error`
    # for a half-written file and without one when there is no file, and neither
    # involved a decision lookup. The boot path checks box.error; the readback
    # did not, which is how the already-fixed defect came back on a new path.
    assert "later.present !== true || later.error" in page, \
        "a failed or absent finding read classifies as an absence again"
    assert 'S((later.finding || {}).job_id || "") !== BOOT_JOB' in page, \
        "a readback about a different case counts as an answer about this one"


def test_a_payload_field_that_should_be_a_list_is_named_when_it_is_not():
    """`_shape_of_payload` requires these keys to exist, not to be lists.

    A served link with `access` as an object reached `(p.access || []).join(...)`
    and threw, which drew an empty pane rather than a malformed record. Widening
    the EVIDENCE branch to EVIDENCE-CHANGED widened that exposure too.
    """
    page = workbench.PAGE.read_text()
    assert "(p.access || []).join" not in page, "a non-list access field throws again"
    assert "listSays(p.access" in page
    # Pin the guard, not just the call site: a listSays whose body dropped the
    # isArray check would leave every call site reading exactly as it does now.
    assert "function listSays(v, malformed){ return Array.isArray(v) ? v.join" in page, \
        "listSays no longer checks that the value is a list"
    assert "Array.isArray(p.checks)" in page, "a non-list checks field throws"


def test_the_unknown_state_is_not_attributed_to_the_policy_server():
    page = workbench.PAGE.read_text()
    claim = "State reported by the Policy Server: "
    # Ordering, not a byte window: the guard branch has to open before the only
    # sentence that names the Policy Server as the source of the state.
    assert page.count(claim) == 1, "a second, unguarded attribution appeared"
    guard = page.find("att.policy_server_reached === false")
    assert guard != -1, "the reached check is gone"
    assert guard < page.find(claim), \
        "the attribution is no longer behind the reached check"
    assert "UNREACHABLE is this page's word for not knowing" in page
    assert "att.error" in page, "the reason the request failed is dropped again"


# --------------------------------------------------------------------------
# The case routes
# --------------------------------------------------------------------------

def _open_case(tmp_path, **over):
    payload = {"job_id": JOB, "family": "injected_turn", "sessions_total": 27,
               "rows": [{"session_id": "s_1"}]}
    payload.update(over)
    return cases.open_case(tmp_path / cases.CASES_DIRNAME, payload)


def test_the_queue_route_lists_what_the_store_holds(served, tmp_path):
    """`served` writes the live finding into tmp_path, so cases sit beside it."""
    opened = _open_case(tmp_path)
    status, _, raw = _request(served, "GET", "/api/cases")
    assert status == 200
    listed = json.loads(raw)
    assert listed["total"] == 1
    row = listed["cases"][0]
    assert row["case_id"] == opened["case_id"] and row["job_id"] == JOB
    assert "decision" not in row, "a disposition here would be a second copy of the row"


def test_a_case_id_the_store_could_not_have_written_is_a_400(served):
    for bad in ("..%2F..%2Fetc%2Fpasswd", "zzzz", "a" * 40):
        status, _, _ = _request(served, "GET", f"/api/cases?id={bad}")
        assert status == 400, bad


def test_a_well_formed_id_with_no_case_is_a_404(served):
    status, _, _ = _request(served, "GET", "/api/cases?id=" + "0" * 16)
    assert status == 404


def test_one_case_answers_with_its_own_evidence(served, tmp_path):
    opened = _open_case(tmp_path)
    status, _, raw = _request(served, "GET", f"/api/cases?id={opened['case_id']}")
    assert status == 200
    got = json.loads(raw)
    assert got["case"]["job_id"] == JOB
    assert got["case"]["finding"]["rows"] == [{"session_id": "s_1"}]


class _Stub(workbench.Source):
    """A source with a warehouse behind it, without a project to reach."""

    mode = "stub"

    def __init__(self, decided=None, row=None):
        self._decided = decided
        self._row = row

    def decided_subjects(self, kind):
        if isinstance(self._decided, Exception):
            raise self._decided
        return self._decided

    def decision(self, kind, subject):
        return self._row


def _queue_bench(tmp_path, source):
    return workbench.Workbench(source, finding_path=tmp_path / "finding-live.json")


def test_a_decided_case_and_a_waiting_one_are_told_apart(tmp_path):
    _open_case(tmp_path)
    _open_case(tmp_path, job_id="europe-west3:job_waiting")
    listed = _queue_bench(tmp_path, _Stub(decided={JOB})).cases()
    by_job = {row["job_id"]: row["decided"] for row in listed["cases"]}
    assert by_job == {JOB: "yes", "europe-west3:job_waiting": "no"}


def test_a_source_that_cannot_know_says_unknown_and_not_waiting(tmp_path):
    """A fixture has no review table, and 'no' would be a claim nothing checked."""
    _open_case(tmp_path)
    listed = _queue_bench(tmp_path, _Stub(decided=None)).cases()
    assert listed["cases"][0]["decided"] == "unknown"


def test_a_warehouse_that_errors_says_unknown_and_says_why(tmp_path):
    _open_case(tmp_path)
    listed = _queue_bench(tmp_path, _Stub(decided=RuntimeError("403 on review.decisions"))).cases()
    assert listed["cases"][0]["decided"] == "unknown"
    assert "403 on review.decisions" in listed["decided_error"]


def test_the_queue_still_carries_no_disposition(tmp_path):
    _open_case(tmp_path)
    row = _queue_bench(tmp_path, _Stub(decided={JOB})).cases()["cases"][0]
    assert set(row) & {"disposition", "rationale", "analyst", "approved"} == set()


def test_a_verdict_older_than_the_revision_is_flagged(tmp_path):
    """Revision 1's rows beside a review row filed against revision 0."""
    _open_case(tmp_path)
    opened = _open_case(tmp_path, rows=[{"session_id": "s_2"}])
    assert opened["revisions"] == 1
    bench = _queue_bench(tmp_path, _Stub(row={"ts": "2020-01-01T00:00:00Z"}))
    assert bench.case(opened["case_id"])["verdict_predates_revision"] is True


def test_a_verdict_after_the_revision_is_not_flagged(tmp_path):
    _open_case(tmp_path)
    opened = _open_case(tmp_path, rows=[{"session_id": "s_2"}])
    bench = _queue_bench(tmp_path, _Stub(row={"ts": "2099-01-01T00:00:00Z"}))
    assert bench.case(opened["case_id"])["verdict_predates_revision"] is False


def test_a_case_never_revised_makes_no_claim_either_way(tmp_path):
    opened = _open_case(tmp_path)
    bench = _queue_bench(tmp_path, _Stub(row={"ts": "2020-01-01T00:00:00Z"}))
    assert bench.case(opened["case_id"])["verdict_predates_revision"] is None


@pytest.mark.parametrize("revised,ts", [
    ("2026-08-30T10:00:00Z", "30 Aug 2026"),
    ("2026-08-30 10:00:00 UTC", "2026-08-30T10:00:00Z"),
    ("2026-08-30T10:00:00Z", None),
    (None, "2026-08-30T10:00:00Z"),
    ("2026-08-30T10:00:00Z", 1756540800),
])
def test_a_timestamp_in_another_shape_is_not_compared(revised, ts):
    """A string compare across two formats answers confidently and wrongly."""
    assert workbench._predates(revised, ts) is None


def test_a_blank_case_id_is_not_the_whole_queue(served, tmp_path):
    """`?id=` asked for one case; parse_qs dropped it and the route sent all of them."""
    _open_case(tmp_path)
    status, _, raw = _request(served, "GET", "/api/cases?id=")
    assert status == 400, raw


def test_a_case_id_with_a_trailing_newline_is_refused_at_the_edge(served):
    status, _, _ = _request(served, "GET", "/api/cases?id=" + "0" * 16 + "%0A")
    assert status == 400


def test_a_blank_version_still_means_the_active_one(served):
    """keep_blank_values must not turn `?version=` into a lookup for ''."""
    status, _, raw = _request(served, "GET", "/api/state?version=")
    assert status == 200
    assert json.loads(raw)["version"] == "v5"


def test_a_store_that_cannot_be_read_does_not_drop_the_connection(tmp_path, monkeypatch):
    """`/api/state` contains its own failures; this route reads a directory too."""
    monkeypatch.setattr(workbench.cases, "list_cases",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no such device")))
    bench = _queue_bench(tmp_path, _Stub(decided=None))
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), workbench.handler_for(bench))
    except (PermissionError, OSError) as exc:
        pytest.skip(f"cannot bind a loopback socket here: {exc}")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status, _, raw = _request(server.server_address, "GET", "/api/cases")
    finally:
        server.shutdown()
        server.server_close()
    assert status == 200
    assert "no such device" in json.loads(raw)["error"]


# --------------------------------------------------------------------------
# The citation, checked where the identity to check it exists
# --------------------------------------------------------------------------
#
# The Analyst Copilot writes the citation and cannot validate it: it holds
# `analyst-sa`, which has WRITER on `review` and no read on `policy`, where the
# version registry lives. This console holds `notary-sa` and already reads that
# registry for its own pane, so the existence check happens here. Nothing below
# is a gate. The row is written before any of it runs; what it decides is what
# the page says about a row that already exists.

VERSIONS = [
    {"version": "v4", "policy_id": "conduct-policy", "promoted_at": "2026-08-20T09:00:00Z"},
    {"version": "v5", "policy_id": None, "promoted_at": "2026-08-25T15:50:00Z"},
    {"version": "v6", "policy_id": "conduct-policy", "promoted_at": "2026-08-28T11:00:00Z"},
    {"version": "p1", "policy_id": "payments-policy", "promoted_at": "2026-08-21T08:00:00Z"},
]


def _cited(**over):
    row = {"kind": "VERDICT", "subject": JOB, "decision_id": "vd_9", "ts": "now",
           "disposition": "confirmed abuse", "citation_source": "ANALYST",
           "cited_policy_id": "conduct-policy", "cited_version": "v5"}
    row.update(over)
    return row


def test_the_version_in_force_is_the_last_one_promoted_before_the_window():
    """v6 exists and was promoted after the window opened, so it was not in force."""
    assert workbench.active_at(VERSIONS, "2026-08-26T00:00:00Z") == "v5"
    assert workbench.active_at(VERSIONS, "2026-08-21T00:00:00Z") == "v4"


def test_a_null_policy_id_belongs_to_the_conduct_line():
    """`ChainStore.register` already holds that convention; this must not disagree."""
    assert workbench.active_at(VERSIONS, "2026-08-26T00:00:00Z", "conduct-policy") == "v5"


def test_active_is_per_policy_line():
    """Two lines exist. A conduct version is not what was in force for payments."""
    assert workbench.active_at(VERSIONS, "2026-08-26T00:00:00Z", "payments-policy") == "p1"


def test_a_window_before_every_promotion_has_no_version_in_force():
    assert workbench.active_at(VERSIONS, "2020-01-01T00:00:00Z") is None


@pytest.mark.parametrize("when", [None, "", "yesterday", "2026-08-26", 1787774304])
def test_a_timestamp_that_is_not_the_fixed_format_answers_not_knowing(when):
    """A wrong answer here tells an analyst their citation is wrong with nothing checked."""
    assert workbench.active_at(VERSIONS, when) is None


def test_a_row_written_before_the_columns_is_not_a_verdict_that_cited_nothing():
    row = {"decision_id": "vd_old", "citation_source": None, "cited_version": None}
    assert workbench.citation_check(row, VERSIONS)["state"] == "PREDATES-COLUMNS"


def test_a_verdict_that_cited_nothing_says_so():
    row = _cited(citation_source="NONE", cited_policy_id=None, cited_version=None)
    assert workbench.citation_check(row, VERSIONS)["state"] == "UNCITED"


def test_a_cited_version_the_registry_holds_is_reported_with_its_promotion():
    out = workbench.citation_check(_cited(), VERSIONS, "2026-08-26T00:00:00Z")
    assert out["state"] == "REGISTERED"
    assert out["promoted_at"] == "2026-08-25T15:50:00Z"
    assert out["active_at_window_start"] == "v5"
    assert out["matches_window"] is True


def test_citing_a_version_promoted_after_the_window_is_shown_not_judged():
    """Not an error. An analyst may be arguing from a later version deliberately."""
    out = workbench.citation_check(_cited(cited_version="v6"), VERSIONS,
                                   "2026-08-26T00:00:00Z")
    assert out["state"] == "REGISTERED"
    assert out["matches_window"] is False
    assert out["active_at_window_start"] == "v5"


def test_a_version_the_registry_does_not_hold_names_nothing():
    out = workbench.citation_check(_cited(cited_version="v99"), VERSIONS)
    assert out["state"] == "UNREGISTERED"


def test_a_version_cited_under_the_wrong_line_names_nothing():
    """`p1` is a payments version. Cited as conduct, it names no row in that line."""
    out = workbench.citation_check(_cited(cited_version="p1"), VERSIONS)
    assert out["state"] == "UNREGISTERED"


def test_an_unreadable_registry_is_cannot_say_and_never_none():
    """An empty list is a registry this console could not read, not a version that is missing."""
    out = workbench.citation_check(_cited(), [])
    assert out["state"] == "REGISTRY-UNKNOWN"


class _RowsWithRegistry(_Rows):
    """A review table and a version registry, counting the reads of each."""

    def __init__(self, rows, versions):
        super().__init__(rows)
        self._versions = versions
        self.registry_reads = 0

    def versions(self):
        self.registry_reads += 1
        return self._versions


def test_the_finding_pane_carries_the_registry_read_of_the_citation(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB, "window_start": "2026-08-26T00:00:00Z"}))
    source = _RowsWithRegistry([_cited(subject=JOB)], VERSIONS)
    out = workbench.Workbench(source, finding_path=path).finding()
    assert out["citation"]["state"] == "REGISTERED"
    assert out["citation"]["matches_window"] is True


def test_an_uncited_verdict_costs_no_registry_query(tmp_path):
    """The console polls this route. A row that cites nothing needs no registry to say so."""
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))
    row = _cited(subject=JOB, citation_source="NONE", cited_policy_id=None,
                 cited_version=None)
    source = _RowsWithRegistry([row], VERSIONS)
    out = workbench.Workbench(source, finding_path=path).finding()
    assert out["citation"]["state"] == "UNCITED"
    assert source.registry_reads == 0


def test_a_registry_read_that_throws_is_cannot_say(tmp_path):
    path = tmp_path / "finding-live.json"
    path.write_text(json.dumps({"job_id": JOB}))

    class _Broken(_Rows):
        def versions(self):
            raise RuntimeError("403 on policy.versions")

    out = workbench.Workbench(_Broken([_cited(subject=JOB)]),
                              finding_path=path).finding()
    assert out["citation"]["state"] == "REGISTRY-UNKNOWN"
    assert "403" in out["citation"]["error"]


def test_the_console_selects_the_columns_the_migration_added():
    """The SELECT and the table drift apart silently; a missing column is a NULL on screen."""
    for column in ("cited_policy_id", "cited_version", "citation_source",
                   "advisory_recommendation", "advisory_rule", "advisory_confidence"):
        assert column in workbench.LiveSource.DECISION_COLUMNS
    assert "*" not in workbench.LiveSource.DECISION_COLUMNS


def test_a_bare_version_resolves_to_the_line_the_registry_holds_it_in():
    """`p1` cited with no line is a payments version, not a missing conduct one.

    Assuming `conduct-policy` for a bare citation would report a real version as
    naming nothing, which is a false alarm about the one field this pane draws.
    """
    out = workbench.citation_check(_cited(cited_policy_id=None, cited_version="p1"),
                                   VERSIONS, "2026-08-26T00:00:00Z")
    assert out["state"] == "REGISTERED"
    assert out["policy_id"] == "payments-policy"
    assert out["active_at_window_start"] == "p1"
