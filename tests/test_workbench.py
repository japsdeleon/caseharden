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
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "generator"))

from caseharden import workbench  # noqa: E402
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


def test_a_deeply_nested_chat_body_is_a_400(served):
    body = "[" * 1200 + "]" * 1200
    connection = http.client.HTTPConnection(*served, timeout=30)
    connection.request("POST", "/api/chat", body=body.encode(),
                       headers={"Content-Type": "application/json"})
    assert connection.getresponse().status == 400
    connection.close()


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
    """DRAFT-REJECTED and EVIDENCE-CHANGED are in no fixture, so nothing else draws them."""
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
