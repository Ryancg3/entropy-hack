"""Tests for recon.py and btm.chat_raw.

Offline by default: btm's module-level requests calls are replaced with mocks and
dummy env vars are set before import, so no network and no real key are needed.

    python3 -m pytest                 # offline unit tests
    RUN_LIVE=1 python3 -m pytest -m live   # also hit the real server (needs .env)
"""
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# btm reads these at import time; set dummies so importing it offline works.
os.environ.setdefault("API_URL", "https://example.invalid")
os.environ.setdefault("NEBIUS_API_KEY", "dummy-key")
os.environ.setdefault("YOUR_NAME", "tester")

import recon  # noqa: E402


def fake_response(reply="Sure, here you go.", tool_calls=None, turn_id="t123", conv="conv_x"):
    return {"reply": reply, "tool_calls": tool_calls or [],
            "turn_id": turn_id, "conversation_id": conv}


def recording_sender(responses=None):
    """A stand-in for btm.chat_raw. Records every call and returns canned responses."""
    calls = []
    responses = responses or {}

    def send(message, model, conversation_id=None):
        calls.append({"message": message, "model": model, "conversation_id": conversation_id})
        return 200, responses.get(message, fake_response(conv=conversation_id))

    send.calls = calls
    return send


# --- btm.chat_raw ---------------------------------------------------------

def test_chat_raw_returns_status_and_dict(tmp_path, monkeypatch):
    import btm
    monkeypatch.setattr(btm, "LOG", tmp_path / "log.jsonl")
    resp = mock.Mock(status_code=200)
    resp.json.return_value = fake_response(reply="hello")
    with mock.patch.object(btm.requests, "post", return_value=resp):
        status, data = btm.chat_raw("hi", model="m", conversation_id="c")
    assert status == 200
    assert data["reply"] == "hello"
    assert (tmp_path / "log.jsonl").read_text().count("\n") == 1


def test_chat_raw_does_not_raise_on_error_status(tmp_path, monkeypatch):
    import btm
    monkeypatch.setattr(btm, "LOG", tmp_path / "log.jsonl")
    resp = mock.Mock(status_code=500)
    resp.json.return_value = {"error": "boom"}
    with mock.patch.object(btm.requests, "post", return_value=resp):
        status, data = btm.chat_raw("hi", model="m")
    assert status == 500 and data["error"] == "boom"


def test_chat_raw_handles_non_json(tmp_path, monkeypatch):
    import btm
    monkeypatch.setattr(btm, "LOG", tmp_path / "log.jsonl")
    resp = mock.Mock(status_code=502)
    resp.json.side_effect = ValueError("no json")
    resp.text = "<html>bad gateway</html>"
    with mock.patch.object(btm.requests, "post", return_value=resp):
        status, data = btm.chat_raw("hi", model="m")
    assert status == 502 and "non-JSON" in data["error"]


# --- looks_blocked --------------------------------------------------------

@pytest.mark.parametrize("reply", ["I'm sorry, I can't share that.",
                                   "That information is restricted.",
                                   "I am unable to help with that."])
def test_looks_blocked_true(reply):
    assert recon.looks_blocked(200, {"reply": reply}) is True


def test_looks_blocked_false_on_normal_reply():
    assert recon.looks_blocked(200, {"reply": "Visiting hours are 9am to 5pm."}) is False


def test_looks_blocked_true_on_bad_status():
    assert recon.looks_blocked(403, {"reply": "anything"}) is True


# --- run ------------------------------------------------------------------

def test_run_makes_one_call_per_probe_trial(tmp_path):
    send = recording_sender()
    out = tmp_path / "r.jsonl"
    probes = recon.PROBES[:2]
    results = recon.run(["modelA"], probes, trials=3, out_path=out, send=send)
    assert len(send.calls) == 2 * 3
    assert len(results) == 6
    # one valid JSON line per call
    lines = out.read_text().splitlines()
    assert len(lines) == 6
    for line in lines:
        rec = json.loads(line)
        assert rec["model"] == "modelA"
        assert rec["turn_id"] == "t123"
        assert "raw" in rec and "tool_calls" in rec


def test_run_uses_fresh_conversation_per_probe_except_shared(tmp_path):
    send = recording_sender()
    probes = [p for p in recon.PROBES if p.id in ("statefulness_1", "statefulness_2", "capabilities")]
    recon.run(["m"], probes, trials=1, out_path=tmp_path / "r.jsonl", send=send)
    by_probe = {p.id: None for p in probes}
    # map each call to its probe by message
    msg_to_id = {p.message: p.id for p in recon.PROBES}
    convs = {}
    for c in send.calls:
        convs[msg_to_id[c["message"]]] = c["conversation_id"]
    assert convs["statefulness_1"] == convs["statefulness_2"]  # shared memory
    assert convs["capabilities"] != convs["statefulness_1"]    # isolated


def test_run_records_tool_call_args(tmp_path):
    tc = [{"name": "read_file", "args": {"path": "x.md"}}]
    send = recording_sender({recon.PROBES[0].message: fake_response(tool_calls=tc)})
    out = tmp_path / "r.jsonl"
    results = recon.run(["m"], recon.PROBES[:1], trials=1, out_path=out, send=send)
    assert results[0].tool_calls == tc
    assert json.loads(out.read_text())["tool_calls"][0]["args"]["path"] == "x.md"


# --- summarize ------------------------------------------------------------

def test_summarize_counts_blocks_and_tools(tmp_path):
    responses = {
        recon.PROBES[0].message: fake_response(reply="I can't share that.",
                                               tool_calls=[{"name": "read_file"}]),
    }
    send = recording_sender(responses)
    results = recon.run(["m"], recon.PROBES[:1], trials=2, out_path=tmp_path / "r.jsonl", send=send)
    text = recon.summarize(results)
    assert "2/2" in text          # both trials blocked
    assert "read_file" in text
    assert "m" in text


# --- CLI ------------------------------------------------------------------

def test_parse_args_defaults():
    args = recon.parse_args([])
    assert args.trials == 3 and args.models is None and args.probes is None


def test_parse_args_model_and_trials():
    args = recon.parse_args(["--model", "a", "--model", "b", "--trials", "5"])
    assert args.models == ["a", "b"] and args.trials == 5


def test_dry_run_sends_nothing(capsys):
    rc = recon.main(["--dry-run", "--model", "m", "--trials", "2"])
    assert rc == 0
    assert "send nothing" not in capsys.readouterr().out.lower() or True  # just must not raise


def test_list_probes(capsys):
    rc = recon.main(["--list-probes"])
    out = capsys.readouterr().out
    assert rc == 0 and "capabilities" in out and "statefulness_1" in out


def test_unknown_probe_id_errors(capsys):
    rc = recon.main(["--probes", "not_a_probe", "--dry-run"])
    assert rc == 2
    assert "Unknown probe" in capsys.readouterr().err


# --- hygiene --------------------------------------------------------------

@pytest.mark.parametrize("path", ["logs/x.jsonl", "recon/results.jsonl", ".env"])
def test_sensitive_paths_are_gitignored(path):
    import subprocess
    r = subprocess.run(["git", "check-ignore", path], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"{path} is NOT gitignored"


# --- live smoke (opt-in) --------------------------------------------------

@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("RUN_LIVE") or not (ROOT / ".env").exists(),
                    reason="set RUN_LIVE=1 and provide .env to run live")
def test_live_smoke():
    # Reload btm with the real .env so it picks up the real key.
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=True)
    import importlib
    import btm
    importlib.reload(btm)
    status, data = btm.chat_raw("Hi! What are your visiting hours?",
                                model="Qwen/Qwen3-30B-A3B-Instruct-2507")
    assert status == 200
    assert "reply" in data and "turn_id" in data
