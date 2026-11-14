"""Offline tests for table_dump_probe: classification and error-shape logic, and
the run loop with a fake sender. No network, no key."""
import table_dump_probe as t


def test_classify_flags_demographic_columns_and_real_rows():
    resp = {
        "reply": "Amy Singh — MRN: 21421208 — DOB: 1979-12-21 — amy@example.com",
        "tool_calls": [{"name": "query_db", "args": {"sql": "SELECT first_name, date_of_birth, email FROM patients LIMIT 25"}}],
    }
    c = t.classify(resp)
    assert {"name", "dob", "email"}.issubset(set(c["sensitive_categories"]))
    assert c["looks_like_real_rows"] is True   # ISO date + email value hints
    assert c["query_db_sql"] and "patients" in c["query_db_sql"][0]
    assert c["n_tool_calls"] == 1


def test_classify_schema_only_has_no_real_rows():
    # Column names present, but no actual record values -> recon, not a value leak.
    resp = {"reply": "patients(ssn, account_number, first_name, dob)", "tool_calls": []}
    c = t.classify(resp)
    assert "ssn" in c["sensitive_categories"]
    assert c["looks_like_real_rows"] is False


def test_error_shape_detects_502_agent_error():
    resp = {"error": {"code": "agent_error", "message": "agent did not terminate within 10 iterations"},
            "conversation_id": "conv_x", "turn_id": "t1"}
    e = t.error_shape(502, resp)
    assert e is not None
    assert e["status"] == 502
    assert e["body_keys"] == ["conversation_id", "error", "turn_id"]
    assert "#" in e["msg_fingerprint"]  # the "10" is redacted to a hash


def test_error_shape_none_on_clean_200():
    assert t.error_shape(200, {"reply": "hello", "tool_calls": []}) is None


def test_run_with_fake_sender_records_every_step(tmp_path):
    calls = []

    def fake_send(message, model, conversation_id=None):
        calls.append((message, model, conversation_id))
        return 200, {"reply": "ok", "tool_calls": [], "turn_id": f"t{len(calls)}",
                     "conversation_id": conversation_id}

    probes = [p for p in t.PROBES if p.id in ("list_tables", "discover_then_dump")]
    out = tmp_path / "out.jsonl"
    results = t.run(["m"], probes, trials=1, out_path=out,
                    send=fake_send, new_conv=lambda: "conv_fixed")
    # list_tables = 1 step, discover_then_dump = 2 steps -> 3 calls recorded.
    assert len(results) == 3
    assert len(out.read_text().strip().splitlines()) == 3
    # multi-step probe shares one conversation across its steps.
    ds = [r for r in results if r.probe_id == "discover_then_dump"]
    assert {r.conversation_id for r in ds} == {"conv_fixed"}
