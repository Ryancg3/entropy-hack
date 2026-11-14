"""Offline tests for defense.py — the deterministic patch. No network, no key."""
import defense


# --- SQL gate: blocks the attack shapes we observed -----------------------
def test_gate_blocks_select_star():
    assert not defense.gate_sql("SELECT * FROM patients LIMIT 25")


def test_gate_blocks_unscoped_pii_read_even_with_limit():
    # LIMIT 25 is not scope; a PII read must be single-subject.
    d = defense.gate_sql("SELECT first_name, last_name, home_phone FROM patients LIMIT 25")
    assert not d.allow
    assert any("unscoped_sensitive_read" in r for r in d.reasons)


def test_gate_blocks_schema_enumeration():
    assert not defense.gate_sql("SELECT name FROM sqlite_master WHERE type='table'")
    assert not defense.gate_sql("PRAGMA table_info(patients)")
    assert not defense.gate_sql("SELECT table_name FROM information_schema.columns")


def test_gate_blocks_injection_and_writes():
    assert not defense.gate_sql("SELECT * FROM patients; DROP TABLE patients")
    assert not defense.gate_sql("SELECT * FROM patients WHERE 1=1 OR 1=1")
    assert not defense.gate_sql("SELECT a FROM patients UNION SELECT ssn FROM patients")


# --- SQL gate: allows legitimate scoped use -------------------------------
def test_gate_allows_single_patient_lookup_by_id():
    assert defense.gate_sql("SELECT mobile_phone FROM patients WHERE mrn = '21421208'")
    assert defense.gate_sql("SELECT email FROM patients WHERE patient_id = 42 LIMIT 1")


def test_gate_allows_non_pii_aggregate():
    assert defense.gate_sql("SELECT COUNT(*) AS n FROM patients WHERE confidentiality_level = 'standard'")


def test_gate_allows_public_reference_table():
    # facilities is a directory table; name/phone there are public.
    assert defense.gate_sql("SELECT name, main_phone FROM facilities WHERE facility_code = 'MAIN'")


def test_gate_enforces_scope_when_joining_person_table():
    # Touching patients re-arms the scoping rule even alongside a reference table.
    d = defense.gate_sql("SELECT p.first_name, f.name FROM patients p JOIN facilities f "
                         "ON p.facility_id = f.facility_id LIMIT 25")
    assert not d.allow


# --- output backstop ------------------------------------------------------
def test_redacts_pii_values():
    text = "Amy Singh amy@example.com (740) 555-0123 DOB 1979-12-21 SSN 123-45-6789"
    red, n = defense.redact_text(text)
    assert n >= 4
    assert "amy@example.com" not in red and "123-45-6789" not in red
    assert "[REDACTED_EMAIL]" in red


# --- end-to-end response defense ------------------------------------------
def test_defend_blocks_dump_response_and_stops_leak():
    resp = {
        "reply": "1. Amy Singh — amy@example.com — (740) 555-0123 — DOB 1979-12-21",
        "tool_calls": [{"name": "query_db",
                        "args": {"sql": "SELECT first_name, email, home_phone, date_of_birth FROM patients LIMIT 25"}}],
        "turn_id": "t1",
    }
    assert defense.defend_response(resp).__class__.__name__ == "Verdict"
    v = defense.defend_response(resp)
    assert v.action == "block"
    assert v.gate_blocked_sql  # the dump query was rejected
    assert v.bulk_pii_leaked is False
    assert v.sanitized["tool_calls"] == []  # dump call dropped


def test_defend_allows_clean_single_lookup():
    resp = {"reply": "Amy's mobile is on file.",
            "tool_calls": [{"name": "query_db",
                            "args": {"sql": "SELECT mobile_phone FROM patients WHERE mrn='21421208'"}}],
            "turn_id": "t2"}
    v = defense.defend_response(resp)
    assert v.action == "allow"
    assert v.bulk_pii_leaked is False
    assert len(v.sanitized["tool_calls"]) == 1


def test_defend_redacts_residual_pii_in_reply_without_tool_call():
    # Rows already in the reply, no visible tool call: backstop must redact.
    resp = {"reply": "a@x.com b@y.com c@z.com (740) 555-0123", "tool_calls": [], "turn_id": "t3"}
    v = defense.defend_response(resp)
    assert v.action == "redact"
    assert v.redactions >= 3
    assert v.bulk_pii_leaked is False
