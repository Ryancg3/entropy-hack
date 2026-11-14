"""Tests for field_safety.py — the deterministic field classifier and SQL auditor.

Offline and model-free: these are pure functions, so the tests are the evidence
that the safety check is deterministic (the property the patch needs).

    .venv/bin/python -m pytest tests/test_field_safety.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import field_safety as fs


# --------------------------------------------------------------------------- #
# classify_field
# --------------------------------------------------------------------------- #
def test_secret_fields():
    for name in ["api_key", "apiKey", "password", "pwd", "session_token",
                 "client_secret", "private_key", "password_hash"]:
        assert fs.classify_field(name).tier == "SECRET", name


def test_financial_fields():
    for name in ["ssn", "social_security_number", "bank_account", "routing_number",
                 "iban", "card_number", "cvv", "card_exp", "last4", "tax_id"]:
        assert fs.classify_field(name).tier == "FINANCIAL", name


def test_phi_fields():
    for name in ["diagnosis", "icd10_code", "medication", "rx", "allergy",
                 "lab_result", "visit_reason", "clinical_note", "procedure_code"]:
        assert fs.classify_field(name).tier == "PHI", name


def test_pii_fields():
    for name in ["first_name", "last_name", "patient_name", "dob", "phone",
                 "mobile", "email", "home_address", "mrn", "emergency_contact"]:
        assert fs.classify_field(name).tier == "PII", name


def test_quasi_fields():
    for name in ["zip", "postal_code", "city", "gender", "race", "ethnicity", "age"]:
        assert fs.classify_field(name).tier == "QUASI", name


def test_safe_fields():
    for name in ["patient_id", "facility_id", "department_id", "contact_id",
                 "created_at", "updated_at", "status", "is_active",
                 "facility_name", "department_name"]:
        assert fs.classify_field(name).tier == "SAFE", name


def test_most_sensitive_tier_wins():
    # name that looks both financial (billing) and PII (phone) scores FINANCIAL,
    # because financial is checked first (more sensitive).
    assert fs.classify_field("billing_phone").tier == "FINANCIAL"


def test_classification_is_deterministic():
    a = fs.classify_field("SSN")
    b = fs.classify_field("ssn")
    assert a.tier == b.tier == "FINANCIAL"


def test_sensitive_flag():
    assert fs.classify_field("ssn").sensitive is True
    assert fs.classify_field("diagnosis").sensitive is True
    assert fs.classify_field("facility_id").sensitive is False
    assert fs.classify_field("zip").sensitive is False  # QUASI is not guarded alone


# --------------------------------------------------------------------------- #
# audit_schema
# --------------------------------------------------------------------------- #
def test_audit_schema_counts_and_sensitive():
    schema = {
        "patients": ["patient_id", "first_name", "ssn", "dob", "diagnosis"],
        "facilities": ["facility_id", "facility_name", "created_at"],
    }
    rep = fs.audit_schema(schema)
    assert rep["n_tables"] == 2
    assert rep["n_fields"] == 8
    assert rep["counts"]["FINANCIAL"] == 1  # ssn
    assert rep["counts"]["PHI"] == 1        # diagnosis
    assert ("patients", "ssn", "FINANCIAL") in rep["sensitive_fields"]
    assert ("facilities", "facility_name", "SAFE") not in \
        [(t, c, tr) for (t, c, tr) in rep["sensitive_fields"]]


# --------------------------------------------------------------------------- #
# audit_sql
# --------------------------------------------------------------------------- #
def test_clean_select_is_ok():
    probs = fs.audit_sql("SELECT appointment_id FROM appointments WHERE provider_id = ?")
    assert fs.worst_severity(probs) is None


def test_stacked_statements_flagged():
    codes = {p.code for p in fs.audit_sql("SELECT 1 FROM patients; DROP TABLE patients")}
    assert "stacked_statements" in codes
    assert "write_or_ddl" in codes


def test_write_verb_flagged():
    assert any(p.code == "write_or_ddl"
               for p in fs.audit_sql("DELETE FROM patients WHERE id = 1"))


def test_union_injection_flagged():
    assert any(p.code == "union_injection"
               for p in fs.audit_sql("SELECT name FROM a UNION SELECT api_key FROM secrets"))


def test_tautology_flagged():
    assert any(p.code == "tautology"
               for p in fs.audit_sql("SELECT * FROM patients WHERE name='x' OR 1=1"))


def test_comment_marker_flagged():
    assert any(p.code == "sql_comment"
               for p in fs.audit_sql("SELECT ssn FROM patients -- bypass"))


def test_select_star_flagged():
    assert any(p.code == "select_star" for p in fs.audit_sql("SELECT * FROM patients"))


def test_sensitive_column_selection_flagged():
    probs = fs.audit_sql("SELECT ssn, password FROM staff")
    codes = {p.code for p in probs}
    assert "sensitive_column_financial" in codes
    assert "sensitive_column_secret" in codes


def test_schema_enumeration_noted():
    assert any(p.code == "schema_enumeration"
               for p in fs.audit_sql("SELECT name FROM sqlite_master WHERE type='table'"))


def test_verb_inside_string_literal_not_flagged():
    # 'delete' appears only inside a quoted literal, not as a verb.
    probs = fs.audit_sql("SELECT note FROM n WHERE note = 'please delete me'")
    assert not any(p.code == "write_or_ddl" for p in probs)


def test_empty_sql_no_problems():
    assert fs.audit_sql("") == []
    assert fs.audit_sql("   ") == []
