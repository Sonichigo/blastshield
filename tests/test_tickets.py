import time

import pytest

from blastshield.tickets import TicketError, TicketIssuer


def issuer(ttl: int = 60) -> TicketIssuer:
    return TicketIssuer("secret", ttl)


def test_issue_and_verify_roundtrip():
    iss = issuer()
    token, payload = iss.issue("postgres", "DELETE FROM t WHERE id = 1")
    verified = iss.verify(token, "postgres", "DELETE FROM t WHERE id = 1")
    assert verified.change_id == payload.change_id


def test_ticket_bound_to_exact_change():
    iss = issuer()
    token, _ = iss.issue("postgres", "DELETE FROM t WHERE id = 1")
    with pytest.raises(TicketError, match="differs from the one that was dry-run"):
        iss.verify(token, "postgres", "DELETE FROM t WHERE id = 2")


def test_ticket_bound_to_database():
    iss = issuer()
    token, _ = iss.issue("postgres", "x")
    with pytest.raises(TicketError, match="issued for 'postgres'"):
        iss.verify(token, "mongodb", "x")


def test_tampered_signature_rejected():
    iss = issuer()
    token, _ = iss.issue("postgres", "x")
    body, sig = token.rsplit(".", 1)
    bad = body + "." + ("0" * len(sig))
    with pytest.raises(TicketError, match="signature is invalid"):
        iss.verify(bad, "postgres", "x")


def test_wrong_secret_rejected():
    token, _ = issuer().issue("postgres", "x")
    other = TicketIssuer("different-secret", 60)
    with pytest.raises(TicketError, match="signature is invalid"):
        other.verify(token, "postgres", "x")


def test_expired_ticket_rejected(monkeypatch):
    iss = issuer(ttl=10)
    token, _ = iss.issue("postgres", "x")
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 11)
    with pytest.raises(TicketError, match="expired"):
        iss.verify(token, "postgres", "x")


def test_single_use():
    iss = issuer()
    token, payload = iss.issue("postgres", "x")
    iss.verify(token, "postgres", "x")
    iss.consume(payload.change_id)
    with pytest.raises(TicketError, match="already used"):
        iss.verify(token, "postgres", "x")


def test_garbage_token_rejected():
    with pytest.raises(TicketError, match="Malformed"):
        issuer().verify("not-a-ticket", "postgres", "x")
