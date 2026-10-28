"""Governance signing rotation regression tests."""
from security.governance import GovernanceSigner


def test_new_key_signs_and_verifies():
    signer = GovernanceSigner(hmac_key=b"new-secret")
    signature = signer.sign("request", "123")
    assert signer.verify("request", signature)
    assert not signer.verify("modified", signature)


def test_previous_key_is_verify_only(monkeypatch):
    old = GovernanceSigner(hmac_key=b"previous-secret")
    previous_signature = old.sign("request", "123")
    monkeypatch.setenv("OMNIGUARD_HMAC_PREVIOUS_KEYS", "previous-secret")
    from security import governance
    monkeypatch.setattr(governance, "OMNIGUARD_HMAC_KEY_BYTES", b"current-secret")
    current = GovernanceSigner()
    assert current.verify("request", previous_signature)
    assert current.sign("request", "123").signature != previous_signature.signature
    monkeypatch.delenv("OMNIGUARD_HMAC_PREVIOUS_KEYS")
    retired = GovernanceSigner()
    assert not retired.verify("request", previous_signature)


def test_invalid_algorithm_rejected():
    signer = GovernanceSigner(hmac_key=b"secret")
    signature = signer.sign("request", "123")
    signature.algorithm = "other"
    assert not signer.verify("request", signature)
