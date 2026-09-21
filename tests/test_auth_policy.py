import pytest

from vguard.auth_policy import AuthorizationDenied, RBACPolicy, TokenIssuer


def test_default_deny():
    policy = RBACPolicy()
    assert not policy.is_allowed("alice", "query", "finance")
    with pytest.raises(AuthorizationDenied):
        policy.allow("alice", "query", "finance")


def test_wildcard_allow():
    policy = RBACPolicy()
    policy.add_rule(principal="alice", action="query", namespace="finance")
    assert policy.is_allowed("alice", "query", "finance")
    assert not policy.is_allowed("alice", "query", "reports")
    assert not policy.is_allowed("bob", "query", "finance")


def test_explicit_deny_wins():
    policy = RBACPolicy()
    policy.add_rule(principal="*", action="*", namespace="*", effect="allow")
    policy.add_rule(principal="malice", action="*", namespace="*", effect="deny")
    assert policy.is_allowed("carol", "query", "anything")
    assert not policy.is_allowed("malice", "query", "anything")


def test_namespace_restricted():
    policy = RBACPolicy()
    policy.add_rule(principal="alice", action="query", namespace="hr")
    assert policy.is_allowed("alice", "query", "hr")
    assert not policy.is_allowed("alice", "query", "security")


def test_action_restricted():
    policy = RBACPolicy()
    policy.add_rule(principal="alice", action="read", namespace="hr")
    assert policy.is_allowed("alice", "read", "hr")
    assert not policy.is_allowed("alice", "write", "hr")


def test_token_issue_and_verify():
    issuer = TokenIssuer("super-secret-master-key")
    token = issuer.issue("alice", "finance")
    principal, namespace = issuer.verify(token)
    assert principal == "alice"
    assert namespace == "finance"


def test_token_tamper_rejected():
    issuer = TokenIssuer("super-secret-master-key")
    token = issuer.issue("alice", "finance")
    with pytest.raises(AuthorizationDenied):
        issuer.verify(token + "tampered")


def test_different_secret_rejects():
    issuer_a = TokenIssuer("secret-a")
    token = issuer_a.issue("alice", "finance")
    issuer_b = TokenIssuer("secret-b")
    with pytest.raises(AuthorizationDenied):
        issuer_b.verify(token)