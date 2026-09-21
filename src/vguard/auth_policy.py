# src/vguard/auth_policy.py
from dataclasses import dataclass
from typing import List, NamedTuple


class AuthorizationDenied(Exception):
    pass


class Rule(NamedTuple):
    principal: str
    action: str
    namespace: str
    effect: str = "allow"


@dataclass
class RBACPolicy:
    rules: List[Rule] = None
    default_deny: bool = True

    def __post_init__(self):
        self.rules = list(self.rules or [])

    def allow(self, principal: str, action: str, namespace: str) -> None:
        matched = [
            r
            for r in self.rules
            if r.namespace in ("*", namespace)
            and r.action in ("*", action)
            and (r.principal == principal or r.principal == "*")
        ]
        if not matched and self.default_deny:
            raise AuthorizationDenied(
                f"Access denied for principal '{principal}' action='{action}' namespace='{namespace}'."
            )
        if any(r.effect == "deny" for r in matched):
            raise AuthorizationDenied(
                f"Explicit deny for principal '{principal}' action='{action}' namespace='{namespace}'."
            )

    def is_allowed(self, principal: str, action: str, namespace: str) -> bool:
        try:
            self.allow(principal, action, namespace)
            return True
        except AuthorizationDenied:
            return False

    def add_rule(self, principal: str, action: str = "*", namespace: str = "*", effect: str = "allow") -> None:
        self.rules.append(Rule(principal=principal, action=action, namespace=namespace, effect=effect))


class TokenIssuer:
    def __init__(self, master_secret: str):
        import hmac
        import hashlib

        self._secret = master_secret.encode()
        self._hmac = hmac
        self._hash = hashlib

    def issue(self, principal: str, namespace: str = "*") -> str:
        payload = f"{principal}:{namespace}"
        signature = self._hmac.new(self._secret, payload.encode(), self._hash.sha256).hexdigest()
        return f"{payload}:{signature}"

    def verify(self, token: str) -> tuple:
        parts = token.split(":")
        if len(parts) != 3:
            raise AuthorizationDenied("Malformed token structure.")
        principal, namespace, signature = parts
        expected = self._hmac.new(self._secret, f"{principal}:{namespace}".encode(), self._hash.sha256).hexdigest()
        if not hmac_compare(expected, signature):
            raise AuthorizationDenied("Token signature verification failed.")
        return principal, namespace


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)