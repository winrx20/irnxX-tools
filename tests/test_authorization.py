"""The authorization gate is the compliance core: it must fail closed."""
import os
import tempfile

os.environ.setdefault("IRNXSEC_HOME", tempfile.mkdtemp(prefix="irnxsec-test-"))

import unittest

from irnxsec import authz, store


class TargetNormalizationTests(unittest.TestCase):
    def test_web_target_gets_scheme_and_host_only(self):
        self.assertEqual(authz.normalize_target("example.com"), "https://example.com")
        self.assertEqual(authz.normalize_target("https://example.com/path?q=1"), "https://example.com")
        self.assertEqual(authz.normalize_target("http://example.com:8080"), "http://example.com:8080")

    def test_web_target_rejects_credentials_and_bad_scheme(self):
        with self.assertRaises(ValueError):
            authz.normalize_target("https://user:pass@example.com")
        with self.assertRaises(ValueError):
            authz.normalize_target("ftp://example.com")

    def test_network_target_normalizes_to_cidr(self):
        self.assertEqual(authz.normalize_target("10.1.2.3", "network"), "10.1.2.3/32")
        self.assertEqual(authz.normalize_target("10.0.0.0/24", "network"), "10.0.0.0/24")

    def test_scope_entries_keep_their_pattern(self):
        self.assertEqual(authz.normalize_scope_target("acme.example"), "acme.example")
        self.assertEqual(authz.normalize_scope_target("*.acme.example"), "*.acme.example")
        self.assertEqual(authz.normalize_scope_target("https://*.acme.example"), "*.acme.example")
        self.assertEqual(authz.normalize_scope_target("https://acme.example/x?y=1"), "acme.example")
        self.assertEqual(authz.normalize_scope_target("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(authz.normalize_scope_target("10.0.0.7"), "10.0.0.7/32")
        with self.assertRaises(ValueError):
            authz.normalize_scope_target("ftp://acme.example")
        with self.assertRaises(ValueError):
            authz.normalize_scope_target("api.*.acme.example")

    def test_lab_targets_are_recognised(self):
        for host in ("127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "172.16.0.9", "printer.lan", "app.test"):
            self.assertTrue(authz.is_lab_target(host), host)
        for host in ("example.com", "8.8.8.8", "103.150.1.1"):
            self.assertFalse(authz.is_lab_target(host), host)


class GuardTests(unittest.TestCase):
    def test_lab_target_allowed_without_confirmation(self):
        decision = authz.Guard().authorize("http://127.0.0.1:8000", "web")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.scope_id, "LAB")

    def test_external_target_requires_confirmation(self):
        decision = authz.Guard().authorize("https://example.org", "web", confirm=False)
        self.assertFalse(decision.allowed)
        self.assertIn("confirmation", decision.reason.lower())

    def test_external_target_without_scope_is_blocked(self):
        decision = authz.Guard().authorize("https://no-scope-registered.org", "web", confirm=True)
        self.assertFalse(decision.allowed)
        self.assertIn("no active authorization scope", decision.reason.lower())

    def test_scope_unlocks_only_its_targets(self):
        scope = store.create_scope(
            {"name": "Unit test engagement", "targets": ["scoped-target.org", "*.wild-target.org"], "authorization": "written-permission"}
        )
        self.assertTrue(authz.Guard().authorize("https://scoped-target.org", "web", confirm=True).allowed)
        self.assertTrue(authz.Guard().authorize("https://api.wild-target.org", "web", confirm=True).allowed)
        blocked = authz.Guard().authorize("https://other-target.org", "web", confirm=True)
        self.assertFalse(blocked.allowed)
        # A revoked scope must close the gate again.
        self.assertTrue(store.revoke_scope(scope["id"]))
        self.assertFalse(authz.Guard().authorize("https://scoped-target.org", "web", confirm=True).allowed)

    def test_kind_scoping_is_enforced(self):
        store.create_scope({"name": "DNS only", "targets": ["dns-only.org"], "kind": "dns"})
        self.assertTrue(authz.Guard().authorize("dns-only.org", "dns", confirm=True).allowed)
        self.assertFalse(authz.Guard().authorize("https://dns-only.org", "web", confirm=True).allowed)

    def test_cidr_scope_covers_member_addresses(self):
        # Documentation/private ranges count as lab targets, so use routable addresses here.
        scope = store.create_scope({"name": "Customer range", "targets": ["45.33.32.156/30"], "kind": "network"})
        self.assertTrue(authz.scope_covers(scope, "45.33.32.157", "network"))
        self.assertFalse(authz.scope_covers(scope, "45.33.32.200", "network"))
        self.assertTrue(
            authz.Guard().authorize("45.33.32.157", "network", confirm=True, scope_id=scope["id"]).allowed
        )
        self.assertFalse(
            authz.Guard().authorize("45.33.32.200", "network", confirm=True, scope_id=scope["id"]).allowed
        )

    def test_expired_scope_is_not_usable(self):
        scope = store.create_scope({"name": "Expired", "targets": ["expired-scope.org"], "expires_at": "2020-01-01"})
        self.assertFalse(scope["usable"])
        self.assertFalse(authz.Guard().authorize("https://expired-scope.org", "web", confirm=True).allowed)


if __name__ == "__main__":
    unittest.main()
