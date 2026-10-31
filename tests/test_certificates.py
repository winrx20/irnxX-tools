"""Signed engagement certificates: issue, verify, and refuse for dead scopes."""
import json
import os
import tempfile

os.environ.setdefault("IRNXSEC_HOME", tempfile.mkdtemp(prefix="irnxsec-test-"))

import unittest

from irnxsec import authz, store


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.scope = store.create_scope(
            {
                "name": "Cert test engagement",
                "targets": ["cert.example"],
                "organization": "Example Org",
                "contact": "security@example.com",
                "authorization": "written-permission",
                "reference": "CTR-2026-99",
            }
        )

    def test_issue_produces_json_and_pdf(self):
        certificate = authz.issue_certificate(self.scope["id"])
        self.assertTrue(certificate["payload"]["certificate_id"].startswith("IRNX-CERT-"))
        self.assertEqual(certificate["algorithm"], "Ed25519")
        self.assertGreater(len(certificate["signature"]), 40)
        self.assertTrue(os.path.exists(certificate["json"]))
        if certificate.get("pdf"):
            with open(certificate["pdf"], "rb") as handle:
                self.assertEqual(handle.read(5), b"%PDF-")

    def test_verify_accepts_untampered_certificate(self):
        certificate = authz.issue_certificate(self.scope["id"])
        verdict = authz.verify_certificate(json.loads(json.dumps(certificate)))
        self.assertTrue(verdict["valid"], verdict.get("reason"))

    def test_verify_rejects_tampered_payload(self):
        certificate = json.loads(json.dumps(authz.issue_certificate(self.scope["id"])))
        certificate["payload"]["targets"] = ["attacker.example"]
        verdict = authz.verify_certificate(certificate)
        self.assertFalse(verdict["valid"])

    def test_verify_rejects_after_revocation(self):
        certificate = authz.issue_certificate(self.scope["id"])
        store.revoke_scope(self.scope["id"])
        self.assertFalse(authz.verify_certificate(certificate)["valid"])

    def test_issue_refuses_revoked_scope(self):
        store.revoke_scope(self.scope["id"])
        with self.assertRaises(ValueError):
            authz.issue_certificate(self.scope["id"])


if __name__ == "__main__":
    unittest.main()
