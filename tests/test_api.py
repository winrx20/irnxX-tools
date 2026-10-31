"""The local API must reject unauthenticated and non-loopback clients."""
import os
import tempfile

os.environ.setdefault("IRNXSEC_HOME", tempfile.mkdtemp(prefix="irnxsec-test-"))

import unittest

from fastapi.testclient import TestClient

from irnxsec import config
from irnxsec.api import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, client=("127.0.0.1", 55555))
        self.headers = {"X-IRNX-Token": config.load().api_token}

    def test_health_requires_token(self):
        self.assertEqual(self.client.get("/api/health").status_code, 401)
        self.assertEqual(self.client.get("/api/health", headers=self.headers).status_code, 200)

    def test_non_loopback_client_is_rejected(self):
        remote = TestClient(app, client=("203.0.113.9", 55555))
        self.assertEqual(remote.get("/api/health", headers=self.headers).status_code, 403)

    def test_dashboard_injects_token_once(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        body = response.text
        self.assertNotIn("__IRNX_TOKEN__", body)
        self.assertIn(config.load().api_token, body)

    def test_canary_catalogue_is_non_exploiting(self):
        payload = self.client.get("/api/payloads", headers=self.headers).json()
        self.assertGreater(len(payload["canaries"]), 3)
        self.assertIn("non-exploiting", payload["note"].lower())

    def test_invalid_target_reports_reason(self):
        response = self.client.post(
            "/api/targets/validate", headers=self.headers, json={"target": "ftp://x", "kind": "web"}
        )
        body = response.json()
        self.assertFalse(body["valid"])
        self.assertTrue(body["reason"])

    def test_scan_submission_requires_authorization(self):
        response = self.client.post(
            "/api/scans",
            headers=self.headers,
            json={"target": "https://outside-scope-registered.org", "kind": "web", "confirm_authorized": True},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization scope", response.json()["detail"])

    def test_settings_validation(self):
        response = self.client.post("/api/settings", headers=self.headers, json={"port": 99999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.post("/api/settings", headers=self.headers, json={"timeout": 6}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
