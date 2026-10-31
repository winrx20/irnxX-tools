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


class CliContractTests(unittest.TestCase):
    """``--json`` must work before and after the subcommand, for every command."""

    def _run(self, *argv):
        import subprocess
        import sys
        import os

        env = {**os.environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1])}
        return subprocess.run(
            [sys.executable, "-m", "irnxsec.cli", *argv],
            capture_output=True, text=True, env=env, timeout=120,
        )

    def test_json_before_subcommand(self):
        result = self._run("--json", "scope", "list")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertIn("scopes", result.stdout)

    def test_json_after_subcommand(self):
        result = self._run("scope", "list", "--json")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertIn("scopes", result.stdout)

    def test_blocked_scan_reports_json_and_exit_3(self):
        result = self._run("scan", "https://never-authorized-here.org", "--json")
        self.assertEqual(result.returncode, 3, result.stdout[-400:])
        self.assertIn("authorization_blocked", result.stdout)

    def test_invalid_target_reports_json_and_exit_2(self):
        result = self._run("scan", "ftp://nope", "--json")
        self.assertEqual(result.returncode, 2, result.stdout[-400:])
        self.assertIn("invalid_input", result.stdout)


if __name__ == "__main__":
    unittest.main()
