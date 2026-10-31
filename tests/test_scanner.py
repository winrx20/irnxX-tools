"""Engine behaviour against a controlled local fixture (no third party involved)."""
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("IRNXSEC_HOME", tempfile.mkdtemp(prefix="irnxsec-test-"))

from irnxsec import config, store
from irnxsec.models import ScanRequest
from irnxsec.runner import Runner


class Fixture(BaseHTTPRequestHandler):
    def _send(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Fixture/1.2")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        routes = {
            "/": '<html><title>Fixture</title><a href="/search?q=x">s</a><a href="/open?next=/a">r</a></html>',
            "/robots.txt": "User-agent: *\nDisallow: /private\n",
            "/.env": "APP_KEY=abc\nDB_HOST=localhost\n",
        }
        if parsed.path == "/search":
            return self._send(200, "<html>results " + query.get("q", [""])[0] + "</html>")
        if parsed.path == "/open":
            return self._send(302, "", {"Location": query.get("next", ["/"])[0]})
        body = routes.get(parsed.path)
        if body is None:
            return self._send(404, "<html>missing</html>")
        return self._send(200, body, {"Set-Cookie": "session=abc; Path=/"})

    def log_message(self, *args):
        pass


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Fixture)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _scan(self, **kwargs):
        request = ScanRequest(target=self.base, kind="web", profile="quick", confirm_authorized=True, **kwargs)
        return Runner().run_sync(request)

    def test_scan_completes_and_records_observations(self):
        result = self._scan()
        self.assertTrue(result.finished_at)
        self.assertGreater(result.metadata.get("requests_made", 0), 0)
        kinds = {observation.kind for observation in result.observations}
        self.assertIn("http", kinds)
        self.assertIn("headers", kinds)

    def test_missing_security_headers_are_reported(self):
        result = self._scan()
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles), titles)

    def test_exposed_dotenv_is_critical_with_signature_evidence(self):
        result = self._scan()
        exposed = [f for f in result.findings if ".env" in f.title]
        self.assertTrue(exposed, [f.title for f in result.findings])
        self.assertEqual(exposed[0].severity, "critical")
        self.assertEqual(exposed[0].confidence, "confirmed")
        self.assertIn("signature", exposed[0].evidence)

    def test_reflection_canary_is_low_with_caveat(self):
        result = self._scan()
        reflected = [f for f in result.findings if "reflected" in f.title.lower()]
        self.assertTrue(reflected, [f.title for f in result.findings])
        self.assertEqual(reflected[0].severity, "low")
        self.assertIn("not cross-site scripting", reflected[0].detail)

    def test_open_redirect_detected_on_controlled_parameter(self):
        result = self._scan()
        redirects = [f for f in result.findings if "open redirect" in f.title.lower()]
        self.assertTrue(redirects, [f.title for f in result.findings])
        self.assertEqual(redirects[0].confidence, "confirmed")

    def test_reports_are_written_for_every_format(self):
        from irnxsec import reports

        result = self._scan()
        paths = reports.write_reports(result)
        for fmt in ("json", "markdown", "html"):
            self.assertTrue(os.path.exists(paths[fmt]), fmt)
        with open(paths["html"], encoding="utf-8") as handle:
            self.assertIn("IRNXSEC", handle.read(400))

    def test_out_of_scope_target_is_refused_by_runner(self):
        request = ScanRequest(target="https://definitely-not-authorized-target.org", kind="web", confirm_authorized=True)
        with self.assertRaises(PermissionError):
            Runner().run_sync(request)

    def test_store_roundtrip(self):
        result = self._scan()
        store.save_scan(result, status="complete")
        record = store.get_scan(result.scan_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["target"], result.target)
        self.assertEqual(len(record["result"]["findings"]), len(result.findings))


if __name__ == "__main__":
    unittest.main()
