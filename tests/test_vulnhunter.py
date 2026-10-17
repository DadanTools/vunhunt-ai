#!/usr/bin/env python3
"""
VulnHunter AI - Test Suite
Verifies scope enforcement, detector positive & negative cases,
secret redaction, tool availability handling, and report generation.
"""

import unittest
import sys
import os
import json
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import vulnhunter

class MockTestServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/vulnerable-headers":
            # Missing CSP and XFO deliberately
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session_id=super_secret_cookie_val; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Vulnerable Target</h1></body></html>")
            return

        if self.path == "/hardened-headers":
            # Hardened target (Negative test case)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Set-Cookie", "session=secure; Path=/; Secure; HttpOnly; SameSite=Strict")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Hardened Target</h1></body></html>")
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Silence HTTP server logs during testing
        pass

class TestVulnHunter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vulnhunter.init_db()
        cls.server = HTTPServer(("127.0.0.1", 0), MockTestServer)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

        # Add this mock test server port to authorized scope
        conn = vulnhunter.get_db()
        conn.execute("INSERT OR REPLACE INTO scopes (id, target, target_type, is_active, allow_private_ip, created_at) VALUES ('test-lab', ?, 'host', 1, 1, '2026-10-16')",
                     (f"127.0.0.1:{cls.port}",))
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_scope_gate_blocks_unauthorized_domain(self):
        result = vulnhunter.validate_scope("http://unauthorized-evil-target.com/path")
        self.assertFalse(result["authorized"])
        self.assertIn("outside authorized scope", result["reason"])

    def test_02_scope_gate_blocks_metadata_ssrf(self):
        # 169.254.169.254 is AWS/GCP cloud metadata IP
        result = vulnhunter.validate_scope("http://169.254.169.254/latest/meta-data")
        self.assertFalse(result["authorized"])

    def test_03_scope_gate_allows_authorized_target(self):
        result = vulnhunter.validate_scope(f"http://127.0.0.1:{self.port}/test")
        self.assertTrue(result["authorized"])

    def test_04_redact_string(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature"
        redacted = vulnhunter.redact_string(token)
        self.assertNotIn("sensitive_payload", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_05_exposure_scanner_positive_detection(self):
        target = f"http://127.0.0.1:{self.port}/vulnerable-headers"
        findings = vulnhunter.run_exposure_audit(target)
        self.assertTrue(len(findings) >= 2)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("X-Frame-Options" in t for t in titles))

    def test_06_exposure_scanner_negative_case(self):
        # Hardened endpoint must NOT trigger false positives for CSP and XFO
        target = f"http://127.0.0.1:{self.port}/hardened-headers"
        findings = vulnhunter.run_exposure_audit(target)
        titles = [f["title"] for f in findings]
        self.assertFalse(any("Content-Security-Policy" in t for t in titles))
        self.assertFalse(any("X-Frame-Options" in t for t in titles))

    def test_07_audit_log_persisted(self):
        conn = vulnhunter.get_db()
        logs = conn.execute("SELECT * FROM audit_logs WHERE action = 'SCAN_COMPLETE'").fetchall()
        conn.close()
        self.assertTrue(len(logs) > 0)

if __name__ == "__main__":
    unittest.main()
