import json
import unittest
from pathlib import Path
from unittest.mock import patch

import app as api_app


class FakeSecurityStore:
    """Small in-memory stand-in for the MySQL SecurityStore used by unit tests."""

    def __init__(self):
        self.records = {
            "test-key-01": {
                "api_key_id": "key-001",
                "status": "active",
                "allowed_ips": ["127.0.0.1"],
                "label": "unit-test",
            }
        }
        self.blocked_ips = set()

    def find(self, raw_api_key):
        record = self.records.get(raw_api_key)
        return dict(record) if record else None

    def find_by_id(self, api_key_id):
        for record in self.records.values():
            if record["api_key_id"] == api_key_id:
                return dict(record)
        return None

    def is_blocked(self, ip):
        return ip in self.blocked_ips

    def blocks(self):
        return [{"ip": ip} for ip in sorted(self.blocked_ips)]

    def record_allowed_request(self, _event):
        return None

    def record_denied_request(self, _event):
        return True

    def respond(self, api_key_id, reason, ip, incident_id):
        record = self.find_by_id(api_key_id)
        if record is None or record["status"] != "active":
            return None

        raw_replacement = "test-key-01-renewed"
        replacement_id = "key-001-renewed"
        for raw_key, stored in self.records.items():
            if stored["api_key_id"] == api_key_id:
                stored["status"] = "revoked"
                break
        self.records[raw_replacement] = {
            "api_key_id": replacement_id,
            "status": "active",
            "allowed_ips": ["127.0.0.1"],
            "label": "unit-test",
        }
        if ip not in {"unknown", "127.0.0.1"}:
            self.blocked_ips.add(ip)
        return {
            "key_revoked": True,
            "incident_id": incident_id or "INC-API-001",
            "new_api_key_id": replacement_id,
            "new_api_key": raw_replacement,
            "ip_blocked": ip not in {"unknown", "127.0.0.1"},
        }


class MainApiServerTest(unittest.TestCase):
    def setUp(self):
        self.store = FakeSecurityStore()
        self.store_patch = patch.object(api_app, "security_store", self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)

        self.log_path = Path(__file__).resolve().parent / ".test-security-events.jsonl"
        self.log_path.unlink(missing_ok=True)
        self.log_path_patch = patch.object(
            api_app, "LOG_FILE", self.log_path
        )
        self.log_path_patch.start()
        self.addCleanup(self.log_path_patch.stop)
        self.addCleanup(self.log_path.unlink, missing_ok=True)

        api_app.REQUEST_COUNTS.clear()
        api_app.SECURITY_EVENTS.clear()
        api_app.INCIDENTS.clear()
        api_app.MIDDLEWARE_INGEST_URL = ""
        api_app.MIDDLEWARE_API_KEY = ""
        self.client = api_app.app.test_client()

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_valid_api_key_is_allowed_and_logs_fixed_fields(self):
        response = self.client.get(
            "/api/data", headers={"X-API-Key": "test-key-01"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "authorized")
        event = api_app.SECURITY_EVENTS[-1]
        self.assertEqual(event["event_type"], "api_request_allowed")
        self.assertEqual(event["api_key_id"], "key-001")
        self.assertNotEqual(event["api_key_id"], "test-key-01")
        self.assertEqual(event["status_code"], 200)
        self.assertIn("timestamp", event)
        self.assertIn("client_ip", event)
        self.assertIn("target_resource", event)

    def test_invalid_api_key_is_rejected(self):
        response = self.client.get(
            "/api/data", headers={"X-API-Key": "wrong-key"}
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            api_app.SECURITY_EVENTS[-1]["event_type"], "authentication_failed"
        )

    def test_disallowed_ip_is_logged_as_compromised_key(self):
        response = self.client.get(
            "/api/data",
            headers={
                "X-API-Key": "test-key-01",
                "X-Demo-Client-IP": "10.10.10.10",
            },
        )

        self.assertEqual(response.status_code, 403)
        event = api_app.SECURITY_EVENTS[-1]
        self.assertEqual(event["event_type"], "api_key_compromised")
        self.assertEqual(event["api_key_id"], "key-001")
        self.assertEqual(event["client_ip"], "10.10.10.10")
        self.assertEqual(event["detection_reason"], "not_allowed_ip")

    def test_middleware_forwarding_is_called_when_logging(self):
        with patch.object(api_app, "_forward_to_middleware") as forward:
            self.client.get(
                "/api/data", headers={"X-API-Key": "test-key-01"}
            )

        forward.assert_called_once()
        forwarded_event = forward.call_args.args[0]
        self.assertEqual(forwarded_event["event_type"], "api_request_allowed")

    def test_middleware_payload_uses_ingest_schema_and_api_key_header(self):
        api_app.MIDDLEWARE_INGEST_URL = "http://middleware.test/v1/ingest"
        api_app.MIDDLEWARE_API_KEY = "middleware-demo-key"
        captured = {}

        class FakeResponse:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def fake_urlopen(http_request, timeout):
            captured["request"] = http_request
            captured["timeout"] = timeout
            return FakeResponse()

        with patch.object(api_app, "urlopen", side_effect=fake_urlopen):
            self.client.get(
                "/api/data", headers={"X-API-Key": "test-key-01"}
            )

        request_body = json.loads(captured["request"].data.decode("utf-8"))
        self.assertEqual(
            captured["request"].full_url, "http://middleware.test/v1/ingest"
        )
        self.assertEqual(
            captured["request"].get_header("X-api-key"), "middleware-demo-key"
        )
        self.assertEqual(request_body["schema_version"], "1.0")
        self.assertEqual(request_body["severity"], 6)
        self.assertEqual(request_body["raw_payload"]["api_key_id"], "key-001")
        self.assertNotIn("test-key-01", json.dumps(request_body))
        self.assertNotIn("api_key_id", request_body)

    def test_n8n_webhook_revokes_key_and_blocks_ip(self):
        response = self.client.post(
            "/automation/revoke-key",
            json={
                "api_key_id": "key-001",
                "client_ip": "10.10.10.10",
                "detection_reason": "not_allowed_ip",
            },
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["key_revoked"])
        self.assertTrue(body["ip_blocked"])
        self.assertEqual(body["new_api_key_id"], "key-001-renewed")
        self.assertEqual(body["new_api_key"], "test-key-01-renewed")
        self.assertEqual(self.store.find_by_id("key-001")["status"], "revoked")
        self.assertIn("10.10.10.10", self.store.blocked_ips)
        self.assertEqual(api_app.INCIDENTS[0]["incident_id"], "INC-API-001")

        new_key_response = self.client.get(
            "/api/data", headers={"X-API-Key": body["new_api_key"]}
        )
        self.assertEqual(new_key_response.status_code, 200)
        self.assertEqual(
            api_app.SECURITY_EVENTS[-1]["api_key_id"], "key-001-renewed"
        )


if __name__ == "__main__":
    unittest.main()
