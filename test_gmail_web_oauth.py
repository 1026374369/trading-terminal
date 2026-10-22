"""Offline integration checks. All Google requests are mocked."""

import base64
import contextlib
import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

import gmail_web_oauth as app

CLIENT = {"client_id": "test.apps.googleusercontent.com", "client_secret": "test-only-secret"}


class GmailOAuthTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.token_file = Path(self.folder.name) / "gmail_token.json"

    def cached(self, **changes):
        token = {"client_id": CLIENT["client_id"], "access_token": "cached-access",
                 "refresh_token": "cached-refresh", "scope": app.SCOPE,
                 "expires_at": time.time() + 3600}
        token.update(changes)
        self.token_file.write_text(json.dumps(token), encoding="utf-8")
        return token

    def test_web_credentials_without_redirect_uris(self):
        filename = Path(self.folder.name) / "credentials.json"
        filename.write_text(json.dumps({"web": dict(CLIENT, auth_uri=app.AUTH_URL)}), encoding="utf-8-sig")
        self.assertEqual(app.load_credentials(filename), CLIENT)
        filename.write_text('{"web": {"client_id": "x"}}', encoding="utf-8")
        with self.assertRaises(app.SetupError):
            app.load_credentials(filename)

    def test_invalid_state_and_duplicate_state_are_ignored(self):
        with app.callback_server(0, "expected") as server:
            def serve():
                for _ in range(4):
                    server.handle_request()

            worker = threading.Thread(target=serve)
            worker.start()
            base = "http://127.0.0.1:{}{}?".format(server.server_port, app.CALLBACK_PATH)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for query in ("state=wrong&code=bad", "state=expected&state=other&code=bad", "state=%E9%94%99&code=bad"):
                with self.assertRaises(urllib.error.HTTPError) as context:
                    opener.open(base + query, timeout=5)
                self.assertEqual(context.exception.code, 400)
                self.assertIsNone(server.result)
            with opener.open(base + "state=expected&code=good", timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Cache-Control"], "no-store")
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertEqual(server.result, {"code": "good"})

    def test_complete_local_authorization_and_pkce(self):
        captured, workers = {}, []

        def simulate_browser(url):
            captured.update(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query))
            query = urllib.parse.urlencode({"state": captured["state"][0], "code": "fake-code"})

            def redirect():
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(captured["redirect_uri"][0] + "?" + query, timeout=5) as response:
                    response.read()

            worker = threading.Thread(target=redirect)
            workers.append(worker)
            worker.start()
            return True

        def token_exchange(url, form=None, access_token=None):
            self.assertEqual(url, app.TOKEN_URL)
            self.assertEqual(form["grant_type"], "authorization_code")
            self.assertEqual(form["code"], "fake-code")
            self.assertEqual(form["client_secret"], CLIENT["client_secret"])
            self.assertEqual(form["redirect_uri"], captured["redirect_uri"][0])
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(challenge, captured["code_challenge"][0])
            self.assertEqual(captured["scope"], [app.SCOPE])
            self.assertEqual(captured["access_type"], ["offline"])
            return {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}

        with patch.object(app.webbrowser, "open", side_effect=simulate_browser), \
                patch.object(app, "request_json", side_effect=token_exchange), \
                contextlib.redirect_stdout(io.StringIO()):
            result = app.authorize(CLIENT, 0, timeout=5)
        for worker in workers:
            worker.join(timeout=5)
        self.assertEqual(result["refresh_token"], "new-refresh")

    def test_authorization_timeout(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(app.SetupError):
            app.authorize(CLIENT, 0, no_browser=True, timeout=0)

    def test_valid_cached_token_skips_network_and_browser(self):
        expected = self.cached()
        with patch.object(app, "request_json") as network, patch.object(app, "authorize") as browser:
            self.assertEqual(app.get_token(CLIENT, self.token_file, 8765), expected)
        network.assert_not_called()
        browser.assert_not_called()

    def test_refresh_preserves_refresh_token_and_saves(self):
        self.cached(expires_at=0)
        with patch.object(app, "request_json", return_value={"access_token": "refreshed", "expires_in": 1800}) as network, \
                patch.object(app, "authorize") as browser:
            token = app.get_token(CLIENT, self.token_file, 8765)
        self.assertEqual(token["refresh_token"], "cached-refresh")
        self.assertEqual(token["access_token"], "refreshed")
        self.assertEqual(network.call_args.kwargs["form"]["grant_type"], "refresh_token")
        self.assertGreater(token["expires_at"], time.time() + 1700)
        self.assertEqual(json.loads(self.token_file.read_text(encoding="utf-8")), token)
        self.assertNotIn("client_secret", token)
        browser.assert_not_called()

    def test_revoked_refresh_token_triggers_reauthorization(self):
        self.cached(expires_at=0)
        with patch.object(app, "request_json", side_effect=app.RemoteError(400, "invalid_grant")), \
                patch.object(app, "authorize", return_value={"access_token": "new", "refresh_token": "new-refresh", "expires_in": 3600}) as browser, \
                contextlib.redirect_stdout(io.StringIO()):
            token = app.get_token(CLIENT, self.token_file, 8765)
        browser.assert_called_once()
        self.assertEqual(token["refresh_token"], "new-refresh")

    def test_different_client_does_not_reuse_cached_token(self):
        self.cached(client_id="other-client")
        with patch.object(app, "request_json") as network, \
                patch.object(app, "authorize", return_value={"access_token": "new", "refresh_token": "new-refresh", "expires_in": 3600}) as browser:
            app.get_token(CLIENT, self.token_file, 8765)
        browser.assert_called_once()
        network.assert_not_called()

    def test_missing_gmail_scope_is_rejected(self):
        with self.assertRaises(app.SetupError):
            app.normalize_token({"access_token": "x", "scope": "openid", "expires_in": 3600}, CLIENT)

    def test_refresh_without_new_access_token_is_rejected(self):
        with self.assertRaises(app.SetupError):
            app.normalize_token({"expires_in": 3600}, CLIENT, self.cached())

    def test_google_error_body_does_not_expose_secrets(self):
        body = io.BytesIO(json.dumps({"error": "invalid_client", "error_description": CLIENT["client_secret"]}).encode())
        remote_error = urllib.error.HTTPError(app.TOKEN_URL, 400, "Bad Request", {}, body)
        with patch.object(app.urllib.request, "urlopen", side_effect=remote_error), self.assertRaises(app.RemoteError) as context:
            app.request_json(app.TOKEN_URL, form=CLIENT)
        self.assertEqual(context.exception.code, "invalid_client")
        self.assertNotIn(CLIENT["client_secret"], str(context.exception))

    def test_message_query_and_metadata_requests(self):
        responses = [{"messages": [{"id": "message-id"}]}, {
            "snippet": "one &amp; two", "payload": {"headers": [
                {"name": "Subject", "value": "=?utf-8?b?5rWL6K+V?="},
                {"name": "From", "value": "sender@example.com\nspoof"},
                {"name": "Date", "value": "today"}]}}]
        with patch.object(app, "request_json", side_effect=responses) as network:
            messages = app.list_messages({"access_token": "test-access"}, "in:inbox newer_than:7d", 20)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(network.call_args_list[0].args[0]).query)
        self.assertEqual(query["q"], ["in:inbox newer_than:7d"])
        self.assertEqual(query["maxResults"], ["20"])
        self.assertEqual(messages[0]["subject"], "测试")
        self.assertEqual(messages[0]["snippet"], "one & two")
        self.assertNotIn("\n", messages[0]["from"])
        self.assertTrue(all(call.kwargs["access_token"] == "test-access" for call in network.call_args_list))

    def test_check_config_does_not_make_network_requests(self):
        filename = Path(self.folder.name) / "credentials.json"
        filename.write_text(json.dumps({"web": CLIENT}), encoding="utf-8")
        with patch.object(app, "request_json") as network, \
                patch.object(app, "authorize") as browser, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = app.main(["--credentials", str(filename), "--check-config"])
        self.assertEqual(status, 0)
        self.assertNotIn(CLIENT["client_secret"], output.getvalue())
        network.assert_not_called()
        browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
