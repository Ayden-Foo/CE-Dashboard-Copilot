import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import azdo_auth


class AzureCliAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = patch.object(azdo_auth, "CACHE_PATH",
                                  os.path.join(self.temp.name, "auth.json"))
        self.cache.start()
        self.login = patch.object(azdo_auth, "_cli_login", None)
        self.login.start()

    def tearDown(self):
        self.login.stop()
        self.cache.stop()
        self.temp.cleanup()

    def test_cli_refresh_does_not_fall_back_to_device_code(self):
        azdo_auth._write_cache({"provider": "azure_cli", "expires_in": 0})
        with patch.object(azdo_auth, "_cli_token",
                          return_value={"access_token": "test-token"}) as token, \
                patch.object(azdo_auth, "_device_code_flow") as device:
            self.assertEqual(azdo_auth.get_access_token(), "test-token")
            token.assert_called_once_with()
            device.assert_not_called()
        with patch.object(azdo_auth, "_cli_token",
                          side_effect=RuntimeError("Policy denied")), \
                patch.object(azdo_auth, "_device_code_flow") as device:
            with self.assertRaisesRegex(SystemExit, "Policy denied"):
                azdo_auth.get_access_token()
            device.assert_not_called()

    def test_cli_token_cache_keeps_provider_and_no_refresh_token(self):
        output = json.dumps({"accessToken": "test-token",
                             "expires_on": time.time() + 3600})
        with patch.object(azdo_auth, "_run_cli", return_value=output):
            cache = azdo_auth._cli_token()
        self.assertEqual(cache["provider"], "azure_cli")
        self.assertEqual(cache["refresh_token"], "")
        self.assertGreater(cache["expires_at"], time.time())
        self.assertTrue(azdo_auth.is_signed_in())

    def test_invalid_cli_token_is_rejected(self):
        for output in ('{}', 'not json',
                       json.dumps({"accessToken": "", "expires_on": time.time() + 3600}),
                       json.dumps({"accessToken": "test", "expires_on": 0})):
            with self.subTest(output=output), \
                    patch.object(azdo_auth, "_run_cli", return_value=output):
                with self.assertRaisesRegex(RuntimeError, "invalid or expired"):
                    azdo_auth._cli_token()
        self.assertFalse(os.path.exists(azdo_auth.CACHE_PATH))

    def test_login_polls_and_surfaces_failure(self):
        with patch.object(azdo_auth, "_azure_cli", return_value="az"), \
                patch.object(azdo_auth.threading, "Thread") as thread:
            result = azdo_auth.begin_signin()
            thread.return_value.start.assert_called_once_with()
            self.assertEqual(result["mode"], "azure_cli")
            self.assertEqual(azdo_auth.poll_signin(result), "pending")
            with self.assertRaisesRegex(RuntimeError, "already running"):
                azdo_auth.begin_signin()
        with patch.object(azdo_auth, "_run_cli", side_effect=RuntimeError("Policy denied")):
            azdo_auth._finish_cli_signin(result["loginId"])
        with self.assertRaisesRegex(RuntimeError, "Policy denied"):
            azdo_auth.poll_signin(result)

    def test_successful_login_checks_devops_token(self):
        azdo_auth._cli_login = {"id": "test-id", "status": "pending", "error": ""}
        with patch.object(azdo_auth, "_run_cli") as run, \
                patch.object(azdo_auth, "_cli_token") as token:
            azdo_auth._finish_cli_signin("test-id")
            run.assert_called_once_with(
                ["login", "--allow-no-subscriptions", "--output", "none"],
                timeout=300, interactive=True)
            token.assert_called_once_with()
        self.assertEqual(azdo_auth.poll_signin({"loginId": "test-id"}), "ok")
        with self.assertRaisesRegex(RuntimeError, "Unknown or expired"):
            azdo_auth.poll_signin({"loginId": "other-id"})

    def test_legacy_device_flow_when_cli_missing(self):
        with patch.object(azdo_auth, "_azure_cli", return_value=""), \
                patch.object(azdo_auth, "begin_device_code", return_value={"deviceCode": "code"}):
            result = azdo_auth.begin_signin()
        with patch.object(azdo_auth, "poll_device_code", return_value="pending") as poll:
            self.assertEqual(azdo_auth.poll_signin(result), "pending")
            poll.assert_called_once_with("code")

    def test_expired_legacy_cache_does_not_start_device_flow_with_cli(self):
        azdo_auth._write_cache({"refresh_token": "test-refresh", "expires_in": 0})
        with patch.object(azdo_auth, "_azure_cli", return_value="az"), \
                patch.object(azdo_auth, "_post", return_value=(None, {"error": "denied"})), \
                patch.object(azdo_auth, "_device_code_flow") as device:
            with self.assertRaisesRegex(SystemExit, "Windows sign-in"):
                azdo_auth.get_access_token()
            device.assert_not_called()

    def test_cli_uses_broker_without_changing_global_config(self):
        result = Mock(returncode=0, stdout="", stderr="")
        with patch.object(azdo_auth, "_azure_cli", return_value="az.cmd"), \
                patch.object(azdo_auth.sys, "platform", "win32"), \
                patch.object(azdo_auth.subprocess, "run", return_value=result) as run:
            azdo_auth._run_cli(["login"], interactive=True)
        kwargs = run.call_args[1]
        self.assertEqual(kwargs["env"]["AZURE_CORE_ENABLE_BROKER_ON_WINDOWS"], "true")
        self.assertEqual(kwargs["env"]["AZURE_CORE_LOGIN_EXPERIENCE_V2"], "off")
        self.assertEqual(kwargs["creationflags"], azdo_auth.subprocess.CREATE_NEW_CONSOLE)


if __name__ == "__main__":
    unittest.main()
