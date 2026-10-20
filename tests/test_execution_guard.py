"""Contract tests for the guarded execution boundary (no live gateway needed)."""
import unittest
from unittest.mock import Mock
from client_sdk import OmniGuardError
from execution_guard import execute_guarded


class ExecutionGuardTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.action = Mock(return_value="executed")
        self.messages = [{"role": "user", "content": "Hello"}]

    def test_allow_executes_once(self):
        self.client.chat_completion.return_value = {"choices": []}
        self.assertEqual(execute_guarded(self.client, self.messages, self.action), "executed")
        self.action.assert_called_once_with()

    def test_block_never_executes(self):
        self.client.chat_completion.side_effect = OmniGuardError("HTTP 403: blocked")
        with self.assertRaises(OmniGuardError):
            execute_guarded(self.client, self.messages, self.action)
        self.action.assert_not_called()

    def test_gateway_unavailable_never_executes(self):
        self.client.chat_completion.side_effect = OmniGuardError("Gateway unavailable")
        with self.assertRaises(OmniGuardError):
            execute_guarded(self.client, self.messages, self.action)
        self.action.assert_not_called()

    def test_malformed_response_never_executes(self):
        self.client.chat_completion.side_effect = OmniGuardError("Malformed gateway response")
        with self.assertRaises(OmniGuardError):
            execute_guarded(self.client, self.messages, self.action)
        self.action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
