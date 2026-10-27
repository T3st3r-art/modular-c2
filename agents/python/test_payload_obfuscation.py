import unittest

from payload_obfuscation import DecryptPayload, EncryptPayload


class PayloadObfuscationTests(unittest.TestCase):
    def test_round_trip_binary_payload(self):
        payload = bytes([0x00, 0x10, 0x80, 0xFF, 0x00])
        self.assertEqual(
            DecryptPayload(EncryptPayload(payload, "agent-01"), "agent-01"),
            payload,
        )

    def test_empty_payload(self):
        self.assertEqual(EncryptPayload(b"", "id"), b"")
        self.assertEqual(DecryptPayload(b"", "id"), b"")

    def test_variable_key_lengths(self):
        payload = b"\x00module\xff"
        for agent_id in ("a", "abcd", "long-agent-id"):
            self.assertEqual(
                DecryptPayload(EncryptPayload(payload, agent_id), agent_id),
                payload,
            )

    def test_empty_key_is_rejected(self):
        with self.assertRaises(ValueError):
            DecryptPayload(b"payload", "")
