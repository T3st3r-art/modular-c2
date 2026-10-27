import unittest

from server.payload_obfuscation import DecryptPayload, EncryptPayload


class PayloadObfuscationTests(unittest.TestCase):
    def test_round_trip_binary_payload(self):
        payload = bytes([0x00, 0x01, 0x7F, 0x80, 0xFF, 0x00])
        encrypted = EncryptPayload(payload, "a1b2c3d4")
        self.assertEqual(DecryptPayload(encrypted, "a1b2c3d4"), payload)

    def test_empty_payload(self):
        self.assertEqual(EncryptPayload(b"", "agent"), b"")
        self.assertEqual(DecryptPayload(b"", "agent"), b"")

    def test_variable_length_agent_ids(self):
        payload = b"module bytes"
        for agent_id in ("a", "abc", "agent-identifier-123"):
            self.assertEqual(
                DecryptPayload(EncryptPayload(payload, agent_id), agent_id),
                payload,
            )

    def test_empty_agent_id_is_rejected(self):
        with self.assertRaises(ValueError):
            EncryptPayload(b"payload", "")


if __name__ == "__main__":
    unittest.main()
