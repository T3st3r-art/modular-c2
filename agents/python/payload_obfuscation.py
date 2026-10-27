"""Agent-side symmetric XOR payload transformation."""


def _xor_payload(payload_bytes: bytes, agent_id: str) -> bytes:
    key = agent_id.encode("utf-8")
    if not key:
        raise ValueError("agent_id must not be empty")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(payload_bytes))


def EncryptPayload(payloadBytes: bytes, agentID: str) -> bytes:
    """Apply the repeating agent ID key to binary payload bytes."""
    return _xor_payload(payloadBytes, agentID)


def DecryptPayload(encryptedBytes: bytes, agentID: str) -> bytes:
    """Recover raw module bytes in memory using the agent ID key."""
    return _xor_payload(encryptedBytes, agentID)
