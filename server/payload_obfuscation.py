"""Symmetric payload obfuscation shared by module transport endpoints."""

from __future__ import annotations


def _xor_payload(payload_bytes: bytes, agent_id: str) -> bytes:
    """Apply the repeating agent ID key to a payload."""
    key = agent_id.encode("utf-8")
    if not key:
        raise ValueError("agent_id must not be empty")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(payload_bytes))


def EncryptPayload(payloadBytes: bytes, agentID: str) -> bytes:
    """Encrypt binary payload bytes with the target agent ID."""
    return _xor_payload(payloadBytes, agentID)


def DecryptPayload(encryptedBytes: bytes, agentID: str) -> bytes:
    """Decrypt binary payload bytes with the target agent ID."""
    return _xor_payload(encryptedBytes, agentID)
