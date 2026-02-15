"""Unit tests for identity module."""

import pact
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestNewIdentity:
    def test_creates_human(self):
        identity = pact.new_identity("human", "alice")
        assert identity.type == "human"
        assert identity.name == "alice"
        assert identity.id.startswith("sha256:")
        assert identity.public_key != ""
        assert identity.private_key is not None

    def test_creates_agent(self):
        identity = pact.new_identity("agent", "my-agent")
        assert identity.type == "agent"
        assert identity.name == "my-agent"

    def test_unique_ids(self):
        a = pact.new_identity("human", "a")
        b = pact.new_identity("human", "b")
        assert a.id != b.id

    def test_id_is_deterministic_from_key(self):
        seed = pact.test_vector_seed("test-det")
        a = pact.identity_from_seed(seed, "human")
        b = pact.identity_from_seed(seed, "human")
        assert a.id == b.id
        assert a.public_key == b.public_key


class TestSignVerify:
    def test_sign_and_verify(self):
        identity = pact.new_identity("human", "signer")
        message = b"hello pact"
        sig = identity.sign(message)
        assert identity.verify(message, sig)

    def test_verify_fails_wrong_message(self):
        identity = pact.new_identity("human", "signer")
        sig = identity.sign(b"correct message")
        assert not identity.verify(b"wrong message", sig)

    def test_verify_fails_wrong_key(self):
        a = pact.new_identity("human", "a")
        b = pact.new_identity("human", "b")
        sig = a.sign(b"message")
        assert not b.verify(b"message", sig)

    def test_sign_without_private_key_raises(self):
        identity = pact.new_identity("human", "signer")
        pub = identity.public_identity()
        with pytest.raises(ValueError, match="no private key"):
            pub.sign(b"message")


class TestPublicIdentity:
    def test_strips_private_key(self):
        identity = pact.new_identity("human", "test")
        pub = identity.public_identity()
        assert pub.private_key is None
        assert pub.id == identity.id
        assert pub.public_key == identity.public_key
        assert pub.name == identity.name

    def test_to_dict_no_private_key(self):
        identity = pact.new_identity("human", "test")
        d = identity.to_dict()
        assert "private_key" not in d
        assert d["type"] == "human"
        assert d["id"] == identity.id
        assert d["public_key"] == identity.public_key


class TestDeriveId:
    def test_derive_id_format(self):
        identity = pact.new_identity("human", "test")
        pub_bytes = identity.raw_public_key_bytes()
        derived = pact.derive_id(pub_bytes)
        assert derived == identity.id
        assert derived.startswith("sha256:")
        # sha256: + 64 hex chars
        assert len(derived) == 7 + 64


class TestIdentityFromPublicKey:
    def test_creates_identity_without_private_key(self):
        orig = pact.new_identity("agent", "orig")
        pub_bytes = orig.raw_public_key_bytes()
        restored = pact.identity_from_public_key("agent", pub_bytes)
        assert restored.id == orig.id
        assert restored.public_key == orig.public_key
        assert restored.private_key is None
