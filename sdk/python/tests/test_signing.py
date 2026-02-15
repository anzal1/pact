"""Unit tests for signing and verification modules."""

import pact
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSignRequest:
    def test_signs_request(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        assert req.get_header("X-Pact-Identity") == agent.id
        assert req.get_header("X-Pact-Chain") != ""
        assert req.get_header("Signature-Input") != ""
        assert req.get_header("Signature").startswith("pact=:")
        assert req.get_header("Date") != ""

    def test_requires_private_key(self):
        agent = pact.new_identity("agent", "my-agent")
        pub = agent.public_identity()

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        with pytest.raises(ValueError, match="no private key"):
            pact.sign_request(req, pub, [])


class TestVerifyRequest:
    def test_full_roundtrip(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        result = pact.verify_request(req)
        assert result.valid, f"Expected valid, got error: {result.error}"
        assert result.agent_id == agent.id
        assert result.root_authority == human.id
        assert result.capabilities == ["api:read"]
        assert result.chain_depth == 1

    def test_multi_hop_chain(self):
        human = pact.new_identity("human", "alice")
        root_agent = pact.new_identity("agent", "root-agent")
        sub_agent = pact.new_identity("agent", "sub-agent")

        d1 = pact.new_delegation(
            from_identity=human,
            to_identity=root_agent,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        d2, chain = pact.sub_delegate(
            chain=[d1],
            agent=root_agent,
            to=sub_agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, sub_agent, chain)

        result = pact.verify_request(req)
        assert result.valid, f"Expected valid, got error: {result.error}"
        assert result.agent_id == sub_agent.id
        assert result.root_authority == human.id
        assert result.chain_depth == 2

    def test_tampered_header_fails(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        # Tamper with the identity header
        req.set_header("X-Pact-Identity", "sha256:tampered")

        result = pact.verify_request(req)
        assert not result.valid

    def test_required_capability(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        # Should pass with matching capability
        opts = pact.VerifyOptions(required_capability="api:read")
        result = pact.verify_request(req, opts)
        assert result.valid

        # Should fail with non-matching capability
        opts = pact.VerifyOptions(required_capability="api:write")
        result = pact.verify_request(req, opts)
        assert not result.valid
        assert "lacks required capability" in result.error

    def test_trusted_roots(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        # Should pass with correct trusted root
        opts = pact.VerifyOptions(trusted_roots={human.id})
        result = pact.verify_request(req, opts)
        assert result.valid

        # Should fail with wrong trusted root
        opts = pact.VerifyOptions(trusted_roots={"sha256:wrong"})
        result = pact.verify_request(req, opts)
        assert not result.valid
        assert "not trusted" in result.error

    def test_revocation_check(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, agent, [d])

        # Should pass without revocation
        result = pact.verify_request(req)
        assert result.valid

        # Should fail with revocation
        opts = pact.VerifyOptions(
            revocation_checker=lambda did: did == d.id
        )
        result = pact.verify_request(req, opts)
        assert not result.valid
        assert "revoked" in result.error


class TestVerifyChain:
    def test_valid_chain(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        result = pact.verify_chain([d])
        assert result.valid
        assert result.agent_id == agent.id
        assert result.root_authority == human.id

    def test_expired_chain(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        # Verify with a time far in the future
        opts = pact.VerifyOptions(
            now=lambda: datetime(2099, 1, 1, tzinfo=timezone.utc)
        )
        result = pact.verify_chain([d], opts)
        assert not result.valid
        assert "expired" in result.error

    def test_empty_chain(self):
        result = pact.verify_chain([])
        assert not result.valid
        assert "empty" in result.error


class TestContentDigest:
    def test_compute(self):
        digest = pact.compute_content_digest(b'{"action":"deploy"}')
        assert digest.startswith("sha-256=:")
        assert digest.endswith(":")

    def test_deterministic(self):
        a = pact.compute_content_digest(b"hello")
        b = pact.compute_content_digest(b"hello")
        assert a == b

    def test_different_bodies(self):
        a = pact.compute_content_digest(b"hello")
        b = pact.compute_content_digest(b"world")
        assert a != b


class TestHttpRequest:
    def test_parse_url(self):
        req = pact.HttpRequest("GET", "https://api.example.com/data?page=1")
        assert req.method == "GET"
        assert req.host == "api.example.com"
        assert req.path == "/data?page=1"

    def test_headers_case_insensitive(self):
        req = pact.HttpRequest("GET", "https://example.com/")
        req.set_header("Content-Type", "application/json")
        assert req.get_header("content-type") == "application/json"
        assert req.get_header("Content-Type") == "application/json"

    def test_default_path(self):
        req = pact.HttpRequest("GET", "https://example.com")
        assert req.path == "/"
