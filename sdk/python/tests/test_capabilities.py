"""Unit tests for capabilities module."""

import pact
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestParseCapability:
    def test_full_wildcard(self):
        cap = pact.parse_capability("*")
        assert cap.resource == "*"
        assert cap.action == "*"

    def test_resource_action(self):
        cap = pact.parse_capability("repo:read")
        assert cap.resource == "repo"
        assert cap.action == "read"

    def test_resource_wildcard_action(self):
        cap = pact.parse_capability("github:*")
        assert cap.resource == "github"
        assert cap.action == "*"

    def test_hierarchical_resource(self):
        cap = pact.parse_capability("github:pr:create")
        assert cap.resource == "github:pr"
        assert cap.action == "create"

    def test_with_constraints(self):
        cap = pact.parse_capability("repo:read,repo=myorg/*")
        assert cap.resource == "repo"
        assert cap.action == "read"
        assert cap.constraints == {"repo": "myorg/*"}

    def test_multiple_constraints(self):
        cap = pact.parse_capability(
            "deploy:create,env=staging,region=us-east-1")
        assert cap.resource == "deploy"
        assert cap.action == "create"
        assert cap.constraints == {"env": "staging", "region": "us-east-1"}

    def test_shorthand_max_constraint(self):
        cap = pact.parse_capability("flights:book<500USD")
        assert cap.resource == "flights"
        assert cap.action == "book"
        assert cap.constraints == {"max": "500USD"}

    def test_single_segment_implies_wildcard_action(self):
        cap = pact.parse_capability("storage")
        assert cap.resource == "storage"
        assert cap.action == "*"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            pact.parse_capability("")


class TestCapabilityCovers:
    def test_wildcard_covers_everything(self):
        parent = pact.parse_capability("*")
        child = pact.parse_capability("repo:read")
        assert parent.covers(child)

    def test_resource_wildcard_covers_sub_actions(self):
        parent = pact.parse_capability("repo:*")
        child = pact.parse_capability("repo:read")
        assert parent.covers(child)

    def test_exact_match(self):
        parent = pact.parse_capability("repo:read")
        child = pact.parse_capability("repo:read")
        assert parent.covers(child)

    def test_different_action_not_covered(self):
        parent = pact.parse_capability("repo:read")
        child = pact.parse_capability("repo:write")
        assert not parent.covers(child)

    def test_hierarchical_covers(self):
        parent = pact.parse_capability("repo:*")
        child = pact.parse_capability("repo:pr:create")
        assert parent.covers(child)

    def test_glob_constraint(self):
        parent = pact.parse_capability("repo:read,repo=owner/*")
        child = pact.parse_capability("repo:read,repo=owner/myrepo")
        assert parent.covers(child)

    def test_glob_constraint_mismatch(self):
        parent = pact.parse_capability("repo:read,repo=owner/*")
        child = pact.parse_capability("repo:read,repo=other/myrepo")
        assert not parent.covers(child)

    def test_max_constraint_covered(self):
        parent = pact.parse_capability("flights:book,max=500USD")
        child = pact.parse_capability("flights:book,max=300USD")
        assert parent.covers(child)

    def test_max_constraint_not_covered(self):
        parent = pact.parse_capability("flights:book,max=500USD")
        child = pact.parse_capability("flights:book,max=700USD")
        assert not parent.covers(child)

    def test_exact_constraint_match(self):
        parent = pact.parse_capability("deploy:create,env=staging")
        child = pact.parse_capability("deploy:create,env=staging")
        assert parent.covers(child)

    def test_exact_constraint_mismatch(self):
        parent = pact.parse_capability("deploy:create,env=staging")
        child = pact.parse_capability("deploy:create,env=production")
        assert not parent.covers(child)

    def test_child_missing_parent_constraint(self):
        parent = pact.parse_capability("repo:read,repo=owner/*")
        child = pact.parse_capability("repo:read")
        assert not parent.covers(child)


class TestCapabilitySet:
    def test_covers_all(self):
        parent = pact.parse_capability_set(["repo:*", "deploy:create"])
        child = pact.parse_capability_set(["repo:read", "deploy:create"])
        assert parent.covers(child)

    def test_not_covers_missing(self):
        parent = pact.parse_capability_set(["repo:read"])
        child = pact.parse_capability_set(["repo:read", "deploy:create"])
        assert not parent.covers(child)

    def test_empty_child_covered(self):
        parent = pact.parse_capability_set(["repo:*"])
        child = pact.parse_capability_set([])
        assert parent.covers(child)
