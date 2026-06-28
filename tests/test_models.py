"""Tests for data models."""

from spectre.models import AttackResult, EngagementContext


def test_attack_result_defaults():
    r = AttackResult(module="scan", action="subdomain", status="SUCCESS")
    assert r.severity == "INFO"
    assert r.timestamp


def test_engagement_context_defaults():
    ctx = EngagementContext()
    assert ctx.threads == 10
    assert ctx.timeout == 10
    assert ctx.delay == 0.3
    assert ctx.stealth is False
    assert ctx.subdomains == {}
    assert ctx.emails == {}


def test_engagement_context_with_targets():
    ctx = EngagementContext(targets=["example.com", "test.com"])
    assert len(ctx.targets) == 2
