"""Tests for network utilities."""

from spectre.utils.network import resolve_host


def test_resolve_localhost():
    result = resolve_host("localhost")
    assert result == "127.0.0.1"


def test_resolve_nonexistent():
    result = resolve_host("this-domain-does-not-exist-xyz123.invalid")
    assert result is None
