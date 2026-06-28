"""Tests for CLI."""

from spectre.cli import MODULE_REGISTRY, build_parser


def test_all_modules_registered():
    expected = {"scan", "email", "dns", "cert", "search", "social"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_domain_arg():
    p = build_parser()
    args = p.parse_args(["--domain", "example.com"])
    assert args.domain == "example.com"


def test_default_modules():
    p = build_parser()
    args = p.parse_args(["-d", "example.com"])
    assert args.modules == ["scan"]


def test_stealth_flag():
    p = build_parser()
    args = p.parse_args(["-d", "example.com", "--stealth"])
    assert args.stealth is True


def test_threads_default():
    p = build_parser()
    args = p.parse_args(["-d", "example.com"])
    assert args.threads == 10
