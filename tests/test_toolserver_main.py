"""The deployed MCP tool servers retain Host validation in ACA."""

from __future__ import annotations

import pytest

from sentinel.demo.toolserver_main import _transport_security


def test_aca_internal_hostname_is_allowed_without_disabling_dns_protection() -> None:
    security = _transport_security("sentinel-tools-web")
    assert security.enable_dns_rebinding_protection is True
    assert "sentinel-tools-web" in security.allowed_hosts
    assert "sentinel-tools-web:*" in security.allowed_hosts
    assert "evil.example" not in security.allowed_hosts


@pytest.mark.parametrize("host", ("https://tools.example", "tools.example/mcp", "host:8000", "   "))
def test_internal_hostname_must_be_a_bare_host(host: str) -> None:
    with pytest.raises(ValueError, match="bare hostname"):
        _transport_security(host)
