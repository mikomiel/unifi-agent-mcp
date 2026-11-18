from __future__ import annotations

import asyncio

import pytest
from fastmcp import Client

from unifi_agent_mcp.network_api import UniFiApiError, UniFiNetworkApi, api_config
from unifi_agent_mcp.server import create_server, main


def test_default_mcp_lists_the_four_inspection_tools() -> None:
    server = create_server(
        UniFiNetworkApi(
            api_config("https://controller.example.test/integration", "example-key")
        )
    )

    async def list_names() -> set[str]:
        async with Client(server) as client:
            return {tool.name for tool in await client.list_tools()}

    assert asyncio.run(list_names()) == {
        "unifi_config_map",
        "unifi_active_clients",
        "unifi_firewall_policies",
        "unifi_trace_endpoint",
    }


@pytest.mark.parametrize(
    "url",
    (
        "http://controller.example.test/integration",
        "https://user:pass@controller.example.test/integration",
        "https://controller.example.test/integration?site=example",
        "https://controller.example.test:bad/integration",
    ),
)
def test_startup_rejects_invalid_origins(url, monkeypatch, capsys) -> None:
    monkeypatch.setenv("UNIFI_NETWORK_URL", url)
    monkeypatch.setenv("UNIFI_NETWORK_API_KEY", "example-credential")
    monkeypatch.delenv("UNIFI_NETWORK_PINNED_CERT_FILE", raising=False)
    assert main() == 2
    message = capsys.readouterr().err
    assert "UNIFI_API_NOT_CONFIGURED" in message
    assert "example-credential" not in message
    assert "user:pass" not in message


def test_configured_empty_pin_refuses_startup(tmp_path, monkeypatch, capsys) -> None:
    certificate = tmp_path / "empty.pem"
    certificate.write_text("\n")
    monkeypatch.setenv(
        "UNIFI_NETWORK_URL", "https://controller.example.test/integration"
    )
    monkeypatch.setenv("UNIFI_NETWORK_API_KEY", "example-key")
    monkeypatch.setenv("UNIFI_NETWORK_PINNED_CERT_FILE", str(certificate))
    assert main() == 2
    assert "UNIFI_TLS_FAILED" in capsys.readouterr().err


def test_controller_timeout_is_bounded() -> None:
    url = "https://controller.example.test/integration"
    assert api_config(url, "example-key", timeout_seconds="7").timeout_seconds == 7
    for value in ("0", "61", "invalid"):
        with pytest.raises(UniFiApiError, match="1 to 60 seconds"):
            api_config(url, "example-key", timeout_seconds=value)
