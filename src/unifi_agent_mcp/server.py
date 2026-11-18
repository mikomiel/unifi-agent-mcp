"""The portable UniFi Network MCP entry point."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, AuthProvider, TokenVerifier, require_scopes

from .broker import BrokerClient
from .firewall import CreateRule, EditRule, FirewallController, PolicyScope, Reason
from .network_api import (
    REQUEST_TIMEOUT_SECONDS,
    UniFiApiError,
    UniFiNetworkApi,
    api_config,
    build_active_clients,
    build_config_map,
    build_endpoint_trace,
    build_firewall_policies,
)


def register_inspection_tools(mcp: FastMCP, api: UniFiNetworkApi) -> None:
    """Add the portable inspection tools to a server."""

    def inspect_controller(
        build: Callable[..., dict[str, Any]], *args: Any
    ) -> dict[str, Any]:
        try:
            return build(api, *args)
        except UniFiApiError as error:
            raise ToolError(str(error)) from None

    @mcp.tool
    def unifi_config_map() -> dict[str, Any]:
        """Map UniFi sites, networks, zones, devices, uplinks, and port state."""
        return inspect_controller(build_config_map)

    @mcp.tool
    def unifi_active_clients(
        query: str | None = None,
        network_id: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List active clients with attachment and network information."""
        return inspect_controller(
            build_active_clients, query, network_id, offset, limit
        )

    @mcp.tool
    def unifi_firewall_policies(
        enabled: bool | None = None,
        source_zone_id: str | None = None,
        destination_zone_id: str | None = None,
    ) -> dict[str, Any]:
        """List firewall policies, zones, ordering, and resolved selectors."""
        return inspect_controller(
            build_firewall_policies, enabled, source_zone_id, destination_zone_id
        )

    @mcp.tool
    def unifi_trace_endpoint(identifier: str) -> dict[str, Any]:
        """Trace active endpoints across devices, networks, and firewall policies."""
        return inspect_controller(build_endpoint_trace, identifier)


_FIREWALL_SCOPE = "unifi:firewall-request"


class _ConfiguredTokens(TokenVerifier):
    def __init__(self, read_token: str, request_token: str) -> None:
        super().__init__()
        if min(len(read_token), len(request_token)) < 32 or read_token == request_token:
            raise ValueError(
                "independent inspection and request credentials are required"
            )
        self._tokens = (
            (hashlib.sha256(read_token.encode()).digest(), "inspection", []),
            (
                hashlib.sha256(request_token.encode()).digest(),
                "approval-requester",
                [_FIREWALL_SCOPE],
            ),
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.encode()).digest()
        result = None
        for expected, client, scopes in self._tokens:
            if hmac.compare_digest(expected, digest):
                result = AccessToken(token=token, client_id=client, scopes=scopes)
        return result


def register_firewall_tools(
    mcp: FastMCP, controller: FirewallController, broker: BrokerClient
) -> None:
    """Add the scoped approval tools to an authenticated shared endpoint."""
    if mcp.auth is None:
        raise ValueError("firewall requests require an authenticated MCP")
    scope = require_scopes(_FIREWALL_SCOPE)

    def broker_call(
        operation: Callable[..., dict[str, Any]], *args: Any
    ) -> dict[str, Any]:
        try:
            return operation(*args)
        except UniFiApiError as error:
            raise ToolError(str(error)) from None
        except ValueError:
            raise ToolError(
                "UNIFI_RULE_UNSUPPORTED: the policy or request is outside the supported rule profile"
            ) from None

    def preview_create(site_id: UUID, rule: CreateRule, reason: str) -> dict[str, Any]:
        return broker.submit(controller.create_preview(site_id, rule, reason))

    def preview_change(
        site_id: UUID, policy_id: UUID, reason: str, edit: EditRule | None
    ) -> dict[str, Any]:
        return broker.submit(
            controller.change_preview(site_id, policy_id, reason, edit)
        )

    @mcp.tool(auth=scope)
    def unifi_firewall_create_request(
        site_id: UUID, rule: CreateRule, reason: Reason
    ) -> dict[str, Any]:
        """Ask the operator to approve creation of a disabled firewall rule."""
        return broker_call(preview_create, site_id, rule, reason)

    @mcp.tool(auth=scope)
    def unifi_firewall_update_request(
        site_id: UUID, policy_id: UUID, edit: EditRule, reason: Reason
    ) -> dict[str, Any]:
        """Ask for approval to edit an admitted user-defined firewall rule."""
        return broker_call(preview_change, site_id, policy_id, reason, edit)

    @mcp.tool(auth=scope)
    def unifi_firewall_delete_request(
        site_id: UUID, policy_id: UUID, reason: Reason
    ) -> dict[str, Any]:
        """Ask for approval to remove an admitted user-defined firewall rule."""
        return broker_call(preview_change, site_id, policy_id, reason, None)

    @mcp.tool(auth=scope)
    def unifi_firewall_request_status(request_id: UUID) -> dict[str, Any]:
        """Read the broker approval and verified execution outcome."""
        return broker_call(broker.status, request_id)


def create_server(
    api: UniFiNetworkApi,
    *,
    auth: AuthProvider | None = None,
    approval: tuple[FirewallController, BrokerClient] | None = None,
) -> FastMCP:
    """Build the read-only-by-default MCP."""
    mcp = FastMCP(
        "unifi-agent-mcp",
        auth=auth,
        instructions="Inspect UniFi Network and, when configured, request approval for firewall policy changes.",
    )
    register_inspection_tools(mcp, api)
    if approval is not None:
        register_firewall_tools(mcp, *approval)
    return mcp


def main() -> int:
    """Serve inspection over stdio or configured approval mode on local HTTP."""
    try:
        certificate_path = os.environ.get("UNIFI_NETWORK_PINNED_CERT_FILE", "")
        certificate = (
            Path(certificate_path).read_text(encoding="utf-8")
            if certificate_path
            else ""
        )
        if certificate_path and not certificate.strip():
            raise UniFiApiError(
                "UNIFI_TLS_FAILED", "controller certificate file is empty"
            )
        config = api_config(
            os.environ.get("UNIFI_NETWORK_URL", ""),
            os.environ.get("UNIFI_NETWORK_API_KEY", ""),
            certificate,
            timeout_seconds=os.environ.get(
                "UNIFI_NETWORK_TIMEOUT_SECONDS", str(REQUEST_TIMEOUT_SECONDS)
            ),
        )
        api = UniFiNetworkApi(config)
        scope_path = os.environ.get("UNIFI_FIREWALL_SCOPE_FILE", "")
        if scope_path:
            scope = PolicyScope.model_validate_json(Path(scope_path).read_bytes())
            auth = _ConfiguredTokens(
                os.environ.get("UNIFI_MCP_READ_TOKEN", ""),
                os.environ.get("UNIFI_MCP_REQUEST_TOKEN", ""),
            )
            port = int(os.environ.get("UNIFI_MCP_PORT", "8080"))
            if not 1 <= port <= 65535:
                raise ValueError("invalid local port")
            mcp = create_server(
                api,
                auth=auth,
                approval=(FirewallController(api, scope), BrokerClient.from_env()),
            )
        else:
            mcp = create_server(api)
    except (OSError, UnicodeError):
        print(
            "UNIFI_MCP_CONFIG: configured file is unreadable",
            file=sys.stderr,
        )
        return 2
    except UniFiApiError as error:
        print(error, file=sys.stderr)
        return 2
    except ValueError:
        print("UNIFI_MCP_CONFIG: invalid approval configuration", file=sys.stderr)
        return 2
    if scope_path:
        mcp.run(
            transport="streamable-http",
            host="127.0.0.1",
            port=port,
            stateless_http=True,
        )
    else:
        mcp.run()
    return 0
