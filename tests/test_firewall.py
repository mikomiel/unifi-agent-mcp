from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unifi_agent_mcp.broker import BrokerClient
from unifi_agent_mcp.executor import execute, reconcile, verify_claim
from unifi_agent_mcp.firewall import (
    CreateRule,
    EditRule,
    FirewallController,
    PolicyScope,
    RuleTarget,
)
from unifi_agent_mcp.network_api import UniFiApiError, UniFiNetworkApi, api_config
from unifi_agent_mcp.server import _ConfiguredTokens, create_server

SITE = UUID("a1000000-0000-4000-8000-000000000001")
SOURCE = UUID("a1000000-0000-4000-8000-000000000002")
DESTINATION = UUID("a1000000-0000-4000-8000-000000000003")
POLICY = UUID("a1000000-0000-4000-8000-000000000004")
OTHER = UUID("a1000000-0000-4000-8000-000000000005")
REQUEST = UUID("a1000000-0000-4000-8000-000000000006")


class FakeController:
    def __init__(self):
        self.policy = None
        self.calls = []
        self.extra_ordered = []
        self.drop_response = False

    def get(self, path, query=None):
        if path.endswith("/ordering"):
            assert query["sourceFirewallZoneId"] == str(SOURCE)
            assert query["destinationFirewallZoneId"] == str(DESTINATION)
            rules = [str(POLICY)] if self.policy else []
            return {
                "orderedFirewallPolicyIds": {
                    "beforeSystemDefined": [],
                    "afterSystemDefined": rules + self.extra_ordered,
                }
            }
        if self.policy is None:
            raise UniFiApiError("UNIFI_API_UNSUPPORTED", "rule is absent")
        return self.policy.copy()

    def _request(self, method, path, *, body):
        self.calls.append((method, path, body))
        if method == "DELETE":
            self.policy = None
        else:
            self.policy = {
                **body,
                "id": str(POLICY),
                "index": 10000,
                "metadata": {"origin": "USER_DEFINED"},
            }
        if self.drop_response:
            raise UniFiApiError("UNIFI_UPSTREAM_UNAVAILABLE", "response lost")
        return self.policy or {}


def fixture():
    api = FakeController()
    scope = PolicyScope(
        targets=[
            RuleTarget(site_id=SITE, source_zone=SOURCE, destination_zone=DESTINATION)
        ]
    )
    return FirewallController(api, scope), api


def new_rule():
    return CreateRule(
        source_zone=SOURCE,
        destination_zone=DESTINATION,
        name="Example rule",
        action="ALLOW",
    )


def approved(controller, change):
    return execute(controller, change, int(time.time()) + 90)


def test_create_edit_delete_use_the_expected_methods_and_readback():
    controller, api = fixture()
    create = controller.create_preview(SITE, new_rule(), "Create a rule")
    assert create.after["enabled"] is False
    assert api.calls == []
    assert approved(controller, create)["state"] == "succeeded"
    api.policy["ipsecFilter"] = "MATCH_ENCRYPTED"
    update = controller.change_preview(
        SITE, POLICY, "Edit a rule", EditRule(name="Edited example")
    )
    assert update.after["ipsecFilter"] == "MATCH_ENCRYPTED"
    assert approved(controller, update)["state"] == "succeeded"
    delete = controller.change_preview(SITE, POLICY, "Delete the rule", None)
    assert approved(controller, delete)["state"] == "succeeded"
    assert [request[0] for request in api.calls] == ["POST", "PUT", "DELETE"]
    assert api.calls[0][1] == f"/v1/sites/{SITE}/firewall/policies"
    assert [call[1] for call in api.calls[1:]] == [
        f"/v1/sites/{SITE}/firewall/policies/{POLICY}"
    ] * 2


def test_refuses_stale_order_unknown_fields_and_protected_targets():
    controller, api = fixture()
    create = controller.create_preview(SITE, new_rule(), "A test change")
    api.extra_ordered.append(str(OTHER))
    assert approved(controller, create)["code"] == "UNIFI_POLICY_CHANGED"
    assert api.calls == []
    api.extra_ordered.clear()
    assert approved(controller, create)["state"] == "succeeded"
    api.policy["newControllerField"] = "preserve"
    with pytest.raises(UniFiApiError, match="UNIFI_RULE_UNSUPPORTED"):
        controller.change_preview(
            SITE, POLICY, "Edit unsupported rule", EditRule(enabled=True)
        )
    api.policy["metadata"]["origin"] = "SYSTEM_DEFINED"
    with pytest.raises(UniFiApiError, match="UNIFI_TARGET_REFUSED"):
        controller.change_preview(SITE, POLICY, "Try a protected rule", None)
    assert len(api.calls) == 1


def test_fresh_read_detects_stale_rule_before_a_write():
    controller, api = fixture()
    assert (
        approved(controller, controller.create_preview(SITE, new_rule(), "Create"))[
            "state"
        ]
        == "succeeded"
    )
    update = controller.change_preview(SITE, POLICY, "Edit", EditRule(enabled=True))
    api.policy["name"] = "Concurrent UI edit"
    assert approved(controller, update)["code"] == "UNIFI_POLICY_CHANGED"
    assert len(api.calls) == 1


def test_lost_response_uses_read_back_once():
    controller, api = fixture()
    assert (
        approved(controller, controller.create_preview(SITE, new_rule(), "Create"))[
            "state"
        ]
        == "succeeded"
    )
    update = controller.change_preview(SITE, POLICY, "Edit", EditRule(enabled=True))
    api.drop_response = True
    assert approved(controller, update)["state"] == "succeeded"
    assert len(api.calls) == 2
    assert (
        approved(controller, controller.change_preview(SITE, POLICY, "Delete", None))[
            "state"
        ]
        == "succeeded"
    )
    assert len(api.calls) == 3


def test_approval_binds_executor_request_id_and_proposal(monkeypatch):
    controller, _ = fixture()
    proposal = controller.create_preview(SITE, new_rule(), "Prepare").model_dump(
        mode="json"
    )
    private_key = Ed25519PrivateKey.generate()
    now = int(time.time())
    grant = {
        "schema": "unifi-firewall-approval.v1",
        "executor": "synthetic-executor",
        "request_id": str(REQUEST),
        "issued_at": now,
        "expires_at": now + 30,
        "proposal_digest": hashlib.sha256(canonical(proposal)).hexdigest(),
    }
    signature = (
        base64.urlsafe_b64encode(private_key.sign(canonical(grant)))
        .rstrip(b"=")
        .decode()
    )
    response = {"grant": grant, "signature": signature, "proposal": proposal}
    key = private_key.public_key()
    assert (
        verify_claim(response, REQUEST, "synthetic-executor", key)[0].operation
        == "create"
    )
    with pytest.raises(UniFiApiError, match="UNIFI_GRANT_REFUSED"):
        verify_claim(response, OTHER, "synthetic-executor", key)
    with pytest.raises(UniFiApiError, match="UNIFI_GRANT_REFUSED"):
        verify_claim(response, REQUEST, "another-executor", key)
    with monkeypatch.context() as expired:
        expired.setattr("unifi_agent_mcp.executor.time.time", lambda: now + 30)
        with pytest.raises(UniFiApiError, match="UNIFI_GRANT_REFUSED"):
            verify_claim(response, REQUEST, "synthetic-executor", key)
    proposal["reason"] = "Altered after approval"
    with pytest.raises(UniFiApiError, match="UNIFI_GRANT_REFUSED"):
        verify_claim(response, REQUEST, "synthetic-executor", key)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()


def test_only_the_privileged_token_has_the_request_scope():
    verifier = _ConfiguredTokens("a" * 32, "b" * 32)
    assert asyncio.run(verifier.verify_token("a" * 32)).scopes == []
    assert asyncio.run(verifier.verify_token("b" * 32)).scopes == [
        "unifi:firewall-request"
    ]
    assert asyncio.run(verifier.verify_token("c" * 32)) is None
    with pytest.raises(ValueError, match="independent"):
        _ConfiguredTokens("a" * 32, "a" * 32)


def test_firewall_tools_require_an_auth_provider():
    api = UniFiNetworkApi(
        api_config("https://controller.example.test/integration", "example-token")
    )
    controller, _ = fixture()
    with pytest.raises(ValueError, match="authenticated MCP"):
        create_server(api, approval=(controller, None))


def test_interrupted_claim_reconciliation_never_calls_a_write():
    controller, api = fixture()
    assert (
        approved(controller, controller.create_preview(SITE, new_rule(), "Create"))[
            "state"
        ]
        == "succeeded"
    )
    edit = controller.change_preview(SITE, POLICY, "Rename", EditRule(name="After"))
    assert reconcile(controller, edit)["state"] == "uncertain"
    api.policy["name"] = "After"
    assert reconcile(controller, edit)["state"] == "succeeded"
    api.policy["ipsecFilter"] = "MATCH_ENCRYPTED"
    assert reconcile(controller, edit)["state"] == "uncertain"
    assert len(api.calls) == 1


@pytest.mark.parametrize("failure", [ConnectionRefusedError, TimeoutError])
def test_broker_outages_refuse_requests_without_a_controller_write(failure):
    class OfflineBroker:
        def open(self, request, *, timeout):
            assert request.method == "POST"
            assert timeout == 10
            raise failure("synthetic broker offline")

    controller, api = fixture()
    broker = BrokerClient("https://broker.example.test", OfflineBroker())
    preview = controller.create_preview(SITE, new_rule(), "Prepare")
    with pytest.raises(UniFiApiError, match="UNIFI_BROKER_UNAVAILABLE"):
        broker.submit(preview)
    assert api.calls == []
