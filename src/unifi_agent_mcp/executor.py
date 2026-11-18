"""Apply claimed UniFi changes using the executor's own controller credential."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .broker import BrokerClient
from .firewall import FirewallController, PolicyScope, Proposal, read_back
from .network_api import (
    REQUEST_TIMEOUT_SECONDS,
    UniFiApiError,
    UniFiNetworkApi,
    api_config,
)


class _Grant(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal["unifi-firewall-approval.v1"] = Field(alias="schema")
    request_id: str
    proposal_digest: str
    executor: str
    issued_at: int
    expires_at: int


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=True, allow_nan=False
    ).encode()


def verify_claim(
    response: dict[str, Any],
    request_id: UUID,
    identity: str,
    key: Ed25519PublicKey,
) -> tuple[Proposal, int]:
    try:
        grant = _Grant.model_validate(response["grant"], strict=True)
        sig_text = response["signature"].encode()
        sig = base64.b64decode(
            sig_text + b"=" * (-len(sig_text) % 4), altchars=b"-_", validate=True
        )
        key.verify(sig, _canonical(response["grant"]))
        digest = hashlib.sha256(_canonical(response["proposal"])).hexdigest()
        if (
            grant.request_id != str(request_id)
            or grant.executor != identity
            or grant.proposal_digest != digest
            or not grant.issued_at <= int(time.time()) < grant.expires_at
            or not 0 < grant.expires_at - grant.issued_at <= 90
        ):
            raise ValueError("grant binding mismatch")
        return Proposal.model_validate(response["proposal"]), grant.expires_at
    except (KeyError, TypeError, AttributeError, ValueError, InvalidSignature):
        raise UniFiApiError(
            "UNIFI_GRANT_REFUSED", "the execution authorization is invalid or stale"
        ) from None


def _outcome(
    state: str, code: str, observed: UUID | None = None
) -> dict[str, str | None]:
    return {
        "state": state,
        "code": code,
        "observed_policy_id": str(observed) if observed else None,
    }


def execute(
    controller: FirewallController, proposal: Proposal, expires_at: int
) -> dict[str, str | None]:
    try:
        controller.recheck(proposal)
    except UniFiApiError as error:
        return _outcome("refused", error.code)
    except (ValueError, ValidationError):
        return _outcome("refused", "UNIFI_RULE_UNSUPPORTED")
    if int(time.time()) >= expires_at:
        return _outcome("refused", "UNIFI_GRANT_EXPIRED")

    observed = proposal.policy_id
    try:
        response = controller.send(proposal)
        if proposal.operation == "create":
            observed = UUID(response.get("id", ""))
    except (UniFiApiError, AttributeError, ValueError):
        # A failed response can follow an applied write. Verify state once.
        pass
    try:
        if read_back(controller, proposal, observed):
            return _outcome("succeeded", "UNIFI_VERIFIED", observed)
    except (UniFiApiError, ValueError):
        pass
    return _outcome("uncertain", "UNIFI_READBACK_UNVERIFIED", observed)


def reconcile(
    controller: FirewallController, proposal: Proposal
) -> dict[str, str | None]:
    """Resolve a consumed claim through controller reads alone."""
    try:
        controller.scope.check(proposal.target, proposal.policy_id)
        if read_back(controller, proposal, proposal.policy_id):
            return _outcome("succeeded", "UNIFI_VERIFIED", proposal.policy_id)
    except (UniFiApiError, ValueError):
        pass
    return _outcome("uncertain", "UNIFI_READBACK_UNVERIFIED", proposal.policy_id)


def run_ready(
    broker: BrokerClient,
    controller: FirewallController,
    identity: str,
    key: Ed25519PublicKey,
) -> int:
    """Drain the broker's bounded approved queue without re-claiming a request."""
    errors = 0
    ready, recover = broker.work()
    for request_id in ready:
        try:
            claim = broker.claim(request_id)
            proposal, expires_at = verify_claim(claim, request_id, identity, key)
            broker.report(request_id, execute(controller, proposal, expires_at))
        except UniFiApiError as error:
            errors += 1
            print(f"UniFi request {request_id}: {error.code}", file=sys.stderr)
    for request_id in recover:
        try:
            proposal = broker.recovery(request_id)
            broker.report(request_id, reconcile(controller, proposal))
        except UniFiApiError as error:
            errors += 1
            print(f"UniFi request {request_id}: {error.code}", file=sys.stderr)
    return int(errors != 0)


def main() -> int:
    """Process the currently approved broker queue once."""
    try:
        identity = os.environ["UNIFI_BROKER_EXECUTOR_IDENTITY"].strip()
        if not identity:
            raise ValueError("executor identity is required")
        key = load_ssh_public_key(
            Path(os.environ["UNIFI_BROKER_SIGNING_PUBLIC_KEY_FILE"]).read_bytes()
        )
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("executor requires an Ed25519 broker signing key")
        scope = PolicyScope.model_validate_json(
            Path(os.environ["UNIFI_FIREWALL_SCOPE_FILE"]).read_bytes()
        )
        certificate_path = os.environ.get("UNIFI_NETWORK_PINNED_CERT_FILE", "")
        certificate = (
            Path(certificate_path).read_text(encoding="utf-8")
            if certificate_path
            else ""
        )
        if certificate_path and not certificate.strip():
            raise ValueError("controller certificate file is empty")
        config = api_config(
            os.environ["UNIFI_NETWORK_URL"],
            os.environ["UNIFI_NETWORK_WRITE_KEY"],
            certificate,
            timeout_seconds=os.environ.get(
                "UNIFI_NETWORK_TIMEOUT_SECONDS", str(REQUEST_TIMEOUT_SECONDS)
            ),
        )
        controller = FirewallController(UniFiNetworkApi(config), scope)
        return run_ready(BrokerClient.from_env(), controller, identity, key)
    except UniFiApiError as error:
        print(error.code, file=sys.stderr)
    except (KeyError, OSError, TypeError, ValueError):
        print("UNIFI_EXECUTOR_CONFIG: invalid executor configuration", file=sys.stderr)
    return 2
