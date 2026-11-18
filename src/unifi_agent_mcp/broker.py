"""Authenticated client for the broker's UniFi operation family."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from uuid import UUID

from .firewall import Proposal
from .network_api import UniFiApiError, _RejectRedirect

_PREFIX = "/v1/unifi/requests"
_MAX_RESPONSE = 65_536


class BrokerClient:
    def __init__(self, url: str, opener: Any) -> None:
        try:
            endpoint = urllib.parse.urlsplit(url)
            port = endpoint.port
        except ValueError:
            raise UniFiApiError("UNIFI_BROKER_CONFIG", "invalid broker URL") from None
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.path not in ("", "/")
            or endpoint.query
            or endpoint.fragment
            or port == 0
        ):
            raise UniFiApiError(
                "UNIFI_BROKER_CONFIG", "broker needs one authenticated HTTPS origin"
            )
        self.url = endpoint.geturl().rstrip("/")
        self.opener = opener

    @classmethod
    def from_env(cls) -> BrokerClient:
        cert = os.environ.get("UNIFI_BROKER_CLIENT_CERT_FILE", "")
        key = os.environ.get("UNIFI_BROKER_CLIENT_KEY_FILE", "")
        if not cert or not key:
            raise UniFiApiError(
                "UNIFI_BROKER_CONFIG",
                "broker client certificate and key files are required",
            )
        try:
            context = ssl.create_default_context(
                cafile=os.environ.get("UNIFI_BROKER_CA_FILE") or None
            )
            context.load_cert_chain(cert, key)
        except (OSError, ValueError):
            raise UniFiApiError(
                "UNIFI_BROKER_CONFIG", "broker mTLS configuration is invalid"
            ) from None
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _RejectRedirect(),
        )
        return cls(os.environ.get("UNIFI_BROKER_URL", ""), opener)

    def _call(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        request = urllib.request.Request(
            self.url + path,
            method=method,
            data=data,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                payload = response.read(_MAX_RESPONSE + 1)
        except urllib.error.HTTPError as error:
            code = (
                "UNIFI_BROKER_REFUSED"
                if error.code in (400, 401, 403, 404, 409, 422)
                else "UNIFI_BROKER_UNAVAILABLE"
            )
            raise UniFiApiError(code, f"broker returned HTTP {error.code}") from None
        except (ssl.SSLError, OSError, UniFiApiError):
            raise UniFiApiError(
                "UNIFI_BROKER_UNAVAILABLE", "broker request failed"
            ) from None
        if len(payload) > _MAX_RESPONSE:
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker response exceeded its size limit"
            )
        try:
            decoded = json.loads(payload)
        except (UnicodeError, ValueError):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker did not return JSON"
            ) from None
        if not isinstance(decoded, dict):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker response was not an object"
            )
        return decoded

    def submit(self, proposal: Proposal) -> dict[str, Any]:
        response = self._call("POST", _PREFIX, proposal.model_dump(mode="json"))
        try:
            request_id = UUID(response["request_id"])
            approval = urllib.parse.urlsplit(response["approval_url"])
        except (KeyError, TypeError, AttributeError, ValueError):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid request reference"
            ) from None
        if (
            response.get("status") != "pending"
            or approval.scheme != "https"
            or not approval.hostname
            or approval.username is not None
            or approval.path != f"{_PREFIX}/{request_id}/approval"
            or approval.query
            or approval.fragment
        ):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid approval reference"
            )
        return {
            "request_id": str(request_id),
            "status": "pending",
            "approval_url": approval.geturl(),
        }

    def status(self, request_id: UUID) -> dict[str, Any]:
        response = self._call("GET", f"{_PREFIX}/{request_id}")
        if response.get("request_id") != str(request_id):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned a different request"
            )
        result = response.get("result")
        if result is not None and not isinstance(result, dict):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid outcome"
            )
        return {
            "request_id": str(request_id),
            "status": response.get("status"),
            "execution_state": response.get("execution_state"),
            "result": {
                key: result.get(key) for key in ("state", "code", "observed_policy_id")
            }
            if result
            else None,
        }

    def work(self) -> tuple[list[UUID], list[UUID]]:
        response = self._call("GET", "/v1/unifi/work")
        return self._ids(response.get("request_ids")), self._ids(
            response.get("recover_ids")
        )

    @staticmethod
    def _ids(items: object) -> list[UUID]:
        if not isinstance(items, list) or len(items) > 20:
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid queue"
            )
        try:
            return [UUID(item) for item in items]
        except (TypeError, AttributeError, ValueError):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid request ID"
            ) from None

    def recovery(self, request_id: UUID) -> Proposal:
        response = self._call("GET", f"{_PREFIX}/{request_id}/recovery")
        try:
            return Proposal.model_validate(response["proposal"])
        except (KeyError, ValueError):
            raise UniFiApiError(
                "UNIFI_BROKER_INVALID", "broker returned an invalid recovery proposal"
            ) from None

    def claim(self, request_id: UUID) -> dict[str, Any]:
        return self._call("POST", f"{_PREFIX}/{request_id}/claim")

    def report(self, request_id: UUID, result: dict[str, Any]) -> None:
        self._call("POST", f"{_PREFIX}/{request_id}/result", result)
