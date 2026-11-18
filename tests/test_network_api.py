from __future__ import annotations

import json
import ssl
import threading
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from unifi_agent_mcp import network_api as api


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.payload[:size]


class FakeOpener:
    def __init__(self, payload: dict[str, Any] | bytes | Exception) -> None:
        self.payload = payload
        self.calls: list[tuple[Any, int]] = []

    def open(self, request: Any, timeout: int) -> FakeResponse:
        self.calls.append((request, timeout))
        if isinstance(self.payload, Exception):
            raise self.payload
        encoded = (
            self.payload
            if isinstance(self.payload, bytes)
            else json.dumps(self.payload).encode()
        )
        return FakeResponse(encoded)


class SequenceOpener:
    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self.payloads = iter(payloads)
        self.calls: list[tuple[Any, int]] = []

    def open(self, request: Any, timeout: int) -> FakeResponse:
        self.calls.append((request, timeout))
        return FakeResponse(json.dumps(next(self.payloads)).encode())


def config(
    max_response_bytes: int = api.MAX_RESPONSE_BYTES,
    certificate_pem: str = "synthetic-certificate",
) -> api.UniFiApiConfig:
    return api.UniFiApiConfig(
        base_url="https://192.0.2.1/proxy/network/integration",
        api_key="synthetic-api-key",
        certificate_pem=certificate_pem,
        timeout_seconds=10,
        max_response_bytes=max_response_bytes,
    )


def self_signed_leaf_files(
    tmp_path: Path, stem: str = "controller"
) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "controller.example.test")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("controller.example.test")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_path = tmp_path / f"{stem}.pem"
    key_path = tmp_path / f"{stem}-key.pem"
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path, certificate_pem.decode()


class JsonHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        payload = b'{"applicationVersion":"synthetic"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


@contextmanager
def https_json_server(certificate_path: Path, key_path: Path) -> Iterator[str]:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certificate_path, key_path)
    server = HTTPServer(("127.0.0.1", 0), JsonHandler)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_transport_is_fixed_get_with_api_key_and_encoded_query() -> None:
    opener = FakeOpener({"data": []})
    client = api.UniFiNetworkApi(config(), opener=opener)
    assert client.get("/v1/sites/site-id/clients", {"offset": 4, "limit": 20}) == {
        "data": []
    }
    request, timeout = opener.calls[0]
    assert request.method == "GET"
    assert request.full_url == (
        "https://192.0.2.1/proxy/network/integration/v1/sites/site-id/clients?offset=4&limit=20"
    )
    assert request.headers["X-api-key"] == "synthetic-api-key"
    assert timeout == 10
    assert request.data is None


@pytest.mark.parametrize(
    "path",
    ["https://example.test/v1/sites", "/api/s/default/stat/device", "/v1/../secrets"],
)
def test_transport_refuses_non_contract_paths(path: str) -> None:
    client = api.UniFiNetworkApi(config(), opener=FakeOpener({}))
    with pytest.raises(api.UniFiApiError, match="UNIFI_API_UNSUPPORTED"):
        client.get(path)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "UNIFI_AUTH_FAILED"),
        (403, "UNIFI_AUTH_FAILED"),
        (404, "UNIFI_API_UNSUPPORTED"),
        (429, "UNIFI_RATE_LIMITED"),
    ],
)
def test_transport_classifies_http_failures(status: int, code: str) -> None:
    error = urllib.error.HTTPError("https://controller", status, "synthetic", {}, None)
    client = api.UniFiNetworkApi(config(), opener=FakeOpener(error))
    with pytest.raises(api.UniFiApiError, match=code):
        client.get("/v1/info")


def test_transport_classifies_tls_failure() -> None:
    client = api.UniFiNetworkApi(
        config(), opener=FakeOpener(urllib.error.URLError(ssl.SSLError("synthetic")))
    )
    with pytest.raises(api.UniFiApiError, match="UNIFI_TLS_FAILED"):
        client.get("/v1/info")


def test_transport_trusts_the_exact_pinned_self_signed_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path, key_path, certificate_pem = self_signed_leaf_files(tmp_path)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with https_json_server(certificate_path, key_path) as base_url:
        test_config = api.UniFiApiConfig(
            base_url=base_url,
            api_key="synthetic-api-key",
            certificate_pem=certificate_pem,
            timeout_seconds=10,
            max_response_bytes=api.MAX_RESPONSE_BYTES,
        )
        assert api.UniFiNetworkApi(test_config).get("/v1/info") == {
            "applicationVersion": "synthetic"
        }


def test_transport_rejects_a_leaf_that_does_not_match_the_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path, key_path, _ = self_signed_leaf_files(tmp_path)
    _, _, unrelated_certificate_pem = self_signed_leaf_files(tmp_path, "unrelated")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with https_json_server(certificate_path, key_path) as base_url:
        test_config = api.UniFiApiConfig(
            base_url=base_url,
            api_key="synthetic-api-key",
            certificate_pem=unrelated_certificate_pem,
            timeout_seconds=10,
            max_response_bytes=api.MAX_RESPONSE_BYTES,
        )
        with pytest.raises(api.UniFiApiError, match="UNIFI_TLS_FAILED"):
            api.UniFiNetworkApi(test_config).get("/v1/info")


def test_transport_rejects_invalid_pinned_certificate() -> None:
    with pytest.raises(api.UniFiApiError, match="UNIFI_TLS_FAILED"):
        api.UniFiNetworkApi(config())


def test_transport_installs_a_redirect_refusal_before_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, certificate_pem = self_signed_leaf_files(tmp_path)
    installed: list[Any] = []
    monkeypatch.setattr(
        api.urllib.request,
        "build_opener",
        lambda *handlers: installed.extend(handlers) or object(),
    )

    api.UniFiNetworkApi(config(certificate_pem=certificate_pem))
    redirect_handler = next(
        handler for handler in installed if isinstance(handler, api._RejectRedirect)
    )
    authenticated_request = api.urllib.request.Request(
        "https://192.0.2.1/v1/info",
        headers={"X-API-Key": "synthetic-api-key"},
    )
    with pytest.raises(api.UniFiApiError, match="UNIFI_UPSTREAM_UNAVAILABLE"):
        redirect_handler.redirect_request(
            authenticated_request,
            None,
            302,
            "synthetic redirect",
            {},
            "http://attacker.invalid/capture",
        )


@pytest.mark.parametrize("payload", [b"not-json", b"[]"])
def test_transport_rejects_invalid_json_shape(payload: bytes) -> None:
    client = api.UniFiNetworkApi(config(), opener=FakeOpener(payload))
    with pytest.raises(api.UniFiApiError, match="UNIFI_RESPONSE_INVALID"):
        client.get("/v1/info")


def test_transport_rejects_response_over_bound() -> None:
    client = api.UniFiNetworkApi(
        config(max_response_bytes=8), opener=FakeOpener(b"{" + b"x" * 20)
    )
    with pytest.raises(api.UniFiApiError, match="exceeded the 1 MiB bound"):
        client.get("/v1/info")


def test_transport_paginates_until_reported_total() -> None:
    opener = SequenceOpener(
        [
            {"data": [{"id": "one"}, {"id": "two"}], "totalCount": 3},
            {"data": [{"id": "three"}], "totalCount": 3},
        ]
    )
    result = api.UniFiNetworkApi(config(), opener=opener).get_all("/v1/sites")
    assert [item["id"] for item in result.items] == ["one", "two", "three"]
    assert result.total == 3
    assert result.truncated is False
    assert opener.calls[0][0].full_url.endswith("?offset=0&limit=200")
    assert opener.calls[1][0].full_url.endswith("?offset=2&limit=200")


def test_transport_marks_irregular_page_overshoot_as_truncated() -> None:
    payloads = [
        {
            "data": [{"id": f"item-{page}-{index}"} for index in range(199)],
            "totalCount": 2050,
        }
        for page in range(10)
    ]
    payloads.append(
        {"data": [{"id": f"last-{index}"} for index in range(60)], "totalCount": 2050}
    )
    result = api.UniFiNetworkApi(config(), opener=SequenceOpener(payloads)).get_all(
        "/v1/sites"
    )
    assert len(result.items) == api.MAX_ITEMS_PER_FAMILY
    assert result.total == 2050
    assert result.truncated is True


class FixtureApi:
    site_id = "11111111-1111-1111-1111-111111111111"
    network_id = "22222222-2222-2222-2222-222222222222"
    zone_id = "33333333-3333-3333-3333-333333333333"
    device_id = "44444444-4444-4444-4444-444444444444"
    client_id = "55555555-5555-5555-5555-555555555555"
    list_id = "66666666-6666-6666-6666-666666666666"
    policy_id = "77777777-7777-7777-7777-777777777777"

    def get(self, path: str, query: dict[str, int] | None = None) -> dict[str, Any]:
        assert query is None
        if path == "/v1/info":
            return {"applicationVersion": "10.4.57", "privateToken": "must-not-leak"}
        if path.endswith(f"/networks/{self.network_id}"):
            return {
                "id": self.network_id,
                "name": "Workstations",
                "vlanId": 30,
                "enabled": True,
                "default": False,
                "management": "GATEWAY",
                "zoneId": self.zone_id,
                "ipv4Configuration": {"hostIpAddress": "192.0.2.1", "prefixLength": 24},
                "metadata": {
                    "origin": "USER",
                    "configurable": False,
                    "secret": "must-not-leak",
                },
                "radiusSecret": "must-not-leak",
            }
        if path.endswith(f"/devices/{self.device_id}"):
            return {
                "id": self.device_id,
                "name": "Core Switch",
                "model": "USW-SYNTHETIC",
                "macAddress": "02:00:00:00:00:01",
                "ipAddress": "192.0.2.2",
                "state": "ONLINE",
                "supported": True,
                "uplink": {"deviceId": "gateway-id"},
                "interfaces": {
                    "ports": [
                        {
                            "idx": 7,
                            "state": "UP",
                            "connector": "RJ45",
                            "speedMbps": 1000,
                        }
                    ],
                    "privateKey": "must-not-leak",
                },
                "sshPassword": "must-not-leak",
            }
        raise AssertionError(f"unexpected GET {path}")

    def get_all(self, path: str) -> api.PageResult:
        if path == "/v1/sites":
            return api.PageResult(
                [
                    {
                        "id": self.site_id,
                        "name": "Default",
                        "internalReference": "default",
                        "secret": "no",
                    }
                ],
                1,
                False,
            )
        if path.endswith("/networks"):
            return api.PageResult(
                [{"id": self.network_id, "name": "Workstations", "vlanId": 30}],
                1,
                False,
            )
        if path.endswith("/firewall/zones"):
            return api.PageResult(
                [
                    {
                        "id": self.zone_id,
                        "name": "Internal",
                        "networkIds": [self.network_id],
                        "metadata": {},
                    }
                ],
                1,
                False,
            )
        if path.endswith("/devices"):
            return api.PageResult(
                [{"id": self.device_id, "name": "Core Switch"}], 1, False
            )
        if path.endswith("/clients"):
            return api.PageResult(
                [
                    {
                        "id": self.client_id,
                        "name": "Laptop",
                        "type": "WIRED",
                        "macAddress": "02:00:00:00:00:02",
                        "ipAddress": "192.0.2.25",
                        "uplinkDeviceId": self.device_id,
                        "access": {"type": "DEFAULT"},
                        "password": "must-not-leak",
                    }
                ],
                1,
                False,
            )
        if path.endswith("/firewall/policies"):
            return api.PageResult(
                [
                    {
                        "id": self.policy_id,
                        "name": "Allow workstations",
                        "description": "Synthetic policy",
                        "enabled": True,
                        "index": 10,
                        "action": {
                            "type": "ALLOW",
                            "allowReturnTraffic": True,
                            "token": "must-not-leak",
                        },
                        "source": {
                            "zoneId": self.zone_id,
                            "trafficFilter": {
                                "type": "NETWORK",
                                "networkFilter": {"networkId": self.network_id},
                            },
                        },
                        "destination": {
                            "zoneId": self.zone_id,
                            "trafficFilter": {
                                "type": "PORT",
                                "portFilter": {"trafficMatchingListId": self.list_id},
                            },
                        },
                        "ipProtocolScope": {
                            "ipVersion": "IPV4",
                            "protocolFilter": {"type": "PROTOCOL_PRESET"},
                        },
                        "loggingEnabled": True,
                        "metadata": {"origin": "USER"},
                        "apiKey": "must-not-leak",
                    }
                ],
                1,
                False,
            )
        if path.endswith("/traffic-matching-lists"):
            return api.PageResult(
                [
                    {
                        "id": self.list_id,
                        "name": "Web",
                        "type": "PORTS",
                        "items": [
                            {
                                "type": "PORT_NUMBER",
                                "value": 443,
                                "secret": "must-not-leak",
                            }
                        ],
                    }
                ],
                1,
                False,
            )
        raise AssertionError(f"unexpected page {path}")


def test_config_map_normalizes_relationships_and_drops_unknown_fields() -> None:
    result = api.build_config_map(FixtureApi())
    assert result["schema"] == "unifi-read.v1"
    site = result["sites"][0]
    assert site["networks"][0]["vlan_id"] == 30
    assert site["networks"][0]["ipv4_subnet"] == "192.0.2.0/24"
    assert site["networks"][0]["metadata"] == {"origin": "USER", "configurable": False}
    assert site["zones"][0]["network_ids"] == [FixtureApi.network_id]
    assert site["devices"][0]["uplink_device_id"] == "gateway-id"
    assert site["devices"][0]["ports"] == [
        {"index": 7, "state": "UP", "connector": "RJ45", "speed_mbps": 1000}
    ]
    assert "must-not-leak" not in json.dumps(result)


def test_active_clients_filters_and_marks_network_inference() -> None:
    result = api.build_active_clients(
        FixtureApi(), "02:00:00", FixtureApi.network_id, 0, 100
    )
    client = result["clients"][0]
    assert client["network"] == {
        "id": FixtureApi.network_id,
        "name": "Workstations",
        "vlan_id": 30,
        "match": "inferred_by_ip_subnet",
    }
    assert client["zone"] == {"id": FixtureApi.zone_id, "name": "Internal"}
    assert client["attachment"] == {
        "device_id": FixtureApi.device_id,
        "device_name": "Core Switch",
    }
    assert "must-not-leak" not in json.dumps(result)


@pytest.mark.parametrize("relation", ["clients", "firewall/zones"])
def test_active_clients_propagates_upstream_truncation_as_partial(relation) -> None:
    class TruncatedRelationApi(FixtureApi):
        def get_all(self, path: str) -> api.PageResult:
            result = super().get_all(path)
            if path.endswith(f"/{relation}"):
                return api.PageResult(result.items, 2050, True)
            return result

    result = api.build_active_clients(TruncatedRelationApi(), None, None, 0, 100)
    assert result["truncated"] is True
    assert result["partial"] is True


@pytest.mark.parametrize(("offset", "limit"), [(-1, 10), (0, 0), (0, 201)])
def test_active_clients_validates_local_pagination(offset: int, limit: int) -> None:
    with pytest.raises(api.UniFiApiError, match="UNIFI_INPUT_INVALID"):
        api.build_active_clients(FixtureApi(), None, None, offset, limit)


def test_firewall_policies_resolve_zone_and_matching_list() -> None:
    result = api.build_firewall_policies(
        FixtureApi(), True, FixtureApi.zone_id, FixtureApi.zone_id
    )
    policy = result["sites"][0]["policies"][0]
    assert policy["source"]["zone"]["name"] == "Internal"
    assert policy["traffic_matching_lists"] == [
        {
            "id": FixtureApi.list_id,
            "name": "Web",
            "type": "PORTS",
            "items": [{"type": "PORT_NUMBER", "value": 443}],
        }
    ]
    assert policy["action"] == {"type": "ALLOW", "allowReturnTraffic": True}
    assert "must-not-leak" not in json.dumps(result)


class MissingPolicyReferencesApi(FixtureApi):
    def get_all(self, path: str) -> api.PageResult:
        if path.endswith(("/firewall/zones", "/traffic-matching-lists")):
            return api.PageResult([], 0, False)
        return super().get_all(path)


def test_firewall_policy_marks_missing_references() -> None:
    result = api.build_firewall_policies(MissingPolicyReferencesApi(), None, None, None)
    policy = result["sites"][0]["policies"][0]
    assert policy["source"]["zone"] == {"id": FixtureApi.zone_id, "missing": True}
    assert policy["traffic_matching_lists"] == [
        {"id": FixtureApi.list_id, "missing": True}
    ]


class LargeTrafficListApi(FixtureApi):
    def get_all(self, path: str) -> api.PageResult:
        if path.endswith("/traffic-matching-lists"):
            return api.PageResult(
                [
                    {
                        "id": self.list_id,
                        "name": "Large ports",
                        "type": "PORTS",
                        "items": [
                            {
                                "type": "PORT_NUMBER",
                                "value": index + 1,
                                "secret": "must-not-leak",
                            }
                            for index in range(205)
                        ],
                    }
                ],
                1,
                False,
            )
        return super().get_all(path)


def test_firewall_matching_list_members_are_allowlisted_and_bounded() -> None:
    result = api.build_firewall_policies(LargeTrafficListApi(), None, None, None)
    matching_list = result["sites"][0]["policies"][0]["traffic_matching_lists"][0]
    assert len(matching_list["items"]) == 200
    assert matching_list["items"][0] == {"type": "PORT_NUMBER", "value": 1}
    assert matching_list["truncated"] is True
    assert result["partial"] is True
    assert result["truncated"] is True
    assert "must-not-leak" not in json.dumps(result)


def test_endpoint_trace_ranks_exact_and_adds_policy_reference() -> None:
    result = api.build_endpoint_trace(FixtureApi(), "192.0.2.25")
    assert result["matches"][0]["id"] == FixtureApi.client_id
    assert result["matches"][0]["policy_references"] == [
        {
            "site_id": FixtureApi.site_id,
            "id": FixtureApi.policy_id,
            "name": "Allow workstations",
            "index": 10,
        }
    ]


class ManyClientsApi(FixtureApi):
    def get_all(self, path: str) -> api.PageResult:
        if path.endswith("/clients"):
            clients = [
                {
                    "id": f"client-{index}",
                    "name": f"Endpoint {index}",
                    "macAddress": f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
                    "ipAddress": f"198.51.100.{index % 254 + 1}",
                    "uplinkDeviceId": self.device_id,
                }
                for index in range(201)
            ]
            clients[-1]["name"] = "Last endpoint"
            return api.PageResult(clients, len(clients), False)
        return super().get_all(path)


def test_endpoint_trace_searches_all_bounded_clients_not_only_first_page() -> None:
    result = api.build_endpoint_trace(ManyClientsApi(), "Last endpoint")
    assert result["matches"][0]["id"] == "client-200"


class SubstringPolicyReferenceApi(FixtureApi):
    def get(self, path: str, query: dict[str, int] | None = None) -> dict[str, Any]:
        result = super().get(path, query)
        if path.endswith(f"/networks/{self.network_id}"):
            result = dict(result)
            result["zoneId"] = "88888888-8888-8888-8888-888888888888"
        return result

    def get_all(self, path: str) -> api.PageResult:
        result = super().get_all(path)
        if path.endswith("/firewall/zones"):
            zones = json.loads(json.dumps(result.items))
            zones[0]["networkIds"] = []
            return api.PageResult(zones, result.total, result.truncated)
        if path.endswith("/firewall/policies"):
            policies = json.loads(json.dumps(result.items))
            policies[0]["description"] = "192.0.2.25"
            policies[0]["source"]["trafficFilter"]["networkFilter"]["networkId"] += (
                "-suffix"
            )
            return api.PageResult(policies, result.total, result.truncated)
        return result


def test_endpoint_trace_policy_reference_matching_requires_an_exact_value() -> None:
    result = api.build_endpoint_trace(SubstringPolicyReferenceApi(), "192.0.2.25")
    assert result["matches"][0]["policy_references"] == []


class TwoSiteApi(FixtureApi):
    second_site_id = "99999999-9999-9999-9999-999999999999"

    def get_all(self, path: str) -> api.PageResult:
        if path == "/v1/sites":
            return api.PageResult(
                [
                    {"id": self.site_id, "name": "First"},
                    {"id": self.second_site_id, "name": "Second"},
                ],
                2,
                False,
            )
        return super().get_all(path)


def test_endpoint_trace_never_crosses_site_boundaries_for_duplicate_addresses() -> None:
    result = api.build_endpoint_trace(TwoSiteApi(), "192.0.2.25")
    assert len(result["matches"]) == 2
    for match in result["matches"]:
        assert {reference["site_id"] for reference in match["policy_references"]} == {
            match["site"]["id"]
        }


class PartialApi(FixtureApi):
    def get_all(self, path: str) -> api.PageResult:
        if path.endswith("/firewall/zones"):
            raise api.UniFiApiError("UNIFI_API_UNSUPPORTED", "synthetic old controller")
        return super().get_all(path)


def test_optional_relation_is_reported_as_partial() -> None:
    result = api.build_config_map(PartialApi())
    assert result["partial"] is True
    assert "firewall_zones" in result["unavailable_relations"]


class TruncatedSitesApi(FixtureApi):
    def get_all(self, path: str) -> api.PageResult:
        page = super().get_all(path)
        if path == "/v1/sites":
            return api.PageResult(page.items, 2, True)
        return page


def test_inspection_tools_report_a_truncated_site_collection() -> None:
    fixture = TruncatedSitesApi()
    results = (
        api.build_config_map(fixture),
        api.build_active_clients(fixture, None, None, 0, 100),
        api.build_firewall_policies(fixture, None, None, None),
        api.build_endpoint_trace(fixture, "192.0.2.25"),
    )
    for result in results:
        assert result["partial"] is True
        assert result["truncated"] is True


@pytest.mark.parametrize("matching_list", [False, True])
def test_endpoint_trace_exposes_an_omitted_selector_member(matching_list) -> None:
    address = "192.0.2.25"
    members = ["198.51.100.9"] * 200 + [address]

    class TruncatedSelectorsApi(FixtureApi):
        def get_all(self, path: str) -> api.PageResult:
            page = super().get_all(path)
            if path.endswith("/firewall/policies"):
                page.items[0]["source"] = {
                    "trafficFilter": {
                        "ipAddressFilter": (
                            {"trafficMatchingListId": self.list_id}
                            if matching_list
                            else {"items": [{"value": member} for member in members]}
                        )
                    }
                }
                page.items[0]["destination"] = {}
            if matching_list and path.endswith("/traffic-matching-lists"):
                page.items[0]["items"] = [
                    {"type": "IP_ADDRESS", "value": member} for member in members
                ]
            return page

    fixture = TruncatedSelectorsApi()
    report = api.build_firewall_policies(fixture, None, None, None)
    policy = report["sites"][0]["policies"][0]
    truncated = policy["traffic_matching_lists"][0] if matching_list else policy
    assert truncated["truncated"] is True
    trace = api.build_endpoint_trace(fixture, address)
    assert trace["matches"][0]["policy_references"] == []
    assert trace["partial"] is True
    assert trace["truncated"] is True
