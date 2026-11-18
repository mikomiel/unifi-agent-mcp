"""Bounded transport and inspection adapter for the local UniFi Network Integration API."""

from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

API_SCHEMA = "unifi-read.v1"
PAGE_LIMIT = 200
MAX_SELECTOR_ITEMS = 200
MAX_ITEMS_PER_FAMILY = 2_000
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10


class UniFiApiError(RuntimeError):
    """A stable client-visible failure at the controller API boundary."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the authenticated request on the one configured origin."""

    def redirect_request(
        self,
        _request: urllib.request.Request,
        _file_pointer: Any,
        _code: int,
        _message: str,
        _headers: Any,
        _new_url: str,
    ) -> None:
        raise UniFiApiError("UNIFI_UPSTREAM_UNAVAILABLE", "controller redirect refused")


@dataclass(frozen=True)
class UniFiApiConfig:
    base_url: str
    api_key: str
    certificate_pem: str
    timeout_seconds: int
    max_response_bytes: int


@dataclass(frozen=True)
class PageResult:
    items: list[dict[str, Any]]
    total: int
    truncated: bool


class UniFiNetworkApi:
    """Authenticated Integration API client. Inspection calls use GET."""

    def __init__(self, config: UniFiApiConfig, opener: Any | None = None) -> None:
        self._config = config
        if opener is None:
            context = ssl.create_default_context()
            if config.certificate_pem:
                # An explicit leaf pin also supports a controller without an IP SAN.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if config.certificate_pem.count("-----BEGIN CERTIFICATE-----") == 1:
                    try:
                        context.load_verify_locations(cadata=config.certificate_pem)
                    except ssl.SSLError:
                        raise UniFiApiError(
                            "UNIFI_TLS_FAILED", "controller certificate pin is invalid"
                        ) from None
                else:
                    raise UniFiApiError(
                        "UNIFI_TLS_FAILED", "one controller certificate pin is required"
                    )
                context.check_hostname = False
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context),
                _RejectRedirect(),
            )
        self._opener = opener

    def get(
        self, path: str, query: dict[str, int | str] | None = None
    ) -> dict[str, Any]:
        return self._request("GET", path, query=query)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, int | str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/v1/") or ".." in path:
            raise UniFiApiError(
                "UNIFI_API_UNSUPPORTED", "refused non-contract endpoint"
            )
        encoded_query = urllib.parse.urlencode(query or {})
        url = f"{self._config.base_url}{path}"
        if encoded_query:
            url = f"{url}?{encoded_query}"
        headers = {"Accept": "application/json", "X-API-Key": self._config.api_key}
        data = None
        if body is not None:
            data = json.dumps(body, allow_nan=False).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, headers=headers, method=method, data=data)
        try:
            with self._opener.open(
                request, timeout=self._config.timeout_seconds
            ) as response:
                payload = response.read(self._config.max_response_bytes + 1)
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                raise UniFiApiError(
                    "UNIFI_AUTH_FAILED", f"controller returned HTTP {error.code}"
                ) from error
            if error.code == 404:
                raise UniFiApiError(
                    "UNIFI_API_UNSUPPORTED", "controller endpoint is unavailable"
                ) from error
            if error.code == 429:
                raise UniFiApiError(
                    "UNIFI_RATE_LIMITED", "controller rate limit reached"
                ) from error
            raise UniFiApiError(
                "UNIFI_UPSTREAM_UNAVAILABLE", f"controller returned HTTP {error.code}"
            ) from error
        except (ssl.SSLError, ssl.CertificateError) as error:
            raise UniFiApiError(
                "UNIFI_TLS_FAILED", "controller certificate verification failed"
            ) from error
        except (OSError, http.client.HTTPException) as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
                raise UniFiApiError(
                    "UNIFI_TLS_FAILED", "controller certificate verification failed"
                ) from error
            raise UniFiApiError(
                "UNIFI_UPSTREAM_UNAVAILABLE", "controller request failed"
            ) from error
        if method == "DELETE" and not payload:
            return {}
        if len(payload) > self._config.max_response_bytes:
            raise UniFiApiError(
                "UNIFI_RESPONSE_INVALID", "controller response exceeded the 1 MiB bound"
            )
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise UniFiApiError(
                "UNIFI_RESPONSE_INVALID", "controller response was not valid JSON"
            ) from error
        if not isinstance(decoded, dict):
            raise UniFiApiError(
                "UNIFI_RESPONSE_INVALID", "controller response was not an object"
            )
        return decoded

    def get_all(self, path: str) -> PageResult:
        items: list[dict[str, Any]] = []
        offset = 0
        total = 0
        while offset < MAX_ITEMS_PER_FAMILY:
            payload = self.get(path, {"offset": offset, "limit": PAGE_LIMIT})
            page = payload.get("data")
            if not isinstance(page, list):
                raise UniFiApiError(
                    "UNIFI_RESPONSE_INVALID", f"{path} data was not a list"
                )
            valid_page = [item for item in page if isinstance(item, dict)]
            items.extend(valid_page)
            reported_total = payload.get("totalCount")
            total = (
                reported_total
                if isinstance(reported_total, int) and reported_total >= 0
                else len(items)
            )
            if not page or len(items) >= total:
                break
            offset += len(page)
        bounded_items = items[:MAX_ITEMS_PER_FAMILY]
        truncated = total > len(bounded_items) or len(items) > len(bounded_items)
        return PageResult(items=bounded_items, total=total, truncated=truncated)


def api_config(
    base_url: str,
    api_key: str,
    certificate_pem: str = "",
    *,
    timeout_seconds: int | str = REQUEST_TIMEOUT_SECONDS,
) -> UniFiApiConfig:
    try:
        origin = urllib.parse.urlsplit(base_url.strip())
        port = origin.port
    except ValueError:
        raise UniFiApiError(
            "UNIFI_API_NOT_CONFIGURED", "invalid controller integration URL"
        ) from None
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username is not None
        or origin.query
        or origin.fragment
        or port == 0
    ):
        raise UniFiApiError(
            "UNIFI_API_NOT_CONFIGURED",
            "an HTTPS controller integration URL is required",
        )
    if not api_key.strip():
        raise UniFiApiError(
            "UNIFI_API_NOT_CONFIGURED", "controller inspection key is required"
        )
    try:
        timeout = int(timeout_seconds)
    except ValueError:
        timeout = 0
    if not 1 <= timeout <= 60:
        raise UniFiApiError(
            "UNIFI_API_NOT_CONFIGURED", "controller timeout must be 1 to 60 seconds"
        )
    return UniFiApiConfig(
        base_url=origin.geturl().rstrip("/"),
        api_key=api_key,
        certificate_pem=certificate_pem,
        timeout_seconds=timeout,
        max_response_bytes=MAX_RESPONSE_BYTES,
    )


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _metadata(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    configurable = (
        raw.get("configurable") if "configurable" in raw else raw.get("isConfigurable")
    )
    return {
        key: value
        for key, value in {
            "origin": _text(raw.get("origin")),
            "configurable": _boolean(configurable),
        }.items()
        if value is not None
    }


def normalize_site(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "internal_reference": _text(raw.get("internalReference")),
    }
    return {key: value for key, value in result.items() if value is not None}


def normalize_network(raw: dict[str, Any]) -> dict[str, Any]:
    ipv4 = raw.get("ipv4Configuration")
    subnet = None
    additional_subnets: list[str] = []
    if isinstance(ipv4, dict):
        host = _text(ipv4.get("hostIpAddress"))
        prefix = _integer(ipv4.get("prefixLength"))
        if host and prefix is not None:
            try:
                subnet = str(ipaddress.ip_network(f"{host}/{prefix}", strict=False))
            except ValueError:
                subnet = None
        additional_subnets = _strings(ipv4.get("additionalHostIpSubnets"))
    result = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "vlan_id": _integer(raw.get("vlanId")),
        "enabled": _boolean(raw.get("enabled")),
        "default": _boolean(raw.get("default")),
        "management": _text(raw.get("management")),
        "zone_id": _text(raw.get("zoneId")),
        "managing_device_id": _text(raw.get("deviceId")),
        "ipv4_subnet": subnet,
        "additional_ipv4_subnets": additional_subnets,
        "metadata": _metadata(raw.get("metadata")),
    }
    return {key: value for key, value in result.items() if value not in (None, [], {})}


def normalize_zone(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "network_ids": _strings(raw.get("networkIds")),
        "metadata": _metadata(raw.get("metadata")),
    }


def normalize_device(raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "model": _text(raw.get("model")),
        "mac_address": _text(raw.get("macAddress")),
        "ip_address": _text(raw.get("ipAddress")),
        "state": _text(raw.get("state")),
        "supported": _boolean(raw.get("supported")),
        "firmware_version": _text(raw.get("firmwareVersion")),
    }
    features = raw.get("features")
    if isinstance(features, list):
        result["features"] = _strings(features)
    elif isinstance(features, dict):
        result["features"] = sorted(
            key for key, value in features.items() if value is True
        )
    uplink = raw.get("uplink")
    if isinstance(uplink, dict) and _text(uplink.get("deviceId")):
        result["uplink_device_id"] = uplink["deviceId"]
    interfaces = raw.get("interfaces")
    if isinstance(interfaces, dict) and isinstance(interfaces.get("ports"), list):
        ports = []
        for port in interfaces["ports"]:
            if not isinstance(port, dict):
                continue
            normalized = {
                "index": _integer(port.get("idx")),
                "state": _text(port.get("state")),
                "connector": _text(port.get("connector")),
                "speed_mbps": _integer(port.get("speedMbps")),
                "max_speed_mbps": _integer(port.get("maxSpeedMbps")),
            }
            ports.append(
                {key: value for key, value in normalized.items() if value is not None}
            )
        result["ports"] = ports
    return {key: value for key, value in result.items() if value not in (None, [])}


def normalize_client(raw: dict[str, Any]) -> dict[str, Any]:
    access = raw.get("access") if isinstance(raw.get("access"), dict) else {}
    result = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "type": _text(raw.get("type")),
        "mac_address": _text(raw.get("macAddress")),
        "ip_address": _text(raw.get("ipAddress")),
        "connected_at": _text(raw.get("connectedAt")),
        "uplink_device_id": _text(raw.get("uplinkDeviceId")),
        "access_type": _text(access.get("type")),
        "authorized": _boolean(access.get("authorized")),
    }
    return {key: value for key, value in result.items() if value is not None}


_FILTER_KEYS = frozenset(
    {
        "type",
        "matchOpposite",
        "trafficMatchingListId",
        "networkId",
        "networkIds",
        "items",
        "domains",
        "protocol",
        "preset",
        "ipVersion",
        "allowReturnTraffic",
        "ipAddressFilter",
        "macAddressFilter",
        "networkFilter",
        "portFilter",
        "domainFilter",
        "applicationFilter",
        "applicationCategoryFilter",
        "regionFilter",
        "siteToSiteVpnTunnelFilter",
        "vpnServerFilter",
        "protocolFilter",
        "start",
        "stop",
        "value",
        "mode",
        "startTime",
        "stopTime",
        "days",
    }
)


def _safe_filter(value: Any) -> tuple[Any, bool]:
    if isinstance(value, dict):
        entries = {
            key: _safe_filter(item)
            for key, item in value.items()
            if key in _FILTER_KEYS
        }
        return (
            {key: item for key, (item, _) in entries.items()},
            any(truncated for _, truncated in entries.values()),
        )
    if isinstance(value, list):
        entries = [_safe_filter(item) for item in value[:MAX_SELECTOR_ITEMS]]
        return (
            [item for item, _ in entries],
            len(value) > MAX_SELECTOR_ITEMS
            or any(truncated for _, truncated in entries),
        )
    if isinstance(value, (str, int, bool)) or value is None:
        return value, False
    return None, False


def normalize_traffic_list(raw: dict[str, Any]) -> dict[str, Any]:
    raw_items = raw.get("items")
    members = raw_items if isinstance(raw_items, list) else []
    items = [_normalize_matching_item(item) for item in members[:MAX_SELECTOR_ITEMS]]
    result = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "type": _text(raw.get("type")),
        "items": [item for item in items if item],
    }
    if len(members) > MAX_SELECTOR_ITEMS:
        result["truncated"] = True
    return {key: value for key, value in result.items() if value not in (None, [])}


def _normalize_matching_item(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    result = {
        "type": _text(raw.get("type")),
        "value": _matching_scalar(raw.get("value")),
        "start": _matching_scalar(raw.get("start")),
        "stop": _matching_scalar(raw.get("stop")),
    }
    return {key: value for key, value in result.items() if value is not None}


def _matching_scalar(value: Any) -> str | int | None:
    if isinstance(value, str):
        return value
    return _integer(value)


def normalize_policy(raw: dict[str, Any]) -> dict[str, Any]:
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    destination = (
        raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
    )
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    protocol = (
        raw.get("ipProtocolScope")
        if isinstance(raw.get("ipProtocolScope"), dict)
        else {}
    )
    filters = {
        name: _safe_filter(value)
        for name, value in (
            ("action", action),
            ("source", source.get("trafficFilter")),
            ("destination", destination.get("trafficFilter")),
            ("ip_protocol_scope", protocol),
            ("schedule", raw.get("schedule")),
        )
    }
    result = {
        "id": _text(raw.get("id")),
        "name": _text(raw.get("name")),
        "description": _text(raw.get("description")),
        "enabled": _boolean(raw.get("enabled")),
        "index": _integer(raw.get("index")),
        "action": filters["action"][0],
        "source": {
            "zone_id": _text(source.get("zoneId")),
            "traffic_filter": filters["source"][0],
        },
        "destination": {
            "zone_id": _text(destination.get("zoneId")),
            "traffic_filter": filters["destination"][0],
        },
        "ip_protocol_scope": filters["ip_protocol_scope"][0],
        "connection_states": _strings(raw.get("connectionStateFilter")),
        "ipsec_filter": _text(raw.get("ipsecFilter")),
        "logging_enabled": _boolean(raw.get("loggingEnabled")),
        "schedule": filters["schedule"][0],
        "metadata": _metadata(raw.get("metadata")),
    }
    if any(truncated for _, truncated in filters.values()):
        result["truncated"] = True
    for side in (result["source"], result["destination"]):
        for key in list(side):
            if side[key] in (None, {}):
                del side[key]
    return {key: value for key, value in result.items() if value not in (None, [], {})}


def _path(site_id: str, suffix: str) -> str:
    return f"/v1/sites/{urllib.parse.quote(site_id, safe='')}/{suffix}"


def _network_details(
    api: UniFiNetworkApi, site_id: str, networks: PageResult
) -> tuple[list[dict[str, Any]], bool]:
    normalized: list[dict[str, Any]] = []
    partial = networks.truncated
    for overview in networks.items:
        network_id = _text(overview.get("id"))
        raw = overview
        if network_id:
            try:
                raw = api.get(
                    _path(
                        site_id, f"networks/{urllib.parse.quote(network_id, safe='')}"
                    )
                )
            except UniFiApiError as error:
                if error.code != "UNIFI_API_UNSUPPORTED":
                    raise
                partial = True
        normalized.append(normalize_network(raw))
    return normalized, partial


def _device_details(
    api: UniFiNetworkApi, site_id: str, devices: PageResult
) -> tuple[list[dict[str, Any]], bool]:
    normalized: list[dict[str, Any]] = []
    partial = devices.truncated
    for overview in devices.items:
        device_id = _text(overview.get("id"))
        raw = overview
        if device_id:
            try:
                raw = api.get(
                    _path(site_id, f"devices/{urllib.parse.quote(device_id, safe='')}")
                )
            except UniFiApiError as error:
                if error.code != "UNIFI_API_UNSUPPORTED":
                    raise
                partial = True
        normalized.append(normalize_device(raw))
    return normalized, partial


def _site_pages(api: UniFiNetworkApi) -> tuple[dict[str, Any], PageResult]:
    info = api.get("/v1/info")
    sites = api.get_all("/v1/sites")
    if not sites.items:
        raise UniFiApiError("UNIFI_RESPONSE_INVALID", "controller returned no sites")
    return info, sites


def _envelope(
    info: dict[str, Any], partial: bool, unavailable: set[str], truncated: bool
) -> dict[str, Any]:
    return {
        "schema": API_SCHEMA,
        "observed_at": datetime.now(UTC).isoformat(),
        "controller": {"application_version": _text(info.get("applicationVersion"))},
        "partial": partial,
        "unavailable_relations": sorted(unavailable),
        "truncated": truncated,
    }


def _optional_page(
    api: UniFiNetworkApi, path: str, relation: str, unavailable: set[str]
) -> PageResult:
    try:
        return api.get_all(path)
    except UniFiApiError as error:
        if error.code != "UNIFI_API_UNSUPPORTED":
            raise
        unavailable.add(relation)
        return PageResult(items=[], total=0, truncated=False)


def build_config_map(api: UniFiNetworkApi) -> dict[str, Any]:
    info, sites_page = _site_pages(api)
    unavailable: set[str] = set()
    sites = []
    truncated = sites_page.truncated
    for raw_site in sites_page.items:
        site = normalize_site(raw_site)
        site_id = site.get("id")
        if not isinstance(site_id, str):
            unavailable.add("site_without_id")
            continue
        networks_page = _optional_page(
            api, _path(site_id, "networks"), "networks", unavailable
        )
        zones_page = _optional_page(
            api, _path(site_id, "firewall/zones"), "firewall_zones", unavailable
        )
        devices_page = _optional_page(
            api, _path(site_id, "devices"), "devices", unavailable
        )
        networks, network_partial = _network_details(api, site_id, networks_page)
        devices, device_partial = _device_details(api, site_id, devices_page)
        zones = [normalize_zone(item) for item in zones_page.items]
        site.update(
            {
                "networks": networks,
                "zones": zones,
                "devices": devices,
                "totals": {
                    "networks": networks_page.total,
                    "zones": zones_page.total,
                    "devices": devices_page.total,
                },
            }
        )
        sites.append(site)
        truncated = (
            truncated
            or networks_page.truncated
            or zones_page.truncated
            or devices_page.truncated
        )
        if network_partial:
            unavailable.add("network_details")
        if device_partial:
            unavailable.add("device_details")
    result = _envelope(info, bool(unavailable) or truncated, unavailable, truncated)
    result["sites"] = sites
    result["totals"] = {"sites": len(sites)}
    return result


def _attach_network(
    client: dict[str, Any],
    networks: list[dict[str, Any]],
    zones: dict[str, dict[str, Any]],
) -> None:
    address = client.get("ip_address")
    if not isinstance(address, str):
        return
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return
    for network in networks:
        candidates = [
            network.get("ipv4_subnet"),
            *network.get("additional_ipv4_subnets", []),
        ]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            try:
                matched = ip in ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            if matched:
                client["network"] = {
                    "id": network.get("id"),
                    "name": network.get("name"),
                    "vlan_id": network.get("vlan_id"),
                    "match": "inferred_by_ip_subnet",
                }
                zone_id = network.get("zone_id")
                if isinstance(zone_id, str):
                    zone = zones.get(zone_id, {})
                    client["zone"] = {"id": zone_id, "name": zone.get("name")}
                return


def _client_sites(
    api: UniFiNetworkApi,
) -> tuple[dict[str, Any], list[dict[str, Any]], set[str], bool]:
    info, sites_page = _site_pages(api)
    unavailable: set[str] = set()
    sites = []
    truncated = sites_page.truncated
    for raw_site in sites_page.items:
        site = normalize_site(raw_site)
        site_id = site.get("id")
        if not isinstance(site_id, str):
            continue
        networks_page = _optional_page(
            api, _path(site_id, "networks"), "networks", unavailable
        )
        zones_page = _optional_page(
            api, _path(site_id, "firewall/zones"), "firewall_zones", unavailable
        )
        devices_page = _optional_page(
            api, _path(site_id, "devices"), "devices", unavailable
        )
        clients_page = api.get_all(_path(site_id, "clients"))
        networks, network_partial = _network_details(api, site_id, networks_page)
        devices = {
            item.get("id"): item
            for item in (normalize_device(raw) for raw in devices_page.items)
        }
        zones = {
            item.get("id"): item
            for item in (normalize_zone(raw) for raw in zones_page.items)
        }
        clients = []
        for raw in clients_page.items:
            client = normalize_client(raw)
            uplink_id = client.get("uplink_device_id")
            if isinstance(uplink_id, str):
                device = devices.get(uplink_id, {})
                client["attachment"] = {
                    "device_id": uplink_id,
                    "device_name": device.get("name"),
                }
            _attach_network(client, networks, zones)
            clients.append(client)
        site["clients"] = clients
        site["total_clients"] = clients_page.total
        sites.append(site)
        truncated = (
            truncated
            or clients_page.truncated
            or networks_page.truncated
            or zones_page.truncated
            or devices_page.truncated
        )
        if network_partial:
            unavailable.add("network_details")
    return info, sites, unavailable, truncated


def build_active_clients(
    api: UniFiNetworkApi,
    query: str | None,
    network_id: str | None,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    if offset < 0:
        raise UniFiApiError("UNIFI_INPUT_INVALID", "offset must be at least 0")
    if limit < 1 or limit > PAGE_LIMIT:
        raise UniFiApiError("UNIFI_INPUT_INVALID", "limit must be between 1 and 200")
    info, sites, unavailable, truncated = _client_sites(api)
    needle = query.casefold().strip() if query else None
    flattened = _flatten_clients(sites)
    matching = []
    for client in flattened:
        if network_id and client.get("network", {}).get("id") != network_id:
            continue
        haystack = [
            client.get(key) for key in ("id", "name", "mac_address", "ip_address")
        ]
        if needle and not any(
            needle in value.casefold() for value in haystack if isinstance(value, str)
        ):
            continue
        matching.append(client)
    selected = matching[offset : offset + limit]
    result = _envelope(
        info,
        bool(unavailable) or truncated,
        unavailable,
        truncated or len(matching) > offset + limit,
    )
    result["clients"] = selected
    result["totals"] = {"matching": len(matching), "returned": len(selected)}
    result["pagination"] = {"offset": offset, "limit": limit}
    return result


def _flatten_clients(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for site in sites:
        site_identity = {
            key: site.get(key) for key in ("id", "name", "internal_reference")
        }
        for client in site.get("clients", []):
            client["site"] = site_identity
            flattened.append(client)
    return flattened


def _resolve_policy(
    policy: dict[str, Any],
    zones: dict[str, dict[str, Any]],
    lists: dict[str, dict[str, Any]],
) -> None:
    for side_name in ("source", "destination"):
        side = policy.get(side_name)
        if not isinstance(side, dict):
            continue
        zone_id = side.get("zone_id")
        if isinstance(zone_id, str):
            side["zone"] = zones.get(zone_id, {"id": zone_id, "missing": True})
    references: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "trafficMatchingListId" and isinstance(child, str):
                    references.append(lists.get(child, {"id": child, "missing": True}))
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(policy)
    if references:
        policy["traffic_matching_lists"] = references


def build_firewall_policies(
    api: UniFiNetworkApi,
    enabled: bool | None,
    source_zone_id: str | None,
    destination_zone_id: str | None,
) -> dict[str, Any]:
    info, sites_page = _site_pages(api)
    unavailable: set[str] = set()
    sites = []
    truncated = sites_page.truncated
    for raw_site in sites_page.items:
        site = normalize_site(raw_site)
        site_id = site.get("id")
        if not isinstance(site_id, str):
            continue
        zones_page = _optional_page(
            api, _path(site_id, "firewall/zones"), "firewall_zones", unavailable
        )
        policies_page = api.get_all(_path(site_id, "firewall/policies"))
        lists_page = _optional_page(
            api,
            _path(site_id, "traffic-matching-lists"),
            "traffic_matching_lists",
            unavailable,
        )
        zones = {
            item.get("id"): item
            for item in (normalize_zone(raw) for raw in zones_page.items)
        }
        lists = {
            item.get("id"): item
            for item in (normalize_traffic_list(raw) for raw in lists_page.items)
        }
        policies = []
        for raw in policies_page.items:
            policy = normalize_policy(raw)
            if enabled is not None and policy.get("enabled") is not enabled:
                continue
            if (
                source_zone_id
                and policy.get("source", {}).get("zone_id") != source_zone_id
            ):
                continue
            if (
                destination_zone_id
                and policy.get("destination", {}).get("zone_id") != destination_zone_id
            ):
                continue
            _resolve_policy(policy, zones, lists)
            policies.append(policy)
        policies.sort(key=lambda item: (item.get("index", 2**31), item.get("name", "")))
        site["zones"] = list(zones.values())
        site["traffic_matching_lists"] = list(lists.values())
        site["policies"] = policies
        site["totals"] = {
            "policies": policies_page.total,
            "matching_policies": len(policies),
        }
        sites.append(site)
        truncated = (
            truncated
            or policies_page.truncated
            or zones_page.truncated
            or lists_page.truncated
            or any(policy.get("truncated") for policy in policies)
            or any(matching_list.get("truncated") for matching_list in lists.values())
        )
    result = _envelope(info, bool(unavailable) or truncated, unavailable, truncated)
    result["sites"] = sites
    result["totals"] = {
        "sites": len(sites),
        "policies": sum(len(site["policies"]) for site in sites),
    }
    return result


def build_endpoint_trace(api: UniFiNetworkApi, identifier: str) -> dict[str, Any]:
    needle = identifier.casefold().strip()
    if not needle:
        raise UniFiApiError("UNIFI_INPUT_INVALID", "identifier must not be empty")
    info, sites, client_unavailable, client_truncated = _client_sites(api)
    clients = _flatten_clients(sites)
    policies_result = build_firewall_policies(api, None, None, None)
    candidates = []
    for client in clients:
        exact_fields = [client.get(key) for key in ("id", "mac_address", "ip_address")]
        name = client.get("name")
        if any(
            isinstance(value, str) and value.casefold() == needle
            for value in exact_fields
        ):
            rank = 0
        elif isinstance(name, str) and name.casefold() == needle:
            rank = 1
        elif any(
            isinstance(value, str) and needle in value.casefold()
            for value in [*exact_fields, name]
        ):
            rank = 2
        else:
            continue
        candidates.append((rank, str(name or ""), client))
    candidates.sort(key=lambda item: (item[0], item[1].casefold()))
    matches = [item[2] for item in candidates[:20]]
    for client in matches:
        client["policy_references"] = _policies_referencing_client(
            client, policies_result
        )
    unavailable = client_unavailable | set(policies_result["unavailable_relations"])
    upstream_truncated = client_truncated or policies_result["truncated"]
    result = {
        "schema": API_SCHEMA,
        "observed_at": datetime.now(UTC).isoformat(),
        "controller": {"application_version": _text(info.get("applicationVersion"))},
        "partial": bool(unavailable)
        or upstream_truncated
        or policies_result["partial"],
        "unavailable_relations": sorted(unavailable),
        "truncated": len(candidates) > 20 or upstream_truncated,
        "identifier": identifier,
        "matches": matches,
        "totals": {"matching": len(candidates), "returned": len(matches)},
    }
    return result


def _policies_referencing_client(
    client: dict[str, Any], policies_result: dict[str, Any]
) -> list[dict[str, Any]]:
    values = {
        str(client.get(key, "")).casefold()
        for key in ("mac_address", "ip_address")
        if client.get(key)
    }
    network_id = client.get("network", {}).get("id")
    if network_id:
        values.add(str(network_id).casefold())
    client_site_id = client.get("site", {}).get("id")
    client_zone_id = client.get("zone", {}).get("id")
    references = []
    for site in policies_result.get("sites", []):
        if site.get("id") != client_site_id:
            continue
        for policy in site.get("policies", []):
            sides = [policy.get(name, {}) for name in ("source", "destination")]
            zone_match = bool(client_zone_id) and any(
                side.get("zone_id") == client_zone_id for side in sides
            )
            selector_match = any(
                _selector_matches(side.get("traffic_filter"), values) for side in sides
            )
            list_match = any(
                _selector_matches(matching_list.get("items"), values)
                for matching_list in policy.get("traffic_matching_lists", [])
            )
            if zone_match or selector_match or list_match:
                references.append(
                    {
                        "site_id": site.get("id"),
                        "id": policy.get("id"),
                        "name": policy.get("name"),
                        "index": policy.get("index"),
                    }
                )
    return references


def _selector_matches(value: Any, targets: set[str]) -> bool:
    if isinstance(value, dict):
        return any(_selector_matches(child, targets) for child in value.values())
    if isinstance(value, list):
        return any(_selector_matches(child, targets) for child in value)
    return isinstance(value, str) and value.casefold() in targets
