# UniFi Agent MCP

UniFi Agent MCP lets agents inspect UniFi Network sites and firewall policies through the Model Context Protocol.

The service starts in read-only mode. An opt-in approval mode lets authorized callers request creation, editing, and deletion of user-defined firewall rules. An operator approves the exact proposed change before a dedicated executor applies it and reads back the result. [Privilege Broker](https://github.com/mikomiel/privilege-broker)

The integration targets the UniFi Network Integration API. Find the API reference for your installed version under **UniFi Network → Integrations**. [Ubiquiti's API guide](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)

## Run from source

Install the project with `uv sync --frozen`. Configure `UNIFI_NETWORK_URL` with
the controller's HTTPS Integration API base, such as
`https://controller.example.test/proxy/network/integration`. Provide the
inspection key through `UNIFI_NETWORK_API_KEY` in the MCP launch environment.
TLS uses the system trust store by default. Set `UNIFI_NETWORK_PINNED_CERT_FILE`
to the verified controller leaf certificate for a self-signed deployment.
Set `UNIFI_NETWORK_TIMEOUT_SECONDS` to a value from 1 to 60 seconds per
controller call. The default is 10 seconds.

Use `uv run unifi-agent-mcp` as the stdio MCP command. The default mode exposes
configuration, active clients, firewall policy inspection, and endpoint tracing.
[Firewall management for the first release](https://github.com/mikomiel/unifi-agent-mcp/issues/3)

## Enable firewall requests

Set `UNIFI_FIREWALL_SCOPE_FILE` to a JSON file containing a non-empty
`targets` array. Each target names `site_id`, `source_zone`, and
`destination_zone` UUIDs. The optional `protected_policy_ids` array
names rules to protect. Admit only intended data zone pairs. Keep gateway
management pairs outside the configured targets.

Provide distinct, high-entropy `UNIFI_MCP_READ_TOKEN` and
`UNIFI_MCP_REQUEST_TOKEN` values. The enabled MCP binds loopback on
`UNIFI_MCP_PORT` (default 8080) and requires a TLS frontend for remote
clients. The request token can submit and inspect operator-approved
create, edit, and delete requests on the shared MCP. The read token
grants inspection.

Configure `UNIFI_BROKER_URL`, `UNIFI_BROKER_CLIENT_CERT_FILE`,
`UNIFI_BROKER_CLIENT_KEY_FILE`, and the optional `UNIFI_BROKER_CA_FILE`
for the caller's broker mTLS identity. Requests return a broker approval
link and request ID. The status tool reports approval and verified
execution separately. Use a broker that implements the UniFi approval
family.

The first rule profile creates disabled IPv4 allow or block rules in
the requested zone pair. Edits support the name, description, logging,
and enabled state while preserving existing match criteria. Updates
and deletes require an admitted user-defined policy.

## Run the trusted executor

Run `unifi-firewall-executor` with its own broker mTLS identity and
controller credentials. Set `UNIFI_BROKER_EXECUTOR_IDENTITY` to the
registered broker identity and `UNIFI_BROKER_SIGNING_PUBLIC_KEY_FILE`
to the pinned OpenSSH Ed25519 public key. Give only this process
`UNIFI_NETWORK_WRITE_KEY`. Supply the same controller URL, trust
configuration, and firewall scope. Each invocation drains a bounded
approved queue and records read-back or uncertainty for each claim.

Use [GitHub Issues](https://github.com/mikomiel/unifi-agent-mcp/issues) for defects and feature requests. See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

Licensed under [Apache-2.0](LICENSE).
