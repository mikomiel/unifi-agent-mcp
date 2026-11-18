## Why

Operators need a portable UniFi Network MCP for inspection and a passkey-approved way to manage user-defined rules. The first installable release includes both modes.

## What Changes

- Expose read-only site, client, firewall, and endpoint inspection.
- Offer typed create, update, delete, and status tools on the same MCP when authenticated approval mode is configured.
- Provide an executor that applies one broker-approved change and verifies the result.

## Capabilities

### New Capabilities

- `unifi-network-mcp`: normalized inspection and opt-in, operator-approved firewall management.

### Modified Capabilities

None.

## Impact

The product introduces an installable Python package and an optional authenticated broker connection. Deployers configure controller trust and credentials. The broker operation contract is tracked in [privilege-broker #53](https://github.com/mikomiel/privilege-broker/issues/53).
