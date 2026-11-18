## Context

The UniFi Network Integration API provides bounded controller inspection and distinct endpoints for firewall policy creation, replacement, and deletion. [Ubiquiti Network API](https://developer.ui.com/network/v11.0.97/openapi.json)

## Decisions

- Keep the existing versioned inspection envelopes. Configure one HTTPS origin, trust material, and timeout. Encode controller-derived identifiers and refuse redirects.
- Enable the firewall tools only with authenticated caller authorization and explicit broker and site policy configuration. The MCP uses a read client to build a typed preview, and the executor alone holds the write credential.
- Bind the proposal to the exact before and after state and the zone-pair order. Close the operation set to create, update, and delete. Start with supported user-defined rules in configured zone pairs. New rules start disabled so their inserted order can be verified.
- The broker owns an expiring, one-use grant. The executor verifies the binding and current controller state, then performs a fixed Integration API call. A lost response is reconciled by reading state and recording the result or uncertainty.

## Trade-offs

The published PUT contract is unconditional. A concurrent UI edit can land after the last read. Refuse previously observed drift and record a read-back mismatch as an uncertain result. Verify the exact supported API version and ordering on a controlled canary before live use.
