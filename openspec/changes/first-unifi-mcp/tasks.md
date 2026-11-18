## 1. Portable inspection

- [x] 1.1 Package the controller client and four read tools. Verify pagination, normalized results, filters, TLS refusal, and discovery with synthetic fixtures. [Issue #2](https://github.com/mikomiel/unifi-agent-mcp/issues/2)

## 2. Firewall rule management

- [x] 2.1 Add typed request validation, preview, caller scoping, and status. Test default discovery and refusals. [Issue #3](https://github.com/mikomiel/unifi-agent-mcp/issues/3)
- [x] 2.2 Add the trusted executor and verify create, update, delete, stale state, replay, and ambiguous outcomes against a fake controller.
- [x] 2.3 Exercise the product with the broker's UniFi provider. Verify passkey approval, exact payload binding, and the recorded outcome. [Broker issue #53](https://github.com/mikomiel/privilege-broker/issues/53)

## 3. First artifact

- [x] 3.1 Build and install the wheel in a clean environment and test both MCP modes.
- [ ] 3.2 Obtain authorization for the exact release. Publish the wheel and digest through GitHub. [Issue #4](https://github.com/mikomiel/unifi-agent-mcp/issues/4)
