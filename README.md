# UniFi Agent MCP

UniFi Agent MCP will let agents inspect UniFi Network sites and firewall policies through the Model Context Protocol.

The planned service starts in read-only mode. An opt-in approval mode will let authorized callers request creation, editing, and deletion of user-defined firewall rules. An operator approves the exact proposed change before a dedicated executor applies it and reads back the result. [Privilege Broker](https://github.com/mikomiel/privilege-broker)

The integration targets the UniFi Network Integration API. Find the API reference for your installed version under **UniFi Network → Integrations**. [Ubiquiti's API guide](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)

This repository contains the project scaffold. Installation instructions will accompany the first release.

Use [GitHub Issues](https://github.com/mikomiel/unifi-agent-mcp/issues) for defects and feature requests. See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

Licensed under [Apache-2.0](LICENSE).
