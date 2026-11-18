# UniFi Network MCP

## Purpose

Provide a portable, read-only UniFi Network inspection surface and optional operator-approved firewall management for configured deployments.

## ADDED Requirements

### Requirement: Inspection is the default

The installed MCP SHALL expose normalized site, client, firewall policy, and endpoint inspection. It SHALL preserve its versioned result envelope and cap responses.

#### Scenario: Default tool discovery

- **WHEN** the package starts with only controller inspection configuration
- **THEN** the MCP SHALL list the four inspection tools and issue fixed HTTPS GET requests when called

### Requirement: Approved operations are typed and scoped

When authentication and approval support are configured, the MCP SHALL expose typed create, update, delete, and status tools for user-defined firewall policies. The broker SHALL bind approval to the proposed rule and ordering.

#### Scenario: Protected target or missing broker

- **WHEN** an authorized request targets a protected policy or the broker cannot receive it
- **THEN** the service SHALL report the refusal and perform no write

### Requirement: The executor observes the result

The executor SHALL verify the broker grant, target policy, and current state before applying a change. It SHALL read back the controller and report the observed result or uncertainty.

#### Scenario: Lost write response

- **WHEN** a controller write might have been applied before the response was lost
- **THEN** the executor SHALL reconcile by read-back without replaying the write
