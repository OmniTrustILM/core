# OmniTrustILM repository map

Hand-curated catalog of repositories in the OmniTrustILM GitHub organization, grouped primarily by the provider-interface axis (the platform's plugin architecture), with platform / frontend / tooling / infrastructure / docs as separate top-level groups.

**A map of purpose, not of current state.** Each entry ends with its primary language and its visibility: `public`, `private` or `internal`. Copies published outside this repository omit non-public repositories and the Archived section.

---

## Platform core

- **ilm** — Umbrella repository and landing page for the ILM (Identity Lifecycle Management) platform; pointer to docs and overall project description. (no primary language, public)
- **core** — Core of the platform managing certificate lifecycle management related tasks. Implements the platform API defined in `interfaces` and calls connectors through the provider contracts. (Java, public)
- **auth** — Authentication service for the platform. (C#, public)
- **auth-opa-policies** — OPA policies for evaluating access control permissions. (Open Policy Agent / Rego, public)
- **scheduler** — Scheduler of activities and tasks. (Java, public)
- **utils-service** — Utils service to support various certificate and key handling. (Java, public)
- **csc-api** — ILM CSC API — component implementing the Cloud Signature Consortium API. (Java, public)
- **provisioning-rabbitmq** — Provisioning service for RabbitMQ. (Java, public)
- **cert-manager-issuer** — ILM cert-manager external issuer (Kubernetes cert-manager integration). (Go, public)

## Contracts

- **interfaces** — Authoritative contracts of the platform: the provider (connector) interfaces every connector implements, the API clients core uses to call connectors, and most of Core's platform API, which core implements. Legacy connectors implement `AttributesController`, `HealthController` and `InfoController` plus the controllers of their Function Group, named in each section below. Newer connectors declare versioned `ConnectorInterface` codes on `/v2/info` instead: the common `info`, `health`, `metrics` and `attributes`, plus functional codes such as `authority`, `discovery`, `cryptography`, `secret`, `signatureFormatting` and one content-signing code per AdES family. (Java, public)
  - **Authority Provider** has three contract generations: the original *Legacy* Function Group, the *v2* contract and a *v3* stateless interface.
  - **Signature formatting** (`signatureFormatting`) is the interface for stateless signature assembly, e.g. RFC 3161 timestamp tokens whose private key lives in an external signer. Content-signing formatting (`padesFormatting`, `cadesFormatting`, `jadesFormatting`, `xadesFormatting`) is its sibling for AdES signatures.
- **interface-documentation** — Generates the OpenAPI documents for the contracts in `interfaces` and publishes them, with authored pages, as the public API reference at api.otilm.com. (Java, public)

## Frontend

- **fe-administrator** — Administrator user interface. Generates and commits its API client types from the published Core API document. (TypeScript / React, public)
- **keycloak-theme** — Custom Keycloak theme. (CSS, public)
- **keycloak-optimized** — Keycloak optimized Docker image. (Dockerfile, public)

## Authority providers / CA connectors

Implement the Legacy or v2 Authority Provider Function Group from `interfaces` — the `AuthorityInstanceController` plus `CertificateController` / `EndEntityController` / `EndEntityProfilesController` (legacy) or the v2 `CertificateController` — or the stateless v3 Authority interface.

- **ejbca-ng-connector** — EJBCA NG connector for certificate management and discovery. (Java, public)
- **hashicorp-vault-connector** — Connector to HashiCorp Vault PKI secrets engine providing certificate management and discovery. (Go, public)
- **pyadcs-connector** — Connector for Microsoft ADCS (Python implementation) providing certificate management and certificate discovery. (Python, public)

## Discovery providers

Implement the `Discovery Provider` Function Group (`DiscoveryController`) or the `discovery` v2 interface from `interfaces`.

- **cryptosense-discovery-provider** — Discovery provider searching for certificates in Cryptosense Analyzer reports. (Java, public)
- **ct-logs-discovery-provider** — Connector providing Certificate Transparency (CT) Logs certificate discovery. (Go, public)
- **ip-discovery-provider** — Discovery provider to identify certificates on network (IP/TLS scanning). (Java, public)

## CBOM

- **cbom-lens** — CLI tool to scan filesystems, containers, and network ports for cryptographic assets and generate a CycloneDX CBOM. (Go, public)
- **cbom-repository** — Repository for uploading, retrieving, and searching Cryptographic Bills of Materials (CBOM) documents. (Go, public)

## Credential / keystore providers

Implement the `Credential Provider` Function Group (base connector controllers only — `AttributesController`, `HealthController`, `InfoController`), the `Entity Provider` Function Group (`EntityController`, `LocationController`) or the `secret` interface.

- **common-credential-provider** — Common credential provider (shared credential types exposed to the platform); also implements the `secret` interface. (Java, public)
- **keystore-entity-provider** — Entity provider for managing certificates in Java Keystores. (Java, public)

## Notification providers

Implement the `Notification Provider` Function Group — the `NotificationInstanceController` interface from `interfaces`.

- **email-notification-provider** — Email notification provider. (Java, public)
- **webhook-notification-provider** — Webhook notification provider. (Java, public)

## Cryptography providers

Implement the `Cryptography Provider` Function Group — `TokenInstanceController`, `KeyManagementController` and `CryptographicOperationsController` — or the `cryptography` v2 interface from `interfaces`.

- **software-cryptography-provider** — Implementation of the software Cryptography Provider connector (software keystore). (Java, public)

## Compliance providers

Implement the `Compliance Provider` Function Group — `ComplianceController` and `ComplianceRulesController` from `interfaces`.

- **x509-compliance-provider** — Compliance provider for X.509 certificates. (Go, public)

## Automation

- **mcp-server** — ILM MCP (Model Context Protocol) Server — exposes platform operations to AI agents and other MCP clients through the Core API. (Java, public)

## SDK & tooling

- **go-sdk** — Go SDK for building ILM connectors: models generated from copies of the published connector documents, a connector runtime conforming to the ILM logging/tracing/health specs, and provider packages for the connector interfaces. (Go, public)
- **cli** — Command-line client for the ILM platform, run as `ilmctl` or as the kubectl plugin `kubectl ilm`: installs and operates the ILM operator and its resources through the Kubernetes API. (Go, public)
- **automated-testing-framework** — Automated testing framework for the ILM platform: endpoint tests against a deployed platform at a pinned chart version. (TypeScript, public)
- **dependencies** — Common dependencies (Spring Boot BOM) for Java modules and connectors, consumed as the Maven parent; also carries the shared build format gates. (Shell — Maven poms plus build scripts, public)

## Infrastructure & deployment

- **helm-charts** — Helm Charts for deploying ILM on Kubernetes. (Go Template, public)
- **operator** — Kubernetes operator for the ILM platform. (Go, public)
- **appliance** — Repository for creation of an Open Virtual Appliance with Postgres, RKE2, and ILM. (Shell, public)
- **appliance-tools** — Debian package with ILM Appliance Tools. (Shell, public)
- **debian-repository** — ILM Debian Repository (package hosting). (Shell, public)
- **development-environment** — Development environment setup (Docker Compose) for ILM platform contributors. (Shell, public)
- **ansible-role-ilm** — Ansible role for installation of the ILM application using the helm chart. (Jinja, public)
- **ansible-role-ilm-branding** — Ansible role for applying ILM branding to the Appliance. (Jinja, public)
- **ansible-role-helm** — Ansible role for installing Helm for ILM Appliance. (Shell, public)
- **ansible-role-http-proxy** — Ansible role for configuring HTTP proxy for ILM Appliance. (Shell, public)
- **ansible-role-postgres** — Ansible role for installing and configuring PostgreSQL for ILM Appliance. (Jinja, public)
- **ansible-role-rke2** — Ansible role for installing and managing RKE2 Kubernetes for ILM Appliance. (Jinja, public)
- **ansible-role-systemd-timesyncd** — Ansible role that configures systemd-timesyncd. (Jinja, public)

## Docs & org

- **documentation** — Documentation of the platform (docs site sources). (JavaScript, public)
- **.github** — Org-wide default configuration (issue templates, labels, release notes template, sync workflows, composite actions). Inherited by every repo unless overridden locally. Full detail: https://github.com/OmniTrustILM/.github (Shell, public)

