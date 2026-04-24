# CZERTAINLY Core

> This repository is part of the open source project CZERTAINLY. You can find more information about the project at [CZERTAINLY](https://github.com/CZERTAINLY/CZERTAINLY) repository, including the contribution guide.

`Core` provides the basic functionality for the CZERTAINLY platform. It implements the logic for the certificate lifecycle management and handles all related tasks. You can think about it as a brain of the CZERTAINLY platform.

There are 2 types of communication that the `Core` is responsible for:
- client requesting management operations on top of certificates and related objects
- `Connector` that provides with the functionality for specific technologies

The management of certificates and cryptographic keys is abstracted through CZERTAINLY objects called `Profiles`, such as:
- `RA Profile` - configuration of the service for certificate lifecycle management
- `Token Profile` - configuration of the cryptographic service and management of the keys
- `Compliance Profile` - compliance requirements for the certificates and related objects

For more information, refer to the [CZERTAINLY documentation](https://docs.czertainly.com).

## Access Control

`Core` access control requires the following to run:
- [CZERTAINLY-Auth](https://github.com/CZERTAINLY/CZERTAINLY-Auth) service to manage users, roles, permission. The URL of the `Auth` service can be configured using `AUTH_SERVICE_BASE_URL` environment variable.
- OPA (Open Policy Agent) evaluating policies and providing decisions about authorization. The OPA service URL can be confgiured using `OPA_BASE_URL` environment variable.
- OPA policies bundles that are loaded into OPA service and define the rules to be evaluated. The policies are defined in [CZERTAINLY-Auth-OPA-Policies](https://github.com/CZERTAINLY/CZERTAINLY-Auth-OPA-Policies)

> **Warning**
> The `Core` will fail to run when `Auth` or OPA is missing.

> **Note**
> OPA can run on the same system with the `Core` or it can be hosted externally. To improve the performance of the permissions evaluation it is typically running on the same host as `Core` (e.g. as a sidecar).

## Certificate inventory

`Certificate` inventory contains all `Certificates` that were discovered or were imported to the platform. Each `Certificate` provides comprehensive and consistent information which can be managed.

### Lifecycle operations

The following basic lifecycle operations are supported for each `Certificate`:
- create (request)
- issue
- renew
- rekey
- revoke

Operations can be automated by the `Core`, but also can be performed manually by the user.

## Cryptographic key inventory

`Key` inventory contains all `Keys` that are available for usage. Each `Key` provides comprehensive and consistent information which can be managed through the `Token Profile`.

## Experimental support for PQC algorithms

`Core` supports the following PQC algorithms: `FALCON`, `CRYSTALS-Dilithium`, `SPHINCS+`. The support is experimental and it is not recommended to use it in production as the PQC algorithms are still in the development and not fully standardized.

## Protocol support

`Core` support the following protocols for certificate management:
- ACME
- SCEP (with optional Intune support)
- CMP

## Message brokers support

Application supports two types of message brokers:
- **RabbitMQ** - uses JmsPoolConnectionFactory with configurable connection pool settings
- **Azure Service Bus** - uses JmsConnectionFactory with two authentication options:
  - **SAS (Shared Access Signature)** - uses connection string with policy name and key
  - **AAD (Azure Active Directory / Entra ID)** - uses OAuth2 with Service Principal credentials

### Authentication configuration

| Broker              | Authentication    | Required variables                                                               |
|---------------------|-------------------|----------------------------------------------------------------------------------|
| RabbitMQ            | Username/Password | `BROKER_USERNAME`, `BROKER_PASSWORD`                                             |
| Azure Service Bus   | SAS               | `BROKER_USERNAME`, `BROKER_PASSWORD`                                             |
| Azure Service Bus   | AAD               | `BROKER_AZURE_TENANT_ID`, `BROKER_AZURE_CLIENT_ID`, `BROKER_AZURE_CLIENT_SECRET` |

## Docker container

`Core` is provided as a Docker container. Use the `czertainly/czertainly-core:tagname` to pull the required image from the repository. It can be configured using the following environment variables:

| Variable                              | Description                                                                                                                                      | Required                                      | Default value       |
|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|---------------------|
| `JDBC_URL`                            | JDBC URL for database access                                                                                                                     | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `JDBC_USERNAME`                       | Username to access the database                                                                                                                  | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `JDBC_PASSWORD`                       | Password to access the database                                                                                                                  | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `DB_SCHEMA`                           | Database schema to use                                                                                                                           | ![](https://img.shields.io/badge/-NO-red.svg) | `core`              |
| `PORT`                                | Port where the service is exposed                                                                                                                | ![](https://img.shields.io/badge/-NO-red.svg) | `8080`              |
| `HEADER_NAME`                         | Name of the header where the certificate of the client can be found                                                                              | ![](https://img.shields.io/badge/-NO-red.svg) | `ssl-client-cert`   |
| `HEADER_ENABLED`                      | True if the certificate should be get from the header                                                                                            | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `TS_PASSWORD`                         | Password for the trusted certificate store                                                                                                       | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `OPA_BASE_URL`                        | Base URL of the Open Policy Agent                                                                                                                | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `AUTH_SERVICE_BASE_URL`               | Base URL of the authentication service                                                                                                           | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `AUTH_TOKEN_HEADER_NAME`              | Name of the header for the JSON ID content                                                                                                       | ![](https://img.shields.io/badge/-NO-red.svg) | `X-USERINFO`        |
| `SCHEDULED_TASKS_ENABLED`             | Scheduled certificate status update enable / disable                                                                                             | ![](https://img.shields.io/badge/-NO-red.svg) | `true`              |
| `JAVA_OPTS`                           | Customize Java system properties for running application                                                                                         | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`               |
| `TRUSTED_CERTIFICATES`                | List of PEM encoded additional trusted certificates                                                                                              | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`               |
| `SCHEDULER_BASE_URL`                  | Base URL of the scheduler service                                                                                                                | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `BROKER_TYPE`                         | Message broker type - supported values are `SERVICEBUS` or `RABBITMQ`                                                                            | ![](https://img.shields.io/badge/-NO-red.svg) | `RABBITMQ`          |
| `BROKER_URL`                          | Message broker url (include protocol, e.g. `amqp://localhost:5672` for RabbitMQ, `amqps://namespace.servicebus.windows.net:5671` for ServiceBus) | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`               |
| `BROKER_USERNAME`                     | Message broker username (required for RabbitMQ and ServiceBus+SAS)                                                                               | ![](https://img.shields.io/badge/-CONDITIONAL-yellow.svg) | `N/A`               |
| `BROKER_PASSWORD`                     | Message broker password (required for RabbitMQ and ServiceBus+SAS)                                                                               | ![](https://img.shields.io/badge/-CONDITIONAL-yellow.svg) | `N/A`               |
| `BROKER_AZURE_TENANT_ID`              | Azure AD tenant ID (required for ServiceBus+AAD authentication)                                                                                  | ![](https://img.shields.io/badge/-CONDITIONAL-yellow.svg) | `N/A`               |
| `BROKER_AZURE_CLIENT_ID`              | Azure AD application (client) ID (required for ServiceBus+AAD)                                                                                   | ![](https://img.shields.io/badge/-CONDITIONAL-yellow.svg) | `N/A`               |
| `BROKER_AZURE_CLIENT_SECRET`          | Azure AD client secret (required for ServiceBus+AAD authentication)                                                                              | ![](https://img.shields.io/badge/-CONDITIONAL-yellow.svg) | `N/A`               |
| `BROKER_AZURE_TOKEN_REFRESH_INTERVAL` | Azure AD token refresh interval in seconds (required for ServiceBus+AAD authentication)                                                          | ![](https://img.shields.io/badge/-NO-red.svg) | `300`               |
| `BROKER_AZURE_TOKEN_GETTING_TIMEOUT`  | Azure AD token getting timeout in seconds (required for ServiceBus+AAD authentication)                                                           | ![](https://img.shields.io/badge/-NO-red.svg) | `30`                 |
| `BROKER_EXCHANGE`                     | Message broker exchange/topic name                                                                                                               | ![](https://img.shields.io/badge/-NO-red.svg) | `czertainly`        |
| `BROKER_VHOST`                        | Message broker vhost (for RabbitMQ only)                                                                                                         | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`               |
| `BROKER_SESSION_CACHE_SIZE`           | ConnectionCachingFactory session cache size (only for RabbitMQ)                                                                                  | ![](https://img.shields.io/badge/-NO-red.svg) | `25`                |
| `BROKER_QUEUE_AUDIT_LOGS`             | Queue name for audit logs (for RabbitMQ only)                                                                                                    | ![](https://img.shields.io/badge/-NO-red.svg) | `core.audit-logs`   |
| `BROKER_QUEUE_EVENT`                  | Queue name for events (for RabbitMQ only)                                                                                                        | ![](https://img.shields.io/badge/-NO-red.svg) | `core.event`        |
| `BROKER_QUEUE_NOTIFICATION`           | Queue name for notifications (for RabbitMQ only)                                                                                                 | ![](https://img.shields.io/badge/-NO-red.svg) | `core.notification` |
| `BROKER_QUEUE_SCHEDULER`              | Queue name for scheduler (for RabbitMQ only)                                                                                                     | ![](https://img.shields.io/badge/-NO-red.svg) | `core.scheduler`    |
| `BROKER_QUEUE_VALIDATION`             | Queue name for validation (for RabbitMQ only)                                                                                                    | ![](https://img.shields.io/badge/-NO-red.svg) | `core.validation`   |
| `BROKER_ROUTINGKEY_ACTIONS`           | Routing key for actions                                                                                                                          | ![](https://img.shields.io/badge/-NO-red.svg) | `actions`           |
| `BROKER_ROUTINGKEY_AUDIT_LOGS`        | Routing key for audit logs                                                                                                                       | ![](https://img.shields.io/badge/-NO-red.svg) | `auditlogs`         |
| `BROKER_ROUTINGKEY_EVENT`             | Routing key for events                                                                                                                           | ![](https://img.shields.io/badge/-NO-red.svg) | `event`             |
| `BROKER_ROUTINGKEY_NOTIFICATION`      | Routing key for notifications                                                                                                                    | ![](https://img.shields.io/badge/-NO-red.svg) | `notification`      |
| `BROKER_ROUTINGKEY_SCHEDULER`         | Routing key for scheduler                                                                                                                        | ![](https://img.shields.io/badge/-NO-red.svg) | `scheduler`         |
| `BROKER_ROUTINGKEY_VALIDATION`        | Routing key for validation                                                                                                                       | ![](https://img.shields.io/badge/-NO-red.svg) | `validation`        |
| `SETTINGS_CACHE_REFRESH_INTERVAL`     | Interval of scheduled settings cache refresh from DB (in seconds)                                                                                | ![](https://img.shields.io/badge/-NO-red.svg) | `30`                |)


### OpenTelemetry settings

`Core` supports OpenTelemetry for producing signals (metrics, traces, logs) to the observability system. The following environment variables can be used to configure OpenTelemetry:

| Variable                              | Description                                                                                                                         | Required                                      | Default value           |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------|
| `OTEL_SDK_DISABLED`                   | Disables the OpenTelemetry SDK. Supported values: `true`, `false`. OpenTelemetry SDK is disabled by default                         | ![](https://img.shields.io/badge/-NO-red.svg) | `true`                  |
| `OTEL_LOGS_EXPORTER`                  | The logs exporter to use. Supported values: `none`, `otlp`, `logging`.                                                              | ![](https://img.shields.io/badge/-NO-red.svg) | `none`                  |
| `OTEL_METRICS_EXPORTER`               | The metrics exporter to use. Supported values: `none`, `otlp`, `logging`.                                                           | ![](https://img.shields.io/badge/-NO-red.svg) | `none`                  |
| `OTEL_TRACES_EXPORTER`                | The traces exporter to use. Supported values: `none`, `otlp`, `logging`.                                                            | ![](https://img.shields.io/badge/-NO-red.svg) | `none`                  |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`    | Endpoint URL for log data only, with an optionally-specified port number. Typically ends with `v1/logs` when using OTLP/HTTP.       | ![](https://img.shields.io/badge/-NO-red.svg) | `http://localhost:4317` |
| `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL`    | Protocol to use for the logs exporter. Supported values: `grpc`, `http/protobuf`, `http/json`.                                      | ![](https://img.shields.io/badge/-NO-red.svg) | `grpc`                  |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Endpoint URL for metric data only, with an optionally-specified port number. Typically ends with `v1/metrics` when using OTLP/HTTP. | ![](https://img.shields.io/badge/-NO-red.svg) | `http://localhost:4317` |
| `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | Protocol to use for the metrics exporter. Supported values: `grpc`, `http/protobuf`, `http/json`.                                   | ![](https://img.shields.io/badge/-NO-red.svg) | `grpc`                  |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`  | Endpoint URL for trace data only, with an optionally-specified port number. Typically ends with `v1/traces` when using OTLP/HTTP.   | ![](https://img.shields.io/badge/-NO-red.svg) | `http://localhost:4317` |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`  | Protocol to use for the traces exporter. Supported values: `grpc`, `http/protobuf`, `http/json`.                                    | ![](https://img.shields.io/badge/-NO-red.svg) | `grpc`                  |

### Proxy settings

You may need to configure proxy to allow `Core` to communicate with external systems.
To enable proxy, use the following environment variables for docker container:

| Variable      | Description                                                                                                                                                | Required                                      | Default value |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|---------------|
| `HTTP_PROXY`  | The proxy URL to use for http connections. Format: `<protocol>://<proxy_host>:<proxy_port>` or `<protocol>://<user>:<password>@<proxy_host>:<proxy_port>`  | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`         |
| `HTTPS_PROXY` | The proxy URL to use for https connections. Format: `<protocol>://<proxy_host>:<proxy_port>` or `<protocol>://<user>:<password>@<proxy_host>:<proxy_port>` | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`         |
| `NO_PROXY`    | A comma-separated list of host names that shouldn't go through any proxy                                                                                   | ![](https://img.shields.io/badge/-NO-red.svg) | `N/A`         |

Example values:
- `HTTP_PROXY=http://user:password@proxy.example.com:3128`
- `HTTPS_PROXY=http://user:password@proxy.example.com:3128`
- `NO_PROXY=localhost,127.0.0.1,0.0.0.0,10.0.0.0/8,cattle-system.svc,.svc,.cluster.local,my-domain.local`
