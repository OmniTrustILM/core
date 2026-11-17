# ILM repository relationships

These relationships decide which other repositories a change can break.

## Contracts and their consumers

OmniTrustILM/interfaces defines two contract families:

- Provider (connector) contracts: the controllers, models and API clients that
  connectors implement and core uses to call them.
- Most of Core's platform API: the controller interfaces and models that core
  implements.

interface-documentation generates the OpenAPI documents for both families from
the compiled interfaces and publishes them as the public API reference
(api.otilm.com). Consumers are built from those documents or from the Java
artifact:

- core and Java connectors depend on a pinned interfaces Maven artifact.
- fe-administrator generates its API client types from the published Core
  document and commits them; other API clients such as mcp-server call the same
  API.
- go-sdk keeps copies of the published connector documents and generates its
  model packages from them; Go connectors built on go-sdk pin a go-sdk module
  version. Other connectors, in Go or other languages, implement the wire
  contract directly from the published documents.

A build-time change in interfaces reaches a consumer only when that consumer's
snapshot moves: the Maven version, the committed generated client, the copied
specification. A wire change reaches every deployed counterpart at once,
whatever it pins: connectors on their own release cycle answer core's calls,
and fe-administrator and other API clients call the Core they are deployed
with. Name the consumer, the snapshot or deployed version it holds and the
failing path. Distinguish an incompatible change from intentional versioned
coexistence, such as the legacy, v2 and v3 Authority Provider contracts,
attribute content versions v1, v2 and v3, or the `attributes` v2 interface
beside the legacy attribute controllers.

## Where a consumer records what it consumes

Open the consumer's record before claiming a break or compatibility:

| Consumer | Record |
|---|---|
| core and Java connectors | `pom.xml`: the `interfaces` dependency version or an `interfaces.version` property; the `dependencies` parent version for the shared BOM |
| Go connectors built on go-sdk | `go.mod`: the `github.com/OmniTrustILM/go-sdk` line |
| go-sdk | `connector/spec/`: copies of the published connector documents; `connector/model/` reflects those copies, not current interfaces main |
| fe-administrator | `src/types/openapi/` (the committed generated client) and `openapitools.json` (the document it was generated from) |
| automated-testing-framework | each test folder's `variables.json` (platform chart version) and its platform values file (the deployed composition) |
| Deployments | `helm-charts`: each chart's `values.yaml` `image.tag`, or `image.digest`, which wins; the `ilm` umbrella chart's values and deployment values override both. `Chart.yaml` `appVersion` is only a label |
| operator | `pkg/bom/`: per platform version, the component images, environment-variable and Secret-key names and messaging topology it deploys; `internal/registration/` calls Core's connector registration API |

A `-SNAPSHOT` version or a `main` document path means the consumer tracks a
moving target; the change must then say which revision it was built against.

Before claiming that a server change breaks a test in a test automation
repository, or that a test correctly describes server behavior, pin the chart
or application version, the API or provider contract, and the deployment
configuration and test data the test runs against.

## Coordinated changes

A change that needs a counterpart in another repository names it. Where a
repository builds against an interfaces snapshot, its pull request body may
carry a `Depends-On: OmniTrustILM/interfaces#<n>` or `Interfaces-Version:
<version>` line, and CI builds against that counterpart. Treat a declared
counterpart as the intended rollout and check that the order is safe for
released consumers; treat an undeclared dependency on unmerged or unreleased
code as a defect. An unmerged counterpart is not available to released code.

## Checks

Check changed routes, wire fields, requiredness, nullability, enum and error
semantics, generated models, SDK defaults and supported version negotiation.
Cite the actual consumer failure and propose compatible behavior or a safe
rollout order.

A map entry is not evidence that you can read a repository. When the review
names specific counterpart repositories or revisions, inspect those, and say
when a counterpart cannot be inspected.
