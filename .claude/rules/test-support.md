---
paths:
  - "src/test/java/**/util/builders/**"
  - "src/test/java/**/util/seeders/**"
  - "src/test/java/**/util/mocks/**"
  - "src/test/java/**/*Builder.java"
  - "src/test/java/**/*Seeder.java"
  - "src/test/java/**/*Fixture.java"
  - "src/test/java/**/*Fixtures.java"
---

# Test support classes

A builder constructs an in-memory object that the test adjusts and persists itself. A seeder is an `@Component` that persists, or drives services, for setup that is procedural by nature, such as an entity graph or a condition→rule→trigger chain. A fixture hands out ready material that tests use as is.

New support classes follow these rules whole, and a change to an existing one follows them in the members it adds or changes. Restyle the rest of a class only when the task asks for it, so a diff stays about its change.

## Builders

```java
/** Builds a minimal valid signing profile; tests override only the field their scenario is about. */
public final class SigningProfileModelBuilder {

    private UUID uuid = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private String name = "test-profile";

    public static SigningProfileModelBuilder aSigningProfile() {
        return new SigningProfileModelBuilder();
    }

    public static SigningProfileModel<?, ?> valid() {
        return aSigningProfile().build();
    }

    public SigningProfileModelBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public SigningProfileModel<?, ?> build() { ... }
}
```

- Each domain type has one `public final class XxxBuilder` in `util/builders`, entered through a static article-and-noun method such as `aSigningProfile()` or `aRawTspRequest()`, or a plain noun phrase such as `ecdsaSignatureAttributes()` where an article reads awkwardly.
- Defaults are field initializers, so `build()` with no overrides yields a minimal valid object, which an optional static `valid()` returns. A lifecycle entity whose tests depend on unset fields, such as a null `commonName` rendered as a placeholder or an absent `state` that drives a branch, builds bare instead: it applies only what each `withXxx` sets, and its class Javadoc says why.
- Each overridable field has one `withXxx(value)` returning `this`. `build()` wraps checked exceptions as unchecked ones such as `UncheckedIOException`, and internal value tuples are nested records.
- The class Javadoc states what the defaults produce.
- A builder works in memory, and anything that saves belongs in a seeder.

## Fixtures

- An `XxxFixtures` class is `public final` with a private constructor and a class Javadoc, and its static factories are named after what they return: `PqcKeyFixtures.keyPair()`, `ExportEnvelopeFixtures.pinnedEnvelope(key, passphrase)`.
- A parameter that tests depend on is a named constant such as `PINNED_ITERATIONS`.
- Fixtures shared across packages live under `util/`, and fixtures for one package sit next to its tests.

## Connector mocks

- A connector mock extends `BaseConnectorMock`, has a package-private constructor that `ConnectorMockFactory` calls, and exposes public `stubXxx(...)` methods returning `this`, so a test wires only the stubs its scenario needs. Each stub's Javadoc names the production call path it covers.
- Behaviour that canned JSON cannot express goes in a WireMock `ResponseDefinitionTransformerV2` such as `RealSignerTransformer`. Material that exercises the real code path, with real signing and real DER, is preferred over hard-coded values.

## Verification

Run the affected tests after changing a builder, seeder or fixture, since a builder that drops or changes a field still compiles.
