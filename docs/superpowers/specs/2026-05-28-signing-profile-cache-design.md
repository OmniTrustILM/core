# Signing Profile cache — design

**Status:** approved for planning
**Target branch:** `feat/signing-profile-cache` (cuts from `main` once `feat/signing-profile-model` has merged).

## 1. Goal & scope

Introduce a per-JVM cache for `SigningProfile` lookups on the signing hot path, modeled on the existing `TspProfileCache` and `TimeQualityConfigurationCache`. The cache returns a `SigningProfileModel` value shaped so that **no other cached aggregate is embedded** — foreign references stay as UUIDs and are resolved through their own cache.

Out of scope: cross-instance cache invalidation (single-JVM bounded staleness via TTL is accepted, matching every other cache in this module).

## 2. Cache shape

### 2.1 Properties

`com.czertainly.core.config.cache.SigningProfileCacheProperties`:

```java
@Validated
@ConfigurationProperties(prefix = "caching.signing-profiles")
public record SigningProfileCacheProperties(
        @Min(1) int ttlMinutes,
        @Min(1) int maxSize
) {}
```

Application properties: `caching.signing-profiles.ttl-minutes` and `caching.signing-profiles.max-size`, defaults matching the magnitudes already used by `caching.tsp-profiles`.

### 2.2 Registration

`com.czertainly.core.config.cache.CacheConfig`:

- Add constant `SIGNING_PROFILE_CACHE = "signingProfile"`.
- Add `SigningProfileCacheProperties.class` to `@EnableConfigurationProperties`.
- Inject `SigningProfileCacheProperties` into `cacheManager(...)`.
- Register a custom Caffeine cache: `expireAfterWrite(ttlMinutes, MINUTES)`, `maximumSize(maxSize)`, `recordStats()`. No `removalListener`.

### 2.3 Cached value

`com.czertainly.core.model.signing.SigningProfileModel<W extends SigningWorkflow, SM extends SigningSchemeModel>` — taken **verbatim** from `feat/signing-profile-model` (assumed merged to `main`).

The model holds: `uuid`, `name`, `description`, `version`, `enabled`, `enabledProtocols`, `workflow`, `signingScheme`. The sealed `workflow` and `signingScheme` subtypes hold only **UUIDs** for peer aggregates (`timeQualityConfigurationUuid`, `signatureFormatterConnectorUuid`, `certificateUuid`, `raProfileUuid`, `tokenProfileUuid`, `csrTemplateUuid`, `connectorUuid`). No embedded `TspProfile`, no embedded `TimeQualityConfiguration`, no embedded entities.

The model intentionally does **not** project `tspProfileUuid` from the entity — that back-pointer is only meaningful for management-UI queries, not for the signing hot path.

### 2.4 Key

`#name` (String). Matches `TspProfileCache`. Hot-path lookups (e.g. TSP `/tsp/{signingProfileName}/...`, and `TspProfileModel.defaultSigningProfileName`) come in by name with no translation.

## 3. Service integration

### 3.1 Loader

In `SigningProfileServiceImpl`:

```java
@Cacheable(value = CacheConfig.SIGNING_PROFILE_CACHE, key = "#name", sync = true)
public SigningProfileModel<?, ?> loadSigningProfileModel(String name) throws NotFoundException {
    SigningProfile profile = signingProfileRepository.findByName(name)
            .orElseThrow(() -> new NotFoundException(SigningProfile.class, name));
    SigningProfileVersion currentVersion = profile.getVersions().stream()
            .filter(v -> v.getVersion() == profile.getLatestVersion())
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Signing Profile '" + name + "' has no row for latestVersion " + profile.getLatestVersion()));
    return SigningProfileMapper.toModel(profile, currentVersion);
}
```

`sync = true` collapses concurrent misses to a single loader call. The cache return type is the raw `SigningProfileModel<?, ?>`; Spring's cache abstraction is generics-blind.

### 3.2 Public accessor

```java
public SigningProfileModel<?, ?> getSigningProfileModel(String name) throws NotFoundException {
    return self.loadSigningProfileModel(name);
}
```

Self-invocation via the `self` proxy is required — direct `this.loadSigningProfileModel(...)` bypasses Spring proxy advice and the `@Cacheable` annotation is silently skipped.

### 3.3 Eviction helper

Mirror `TimeQualityConfigurationServiceImpl.evictTimeQualityConfigurationCache` exactly:

```java
private void evictSigningProfileCache(String name) {
    Cache cache = cacheManager.getCache(CacheConfig.SIGNING_PROFILE_CACHE);
    if (cache == null) return;
    if (TransactionSynchronizationManager.isActualTransactionActive()) {
        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        cache.evict(name);
                        tspProfileService.evictAllCachedModels();
                    }
                });
    } else {
        cache.evict(name);
        tspProfileService.evictAllCachedModels();
    }
}
```

The cross-cache fan-out into TspProfile (see §4.2) is intentionally part of the same afterCommit callback so the two caches flip atomically from a reader's perspective.

### 3.4 Mutation call sites

Inside the existing service methods, after the DB write but before returning:

| Method | Eviction |
|---|---|
| `createSigningProfile` | `evictSigningProfileCache(saved.getName())` |
| `updateSigningProfile` (rename-safe) | `evictSigningProfileCache(oldName)` and `evictSigningProfileCache(newName)` |
| `deleteSigningProfile` | `evictSigningProfileCache(profile.getName())` |
| `enableSigningProfile` / `disableSigningProfile` | `evictSigningProfileCache(profile.getName())` |
| Version operations (create version, activate, …) | `evictSigningProfileCache(profile.getName())` |
| Bulk delete / bulk enable / bulk disable | iterate; evict each affected name |

## 4. Coherence

### 4.1 Internal coherence

- **Bounded staleness:** `expireAfterWrite(ttlMinutes)` — defensive bound if an eviction path is ever missed.
- **Concurrent-miss collapse:** `sync = true`.
- **Post-commit eviction:** all evictions register a `TransactionSynchronization.afterCommit()` callback. Pre-commit eviction is incorrect on two counts: a roll-back leaves the cache empty while the DB is unchanged (cosmetic harm); a concurrent reader during the in-flight write reads the pre-update row and repopulates the cache with the value we are about to invalidate (real correctness bug). Post-commit is the only sound point.
- **No transaction held across cache operations.** Caffeine is in-memory, but consistent with the codebase convention.
- **Single-JVM scope.** Multi-instance deployments accept up to `ttlMinutes` of cross-node staleness on writes.

### 4.2 Cross-cache coherence

Comprehensive both-directions analysis:

| Producer of change | Consumer cache | Does consumer model embed any producer-owned data? | Eviction required? |
|---|---|---|---|
| **SigningProfile** mutation (create / update / delete / enable / disable / version op) | TspProfile cache | Yes — `TspProfileModel.defaultSigningProfileName` and the derived `signingUrl` denormalize SP state | **Yes.** SP eviction helper calls `tspProfileService.evictAllCachedModels()` in the same `afterCommit` callback. |
| **SigningProfile** mutation | TimeQualityConfiguration cache | No | No |
| **TspProfile** mutation (create / update / delete / enable / disable) | SP cache | **No.** Verified by inspection of every field in `SigningProfileModel` and its sub-models (`ManagedTimestampingWorkflow`, `ManagedContentSigningWorkflow`, `ManagedRawSigningWorkflow`, `DelegatedTimestampingWorkflow`, `StaticKeyManagedSigning`, `OneTimeKeyManagedSigning`, `DelegatedSigning`). No `tspProfileUuid` / `tspProfileName` / TSP-derived field anywhere. `TspProfileServiceImpl` also never writes to `SigningProfile` state. | **No.** Intentionally not added — would be unnecessary work and would mask the model's clean invariant. |
| **TimeQualityConfiguration** mutation | SP cache | No — SP model holds only `timeQualityConfigurationUuid` | **No.** As part of this work, **remove** the existing wiring: `SigningProfileService.notifyTimeQualityConfigurationChange(UUID)`, its empty stub in `SigningProfileServiceImpl`, and the two call sites in `TimeQualityConfigurationServiceImpl` (one on delete, one on update). The stub was placed in anticipation of an SP cache that embedded TQC data; the actual design does not. |
| **CryptographicKeyItem** / **CertificateChain** / RA-profile / token-profile / connector / CSR-template change | SP cache | No — UUID-only refs | No |

**The asymmetry between SP↔TspProfile is by design.** `TspProfileModel` chose to denormalize `defaultSigningProfileName` for the hot path. That choice buys it the SP→TspProfile fan-out as its eviction cost. `SigningProfileModel` made the opposite choice (UUID-only), so the reverse fan-out is not needed. If a future change moves `TspProfileModel` to UUID-only, the SP→TspProfile fan-out can be removed.

### 4.3 Race window during rename

SP-rename + concurrent TspProfile read can interleave:

1. Reader thread A reads `TspProfileModel` from cache, sees `defaultSigningProfileName = "old"`.
2. Writer thread B commits an SP rename `"old" → "new"`, runs `afterCommit`: evicts both SP names and `tspProfileService.evictAllCachedModels()`.
3. Reader A continues with the stale `"old"` it already read; subsequent SP load for `"old"` hits the DB (cache miss) and throws `NotFoundException`.

Mitigation: this is bounded to the duration of a single in-flight request that captured the TspProfileModel before step 2. A retry hits the freshly-loaded TspProfileModel with the new name. The window cannot grow unbounded because `afterCommit` runs sequentially on the writer thread before any subsequent reader-driven cache fill.

Cross-transaction concurrent renames of multiple SPs are bounded by `sync = true` collapsing concurrent loads against the same name.

## 5. Removed code

As part of this PR, delete:

- `SigningProfileService.notifyTimeQualityConfigurationChange(UUID)`.
- The empty stub `SigningProfileServiceImpl.notifyTimeQualityConfigurationChange`.
- `TimeQualityConfigurationServiceImpl` invocations of `signingProfileService.notifyTimeQualityConfigurationChange(...)` (currently called from `deleteTimeQualityConfiguration` and from the update path).
- The `SigningProfileService` import in `TimeQualityConfigurationServiceImpl` if it becomes unused after the call removals.

Rationale documented in §4.2: SP model holds only `timeQualityConfigurationUuid`, so TQC mutations have no effect on SP-cache validity.

## 6. Tests

### 6.1 New tests in `SigningProfileServiceImplTest`

- Load populates cache (second call hits the cache, not the repository — verify with a Mockito spy or repository call counter).
- `updateSigningProfile` rename evicts both old and new name.
- `deleteSigningProfile` / `enableSigningProfile` / `disableSigningProfile` evict by name.
- Version operations evict the owning profile's name.
- Bulk delete / bulk enable / bulk disable evict every affected name.
- Eviction is deferred until after commit: register the eviction inside a programmatic transaction, assert the cache still contains the entry before commit and is empty after.

### 6.2 Cross-cache tests

- SP mutation triggers `TspProfileService.evictAllCachedModels()` (verify with Mockito).
- TQC mutation does **not** touch SP cache (verify with Mockito strict stubs / no-interactions check).
- TspProfile mutation does **not** touch SP cache.

### 6.3 Removed tests

Drop or migrate any existing tests that exercise `notifyTimeQualityConfigurationChange` plumbing.

## 7. Build & verification

- Project must compile with `-Dmaven.compiler.proc=full` (annotation-processor parity — see CLAUDE.local.md).
- Match SonarCloud `new_coverage` locally before pushing, applying `sonar.coverage.exclusions` and counting both lines and branches per the formula in CLAUDE.md.
- Bot-driven static analysis: the eviction helper's `if (cache == null) return;` guard plus the explicit `Cache` local mirror the existing helpers — no new Sonar/Copilot patterns introduced.

## 8. Future work, explicitly deferred

- Cross-JVM cache invalidation (Caffeine is per-JVM today; a Redis or pub/sub layer is a separate initiative across all caches in this module).
- Moving `TspProfileModel` to UUID-only refs and removing the SP→TspProfile fan-out.
