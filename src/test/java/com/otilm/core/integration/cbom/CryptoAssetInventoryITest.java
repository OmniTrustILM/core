package com.otilm.core.integration.cbom;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.IdentityRuleset;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CbomTombstone;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.CryptoAssetAlias;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CbomTombstoneRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetAliasRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CbomTombstoneWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/**
 * The cryptographic asset inventory against real PostgreSQL: the upsert paths, the merge election, the foreign-key
 * behaviours the schema promises, and the alias table's invisibility to identity.
 */
class CryptoAssetInventoryITest extends BaseSpringBootTest {

    private static final String SECRET_MARKER = "AKIA-SECRET-MARKER";

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CryptoAssetSourceRepository sourceRepository;

    @Autowired
    private CryptoAssetAliasRepository aliasRepository;

    @Autowired
    private CbomTombstoneRepository tombstoneRepository;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomExternalService cbomService;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CryptoAssetAliasWriter aliasWriter;

    @Autowired
    private CbomAssetSyncStateWriter syncStateWriter;

    @Autowired
    private CbomTombstoneWriter tombstoneWriter;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private Cbom leanCbom;
    private Cbom richCbom;

    @BeforeEach
    void seedCboms() {
        leanCbom = cbom("urn:uuid:lean", 1);
        richCbom = cbom("urn:uuid:rich", 1);
    }

    // ---- upsert and the rule-set stamp ----

    @Test
    void reIngestingTheSameAssetKeepsOneRow() {
        UUID first = upsert(rsa2048(), null);
        UUID second = upsert(rsa2048(), null);

        assertThat(second).isEqualTo(first);
        assertThat(assetRepository.count()).isEqualTo(1);
    }

    @Test
    void differentAssetsGetDifferentRows() {
        upsert(rsa2048(), null);
        upsert(algorithm("RSA", "4096"), null);

        assertThat(assetRepository.count()).isEqualTo(2);
    }

    @Test
    void everyUpsertStampsTheRulesetVersionThatKeyedTheRow() {
        UUID assetUuid = upsert(rsa2048(), null);

        assertThat(asset(assetUuid).getRulesetVersion()).isEqualTo(IdentityRuleset.VERSION);

        // A row left behind by an older rule set: findable by query, which is what recording the version buys.
        CryptoAsset stale = asset(assetUuid);
        stale.setRulesetVersion(IdentityRuleset.VERSION - 1);
        assetRepository.save(stale);

        assertThat(assetRepository.findUuidsKeyedBefore(IdentityRuleset.VERSION)).containsExactly(assetUuid);

        // The update branch of the upsert restamps it, so a re-sync clears the backlog.
        assertThat(upsert(rsa2048(), null)).isEqualTo(assetUuid);
        assertThat(assetRepository.findUuidsKeyedBefore(IdentityRuleset.VERSION)).isEmpty();
        assertThat(asset(assetUuid).getRulesetVersion()).isEqualTo(IdentityRuleset.VERSION);
    }

    @Test
    void aPqcVerdictLeavesTheIdentityStampAlone() {
        UUID assetUuid = upsert(rsa2048(), null);
        CryptoAsset before = asset(assetUuid);

        assetWriter
                .applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "RSA-CLASSICAL", "RSA is not quantum resistant", 7,
                        Map.of("algorithmFamily", "rsa", "parameterSetIdentifier", "2048"));

        CryptoAsset after = asset(assetUuid);
        assertThat(after.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(after.getPqcRuleId()).isEqualTo("RSA-CLASSICAL");
        assertThat(after.getPqcRulesetVersion()).isEqualTo(7);
        assertThat(after.getPqcEvaluatedFields()).containsEntry("parameterSetIdentifier", "2048");
        assertThat(after.getRulesetVersion())
                .describedAs("a verdict is not an identity")
                .isEqualTo(before.getRulesetVersion());
        assertThat(after.getIdentityKey()).isEqualTo(before.getIdentityKey());
    }

    /**
     * The contract distinguishes when a verdict was decided from when it was last looked at, so a re-evaluation that
     * confirms the same verdict must advance one and not the other.
     */
    @Test
    void aReEvaluationAdvancesEvaluatedAtButNotDecidedAt() {
        UUID assetUuid = upsert(rsa2048(), null);

        assetWriter.applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "RSA-CLASSICAL", "not quantum resistant", 7, null);
        CryptoAsset firstVerdict = asset(assetUuid);
        assertThat(firstVerdict.getPqcDecidedAt()).isNotNull();
        assertThat(firstVerdict.getPqcEvaluatedAt()).isNotNull();

        assetWriter.applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "RSA-CLASSICAL", "not quantum resistant", 8, null);
        CryptoAsset confirmed = asset(assetUuid);
        assertThat(confirmed.getPqcDecidedAt())
                .describedAs("the verdict did not change, so the date it was decided must not move")
                .isEqualTo(firstVerdict.getPqcDecidedAt());
        assertThat(confirmed.getPqcEvaluatedAt())
                .describedAs("but it was looked at again")
                .isAfterOrEqualTo(firstVerdict.getPqcEvaluatedAt());

        assetWriter.applyPqcVerdict(assetUuid, PqcVerdict.READY, "RSA-REKEYED", "re-keyed to ML-DSA", 8, null);
        assertThat(asset(assetUuid).getPqcDecidedAt())
                .describedAs("a changed verdict is a new decision")
                .isAfter(firstVerdict.getPqcDecidedAt());
    }

    // ---- the merge and its provenance pointer ----

    @Test
    void theMergedPayloadIsTheRichestSourcePayloadAndSaysWhichSourceItCameFrom() {
        UUID assetUuid = upsert(rsa2048(), null);
        Map<String, Object> lean = Map.of("primitive", "signature");
        Map<String, Object> rich = Map.of("primitive", "signature", "padding", "pkcs1v15", "parameterSet", "2048");

        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), lean, List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), rich, List.of(), OffsetDateTime.now());

        CryptoAsset merged = asset(assetUuid);
        assertThat(merged.getSourceCount()).isEqualTo(2);
        assertThat(merged.getMergedCryptoProperties()).isEqualTo(rich);
        assertThat(merged.getPropertiesLeafCount()).isEqualTo(3);
        assertThat(merged.getPropertiesHash()).isNotNull();
        assertThat(merged.getPropertiesSourceUuid())
                .describedAs("the merged payload must be attributable to the source it was adopted from")
                .isEqualTo(source(assetUuid, richCbom.getUuid()).getUuid());
    }

    @Test
    void detachingTheElectedSourceReElectsFromWhatIsLeft() {
        UUID assetUuid = upsert(rsa2048(), null);
        Map<String, Object> lean = Map.of("primitive", "signature");
        Map<String, Object> rich = Map.of("primitive", "signature", "padding", "pkcs1v15");
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), lean, List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), rich, List.of(), OffsetDateTime.now());

        assertThat(sourceWriter.detachCbom(assetUuid, richCbom.getUuid())).isEqualTo(1);

        CryptoAsset merged = asset(assetUuid);
        assertThat(merged.getSourceCount()).isEqualTo(1);
        assertThat(merged.getMergedCryptoProperties()).isEqualTo(lean);
        assertThat(merged.getPropertiesSourceUuid()).isEqualTo(source(assetUuid, leanCbom.getUuid()).getUuid());
    }

    @Test
    void detachingTheLastSourceLeavesTheAssetWithNothingToAttribute() {
        UUID assetUuid = upsert(rsa2048(), null);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(),
                        OffsetDateTime.now());

        sourceWriter.detachCbom(assetUuid, leanCbom.getUuid());

        CryptoAsset stripped = asset(assetUuid);
        assertThat(stripped.getSourceCount()).isZero();
        assertThat(stripped.getMergedCryptoProperties()).isNull();
        assertThat(stripped.getPropertiesHash()).isNull();
        assertThat(stripped.getPropertiesLeafCount()).isZero();
        assertThat(stripped.getPropertiesSourceUuid()).isNull();
        assertThat(assetRepository.findById(assetUuid))
                .describedAs("retention is reversible by a later sweep; deletion is not, and the re-sync semantics "
                        + "are not ratified")
                .isPresent();
    }

    @Test
    void deletingASourceRowNullsThePointerRatherThanLeavingItDangling() {
        UUID assetUuid = upsert(rsa2048(), null);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(),
                        OffsetDateTime.now());
        UUID sourceUuid = source(assetUuid, leanCbom.getUuid()).getUuid();
        assertThat(asset(assetUuid).getPropertiesSourceUuid()).isEqualTo(sourceUuid);

        // Deliberately bypassing the writer: this asserts the schema's own guarantee, not the writer's discipline.
        sourceRepository.deleteById(sourceUuid);

        assertThat(asset(assetUuid).getPropertiesSourceUuid())
                .describedAs("a NULL pointer is findable; a dangling uuid is indistinguishable from a valid one")
                .isNull();
    }

    @Test
    void reIngestingASourceKeepsWhenItWasFirstSeen() {
        UUID assetUuid = upsert(rsa2048(), null);
        OffsetDateTime first = OffsetDateTime.now().minusDays(3);
        OffsetDateTime later = OffsetDateTime.now();

        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(), first);
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "keyAgree"), List.of(), later);

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(sourceRepository.count()).isEqualTo(1);
        assertThat(stored.getFirstSeenAt()).isCloseTo(first, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getLastSeenAt()).isCloseTo(later, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getOriginalCryptoProperties()).containsEntry("primitive", "keyAgree");
    }

    @Test
    void aSourceThatReportedNoPropertiesLeavesTheMergeBookkeepingEmpty() {
        UUID assetUuid = upsert(rsa2048(), null);

        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), null, null, OffsetDateTime.now());

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(stored.getOriginalCryptoProperties()).isNull();
        assertThat(stored.getEvidence()).isNull();
        assertThat(stored.getOccurrenceCount()).isZero();
        assertThat(stored.getPropertiesHash()).isNull();

        CryptoAsset merged = asset(assetUuid);
        assertThat(merged.getSourceCount()).isEqualTo(1);
        assertThat(merged.getMergedCryptoProperties()).isNull();
        assertThat(merged.getPropertiesHash())
                .describedAs("ck_crypto_asset_properties_pair requires payload and hash to be absent together")
                .isNull();
        assertThat(merged.getPropertiesSourceUuid())
                .describedAs("an absent payload is still attributable to the source that reported nothing")
                .isEqualTo(stored.getUuid());
    }

    @Test
    void anEquallyRichPairElectsDeterministically() {
        UUID assetUuid = upsert(rsa2048(), null);
        Map<String, Object> one = Map.of("primitive", "signature");
        Map<String, Object> other = Map.of("primitive", "keyAgree");
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), one, List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), other, List.of(), OffsetDateTime.now());
        Map<String, Object> firstElection = asset(assetUuid).getMergedCryptoProperties();

        // Re-ingesting in the opposite order must not flip the election; without a total order the pointer would
        // oscillate on every sync.
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), other, List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), one, List.of(), OffsetDateTime.now());

        assertThat(asset(assetUuid).getMergedCryptoProperties()).isEqualTo(firstElection);
    }

    @Test
    void aVerdictCanBeCleared() {
        UUID assetUuid = upsert(rsa2048(), null);
        assetWriter.applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "RSA-CLASSICAL", "reason", 7, Map.of("a", "b"));

        assetWriter.applyPqcVerdict(assetUuid, null, null, null, 8, null);

        CryptoAsset cleared = asset(assetUuid);
        assertThat(cleared.getPqcVerdict()).isNull();
        assertThat(cleared.getPqcRuleId()).isNull();
        assertThat(cleared.getPqcEvaluatedFields()).isNull();
        assertThat(cleared.getPqcRulesetVersion()).isEqualTo(8);
    }

    // ---- evidence capping ----

    @Test
    void storedEvidenceIsCappedAndTheOccurrenceCountStillRecordsWhatWasSeen() {
        UUID assetUuid = upsert(rsa2048(), null);
        List<Map<String, Object>> occurrences = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            Map<String, Object> occurrence = new LinkedHashMap<>();
            occurrence.put("location", "src/file" + i + ".java");
            occurrence.put("additionalContext", SECRET_MARKER + "x".repeat(4096));
            occurrences.add(occurrence);
        }

        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), occurrences,
                        OffsetDateTime.now());

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(stored.getOccurrenceCount()).isEqualTo(60);
        assertThat(stored.getEvidence()).hasSize(50);
        assertThat(stored.getEvidence())
                .describedAs("the snippet is dropped whole, never shortened")
                .allSatisfy(occurrence -> assertThat(occurrence).doesNotContainKey("additionalContext"));
        assertThat(String.valueOf(stored.getEvidence())).doesNotContain(SECRET_MARKER);
    }

    /**
     * F6: {@code cap()} filters JSON-null array elements out before it ever counts an occurrence, so a null carries no
     * evidence and must not inflate {@code occurrence_count} either -- the stored count has to keep agreeing with what
     * capping considered real.
     */
    @Test
    void occurrenceCountExcludesJsonNullArrayElements() {
        UUID assetUuid = upsert(rsa2048(), null);
        List<Map<String, Object>> occurrencesWithNulls = new ArrayList<>();
        occurrencesWithNulls.add(Map.of("location", "src/a.java"));
        occurrencesWithNulls.add(null);
        occurrencesWithNulls.add(null);

        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), occurrencesWithNulls,
                        OffsetDateTime.now());

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(stored.getOccurrenceCount())
                .describedAs("a JSON-null array element carries no evidence and must not inflate the true count")
                .isEqualTo(1);
        assertThat(stored.getEvidence()).hasSize(1);
    }

    // ---- foreign-key behaviour ----

    @Test
    void deletingAnAssetTakesItsSourcesAndAliasesWithIt() {
        UUID absorbedUuid = upsert(algorithm("RSA", "2048"), null);
        UUID canonicalUuid = upsert(algorithm("RSA", "4096"), null);
        sourceWriter
                .upsertSource(canonicalUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(),
                        OffsetDateTime.now());
        aliasWriter
                .record(asset(absorbedUuid).getIdentityKey(), asset(canonicalUuid).getIdentityKey(), "typo",
                        "operator");
        assertThat(aliasRepository.count()).isEqualTo(1);

        assertThat(assetWriter.delete(canonicalUuid)).isEqualTo(1);

        assertThat(sourceRepository.count())
                .describedAs("a source reference is meaningless without its asset")
                .isZero();
        assertThat(aliasRepository.count()).describedAs("an alias pointing at nothing is a lie").isZero();
        assertThat(cbomRepository.findById(leanCbom.getUuid()))
                .describedAs("deleting an asset must not touch the CBOM it came from")
                .isPresent();
    }

    @Test
    void aCbomStillReferencedByTheInventoryCannotBeDeletedAndTheRefusalLeaksNothing() {
        UUID assetUuid = upsert(rsa2048(), null);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(),
                        OffsetDateTime.now());

        DataIntegrityViolationException rejection = (DataIntegrityViolationException) org.junit.jupiter.api.Assertions
                .assertThrows(DataIntegrityViolationException.class,
                        () -> cbomRepository.deleteById(leanCbom.getUuid()));

        assertThat(CryptoAssetConstraintTranslator.constraintNameOf(rejection))
                .contains("crypto_asset_source_to_cbom_key");
        String description = CryptoAssetConstraintTranslator.describe(rejection);
        assertThat(description).contains("still referenced by the cryptographic asset inventory");
        assertThat(description)
                .describedAs("the driver's DETAIL line quotes the failing row")
                .doesNotContain("Detail")
                .doesNotContain("DETAIL")
                .doesNotContain(leanCbom.getUuid().toString())
                .doesNotContain(asset(assetUuid).getIdentityKey());

        // Detaching first is what makes the deletion possible, which is what "through the service path" means.
        sourceWriter.detachCbom(assetUuid, leanCbom.getUuid());
        cbomRepository.deleteById(leanCbom.getUuid());
        assertThat(cbomRepository.findById(leanCbom.getUuid())).isEmpty();
    }

    @Test
    void theCbomDeleteServicePathRefusesWhileTheInventoryReferencesItAndForwardsNoDriverText() throws Exception {
        UUID assetUuid = upsert(rsa2048(), null);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(),
                        OffsetDateTime.now());
        String identityKey = asset(assetUuid).getIdentityKey();

        ValidationException refusal = org.junit.jupiter.api.Assertions
                .assertThrows(ValidationException.class, () -> cbomService.deleteCbom(leanCbom.getUuid()));

        assertThat(refusal.getMessage()).contains("still referenced by the cryptographic asset inventory");
        assertLeaksNothing(refusal.getMessage(), identityKey);

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(leanCbom.getUuid()));

        assertThat(messages).singleElement().satisfies(message -> {
            assertThat(message.getMessage()).contains("still referenced by the cryptographic asset inventory");
            assertLeaksNothing(message.getMessage(), identityKey);
        });
        assertThat(cbomRepository.findById(leanCbom.getUuid()))
                .describedAs("a refused deletion leaves the row where it was")
                .isPresent();
    }

    private void assertLeaksNothing(String text, String identityKey) {
        assertThat(text)
                .describedAs("the driver's DETAIL line quotes the failing row, and for crypto_asset that row carries "
                        + "the identity key")
                .doesNotContain("Detail")
                .doesNotContain("DETAIL")
                .doesNotContain("detail")
                .doesNotContain(identityKey)
                .doesNotContain(leanCbom.getUuid().toString())
                .doesNotContain("crypto_asset_source");
    }

    // ---- the alias table is invisible to identity ----

    @Test
    void addingRemovingAndRePointingAnAliasChangesNoIdentityKey() {
        UUID absorbedUuid = upsert(algorithm("RSA", "2048"), null);
        UUID canonicalUuid = upsert(algorithm("RSA", "4096"), null);
        UUID otherUuid = upsert(algorithm("ECDSA", "P-256"), null);
        Map<UUID, String> keysBefore = Map
                .of(absorbedUuid, asset(absorbedUuid).getIdentityKey(), canonicalUuid,
                        asset(canonicalUuid).getIdentityKey(), otherUuid, asset(otherUuid).getIdentityKey());

        aliasWriter.record(keysBefore.get(absorbedUuid), keysBefore.get(canonicalUuid), "duplicate", "operator");
        assertKeysUnchanged(keysBefore);

        aliasWriter.record(keysBefore.get(absorbedUuid), keysBefore.get(otherUuid), "re-pointed", "operator");
        assertThat(aliasRepository.count())
                .describedAs("re-pointing replaces the decision, it does not add one")
                .isEqualTo(1);
        assertThat(aliasRepository.resolveCanonicalKey(keysBefore.get(absorbedUuid)))
                .contains(keysBefore.get(otherUuid));
        assertKeysUnchanged(keysBefore);

        assertThat(aliasWriter.remove(keysBefore.get(absorbedUuid))).isEqualTo(1);
        assertKeysUnchanged(keysBefore);

        // And keying is unaffected: the same fields still land on the same row, alias or no alias.
        assertThat(upsert(algorithm("RSA", "2048"), null)).isEqualTo(absorbedUuid);
    }

    /**
     * A re-sync that arrives out of order must not invert the window. Keeping {@code first_seen_at} and assigning
     * {@code last_seen_at} looks equivalent only while events arrive in order; a retry or a replayed document can
     * present an older timestamp after a newer one.
     */
    @Test
    void anOutOfOrderResyncStillLeavesARealSeenAtWindow() {
        UUID assetUuid = upsert(rsa2048(), null);
        OffsetDateTime later = OffsetDateTime.now();
        OffsetDateTime earlier = later.minusDays(2);

        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), null, null, later);
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), null, null, earlier);

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(stored.getFirstSeenAt())
                .describedAs("an older event moves first_seen_at earlier")
                .isCloseTo(earlier, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getLastSeenAt())
                .describedAs("an older event does not drag last_seen_at back")
                .isCloseTo(later, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getLastSeenAt())
                .describedAs("the window is never inverted")
                .isAfterOrEqualTo(stored.getFirstSeenAt());
    }

    /**
     * The other half of the out-of-order rule. The window merge alone would leave stale content under a window claiming
     * the newer sync: the row would attest "as of last_seen_at this CBOM said P1" at an instant when it said P2, and
     * the merge election would run on P1. Content follows the newest observation, not the newest arrival.
     */
    @Test
    void aDelayedRetryWidensTheWindowButKeepsTheNewerContent() {
        UUID assetUuid = upsert(rsa2048(), null);
        OffsetDateTime later = OffsetDateTime.now();
        OffsetDateTime earlier = later.minusDays(2);
        Map<String, Object> newer = Map.of("primitive", "signature", "parameterSetIdentifier", "2048");
        Map<String, Object> older = Map.of("primitive", "keyAgree");

        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), newer,
                        List.of(Map.of("location", "a.jar"), Map.of("location", "b.jar")), later);
        sourceWriter.upsertSource(assetUuid, leanCbom.getUuid(), older, List.of(Map.of("location", "c.jar")), earlier);

        CryptoAssetSource stored = source(assetUuid, leanCbom.getUuid());
        assertThat(stored.getFirstSeenAt())
                .describedAs("the older sighting still widens the window")
                .isCloseTo(earlier, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getLastSeenAt()).isCloseTo(later, within(1, ChronoUnit.SECONDS));
        assertThat(stored.getOriginalCryptoProperties())
                .describedAs("a stale arrival must not overwrite the newer payload")
                .containsEntry("primitive", "signature");
        assertThat(stored.getOccurrenceCount())
                .describedAs("the counts move with the payload they describe")
                .isEqualTo(2);
        assertThat(stored.getEvidence()).hasSize(2);
        assertThat(asset(assetUuid).getPropertiesHash())
                .describedAs("the merge election re-derives the same answer, not the stale one")
                .isEqualTo(stored.getPropertiesHash());
    }

    /**
     * The tie must refresh, not freeze. If the ingest path ever derives the seen-at from the document rather than from
     * the extraction run, every re-ingest is a tie -- and a strict comparison would lock the content forever, so a
     * re-extraction under upgraded code could never correct the row.
     */
    @Test
    void aReIngestAtTheSameInstantRefreshesTheContent() {
        UUID assetUuid = upsert(rsa2048(), null);
        OffsetDateTime sameInstant = OffsetDateTime.now();

        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "signature"), List.of(), sameInstant);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), Map.of("primitive", "keyAgree"), List.of(), sameInstant);

        assertThat(source(assetUuid, leanCbom.getUuid()).getOriginalCryptoProperties())
                .containsEntry("primitive", "keyAgree");
    }

    /**
     * A guard is a safety refusal, not a field: {@link CryptoAssetAliasWriter} reads the guard that is on the row now
     * to decide whether a merge is allowed. If ordinary re-ingest could clear it, the refusal would evaporate on the
     * next unguarded report of the same normalized identity.
     */
    @Test
    void aLaterUnguardedReportDoesNotClearASafetyGuard() {
        CryptoAssetIdentityFields bareCnFields = new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE,
                "example.com", null, null, null, null, null, null, null, null);
        UUID bareCn = upsert(bareCnFields, CryptoAssetIdentityGuard.BARE_CN_SUBJECT);

        assertThat(upsert(bareCnFields, null))
                .describedAs("the same normalized identity lands on the same row")
                .isEqualTo(bareCn);
        assertThat(asset(bareCn).getIdentityGuard())
                .describedAs("re-ingest without a guard must not lift one that was set")
                .isEqualTo(CryptoAssetIdentityGuard.BARE_CN_SUBJECT);

        UUID fullDn = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE,
                "CN=example.com,O=Example,C=CZ", null, null, null, null, null, null, null, null), null);
        String bareCnKey = asset(bareCn).getIdentityKey();
        String fullDnKey = asset(fullDn).getIdentityKey();

        assertThatThrownBy(() -> aliasWriter.record(bareCnKey, fullDnKey, "still looks the same", "operator"))
                .describedAs("the refusal survives the re-ingest that would otherwise have cleared the guard")
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("BARE_CN_SUBJECT");
    }

    @Test
    void anAliasIsRefusedWhereASafetyRuleCausedTheSplit() {
        UUID bareCn = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "example.com", null,
                null, null, null, null, null, null, null), CryptoAssetIdentityGuard.BARE_CN_SUBJECT);
        UUID fullDn = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE,
                "CN=example.com,O=Example,C=CZ", null, null, null, null, null, null, null, null), null);
        String bareCnKey = asset(bareCn).getIdentityKey();
        String fullDnKey = asset(fullDn).getIdentityKey();

        assertThatThrownBy(
                () -> aliasWriter.record(bareCnKey, fullDnKey, "looks like the same certificate", "operator"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("BARE_CN_SUBJECT");
        assertThat(aliasRepository.count()).isZero();

        assertThatThrownBy(() -> aliasWriter.record(fullDnKey, bareCnKey, "the other way round", "operator"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("BARE_CN_SUBJECT");
        assertThat(aliasRepository.count()).isZero();
    }

    /**
     * The other half of the guard rule. An alias says this key <em>is</em> another one; a guard says a safety rule
     * requires it to stand alone. Whichever arrives second has to fail, or the inventory ends up holding both
     * statements and neither operator learns they disagreed.
     */
    @Test
    void aGuardIsRefusedWhenAnAliasAlreadyMergesTheKey() {
        CryptoAssetIdentityFields absorbedFields = algorithm("RSA", "2048");
        UUID absorbed = upsert(absorbedFields, null);
        UUID canonical = upsert(algorithm("RSA", "4096"), null);
        aliasWriter.record(asset(absorbed).getIdentityKey(), asset(canonical).getIdentityKey(), "same key", "operator");

        assertThatThrownBy(() -> upsert(absorbedFields, CryptoAssetIdentityGuard.REFUTED_OID))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("REFUTED_OID");
        assertThat(asset(absorbed).getIdentityGuard()).describedAs("the refused guard left no trace").isNull();
    }

    @Test
    void aGuardIsRefusedWhenAnotherAssetIsMergedIntoTheKey() {
        UUID absorbed = upsert(algorithm("RSA", "2048"), null);
        CryptoAssetIdentityFields canonicalFields = algorithm("RSA", "4096");
        UUID canonical = upsert(canonicalFields, null);
        aliasWriter.record(asset(absorbed).getIdentityKey(), asset(canonical).getIdentityKey(), "same key", "operator");

        assertThatThrownBy(() -> upsert(canonicalFields, CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("REFUTED_CERTIFICATE_DIGEST");
        assertThat(asset(canonical).getIdentityGuard()).isNull();
    }

    @Test
    void anUnguardedUpsertIsUnaffectedByAnAlias() {
        CryptoAssetIdentityFields absorbedFields = algorithm("RSA", "2048");
        UUID absorbed = upsert(absorbedFields, null);
        UUID canonical = upsert(algorithm("RSA", "4096"), null);
        aliasWriter.record(asset(absorbed).getIdentityKey(), asset(canonical).getIdentityKey(), "same key", "operator");

        assertThat(upsert(absorbedFields, null))
                .describedAs("only a guard contradicts an alias; ordinary re-ingest does not")
                .isEqualTo(absorbed);
    }

    /**
     * Eleven producer-supplied text columns are indexed, and a btree tuple wider than roughly 2704 bytes is refused by
     * the index rather than by validation. The OID has a realistic bound, so it is capped at the column, where the
     * error names the column instead of naming an index nobody asked about.
     *
     * <p>
     * The refusal has to come from the writer, not from the CHECK. A failed CHECK makes PostgreSQL emit
     * {@code DETAIL: Failing row contains (...)}, and Hibernate logs the driver's message at ERROR before any catch
     * runs -- so a bound enforced only at the column turns an over-long name, which a producer chooses, into a way to
     * make the platform log an identity key.
     */
    @Test
    void anOverlongOidIsRefusedBeforeItReachesTheDatabase() {
        CryptoAssetIdentityFields overlong = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "RSA",
                "1.2.840.113549".repeat(40), null, null, null, null, null, null, null);

        assertThatThrownBy(() -> upsert(overlong, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("longer than 255 characters");
        assertThat(assetRepository.count()).isZero();
    }

    @Test
    void anOverlongNameIsRefusedBeforeItReachesTheDatabase() {
        CryptoAssetIdentityFields overlong = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM,
                "A".repeat(1025), null, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> upsert(overlong, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("longer than 1024 characters");
        assertThat(assetRepository.count()).isZero();
    }

    /**
     * The CHECK is the backstop, so it has to still be there. Addressed through the repository, which is the one way to
     * reach the column without passing the writer's pre-check first.
     *
     * <p>
     * The repository write runs inside an explicit transaction because it is {@code @Modifying}: without one, Hibernate
     * refuses the statement before it is sent and the failure is an {@code InvalidDataAccessApiUsageException} from the
     * JPA layer, not the constraint doing its job. A type-only assertion would not have told the two apart -- what has
     * to be proven here is that the refusal came from the column.
     */
    @Test
    void theColumnStillRefusesAnOverlongNameThatBypassesTheWriter() {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> transaction
                .executeWithoutResult(status -> assetRepository
                        .upsertIdentity(UUID.randomUUID(), "b".repeat(64), IdentityRuleset.VERSION,
                                CryptographicAssetType.ALGORITHM.name(), "A".repeat(1025), null, null, null, null, null,
                                null, null, null, null)))
                .isInstanceOf(DataIntegrityViolationException.class)
                .satisfies(failure -> assertThat(CryptoAssetConstraintTranslator.constraintNameOf(failure))
                        .describedAs("the refusal must come from the name bound, not "
                                + "from another constraint or from the JPA layer")
                        .contains("ck_crypto_asset_name_length"));
        assertThat(assetRepository.count()).isZero();
    }

    @Test
    void aNameAtTheLimitIsAccepted() {
        CryptoAssetIdentityFields atLimit = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM,
                "A".repeat(1024), null, null, null, null, null, null, null, null);

        assertThat(upsert(atLimit, null)).isNotNull();
    }

    @Test
    void anOidAtTheLimitIsAccepted() {
        CryptoAssetIdentityFields atLimit = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "RSA",
                "1".repeat(255), null, null, null, null, null, null, null);

        assertThat(upsert(atLimit, null)).isNotNull();
    }

    /**
     * A wrong canonical key used to reach the foreign key as an untranslated {@code DataIntegrityViolationException},
     * which the generic handler logs with the driver's DETAIL -- and that DETAIL quotes the missing identity key. The
     * refusal has to come from us, with a sentence we wrote, so the driver never writes one.
     */
    @Test
    void anAliasIsRefusedWhenTheCanonicalAssetDoesNotExist() {
        UUID absorbed = upsert(algorithm("RSA", "2048"), null);
        String absorbedKey = asset(absorbed).getIdentityKey();

        assertThatThrownBy(() -> aliasWriter.record(absorbedKey, "0".repeat(64), "typo", "operator"))
                .isInstanceOf(ValidationException.class)
                .isNotInstanceOf(DataIntegrityViolationException.class);
        assertThat(aliasRepository.count()).isZero();
    }

    @Test
    void anAliasIsRefusedWhenItWouldFormAChainOrPointAtItself() {
        UUID first = upsert(algorithm("RSA", "2048"), null);
        UUID second = upsert(algorithm("RSA", "4096"), null);
        UUID third = upsert(algorithm("RSA", "8192"), null);
        String firstKey = asset(first).getIdentityKey();
        String secondKey = asset(second).getIdentityKey();
        String thirdKey = asset(third).getIdentityKey();

        aliasWriter.record(firstKey, secondKey, "duplicate", "operator");

        assertThatThrownBy(() -> aliasWriter.record(secondKey, thirdKey, "chained", "operator"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("chains");
        assertThatThrownBy(() -> aliasWriter.record(thirdKey, thirdKey, "itself", "operator"))
                .isInstanceOf(ValidationException.class);

        // The other direction, which only requireNoChain's second branch can refuse: pointing at a key that is itself
        // absorbed. The case above is caught by the first branch, so without this one that branch could be deleted
        // and the whole build would stay green while the chain C -> A -> B became recordable.
        assertThatThrownBy(() -> aliasWriter.record(thirdKey, firstKey, "pointing at an absorbed key", "operator"))
                .describedAs("the acceptance criterion promises refusal in either direction")
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("itself absorbed");

        assertThat(aliasRepository.findAll()).extracting(CryptoAssetAlias::getAbsorbedKey).containsExactly(firstKey);
    }

    @Test
    void anAliasIsRefusedWhenThereIsNothingToDecideAboutOrAKeyIsMissing() {
        String existing = asset(upsert(rsa2048(), null)).getIdentityKey();

        assertThatThrownBy(() -> aliasWriter.record("never-ingested", existing, "typo", "operator"))
                .describedAs("a redirect from a key no asset and no alias carries is one no ingest can follow")
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("no cryptographic asset to absorb");
        assertThatThrownBy(() -> aliasWriter.record(null, existing, "typo", "operator"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("two distinct asset keys");
        assertThatThrownBy(() -> aliasWriter.record(existing, null, "typo", "operator"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("two distinct asset keys");
        assertThat(aliasRepository.count()).isZero();
    }

    @Test
    void removingAnAliasThatIsNotThereChangesNothing() {
        assertThat(aliasWriter.remove("never-recorded")).isZero();
    }

    // ---- CBOM-level asset bookkeeping ----

    @Test
    void theSyncStateWriterMovesACbomThroughIngest() {
        assertThat(cbom(leanCbom.getUuid()).getAssetSyncState())
                .describedAs("an existing header-only row has never had its assets ingested")
                .isEqualTo(CbomAssetSyncState.PENDING);

        syncStateWriter.markInProgress(leanCbom.getUuid());
        assertThat(cbom(leanCbom.getUuid()).getAssetSyncState()).isEqualTo(CbomAssetSyncState.IN_PROGRESS);

        syncStateWriter.markFailed(leanCbom.getUuid(), "The CBOM document could not be parsed.");
        Cbom failed = cbom(leanCbom.getUuid());
        assertThat(failed.getAssetSyncState()).isEqualTo(CbomAssetSyncState.FAILED);
        assertThat(failed.getAssetSyncError()).isEqualTo("The CBOM document could not be parsed.");
        assertThat(failed.getAssetsSyncedAt()).isNull();

        OffsetDateTime syncedAt = OffsetDateTime.now();
        syncStateWriter.markSynced(leanCbom.getUuid(), syncedAt);
        Cbom synced = cbom(leanCbom.getUuid());
        assertThat(synced.getAssetSyncState()).isEqualTo(CbomAssetSyncState.SYNCED);
        assertThat(synced.getAssetSyncError()).describedAs("a success clears the previous failure").isNull();
        assertThat(synced.getAssetsSyncedAt()).isNotNull();
    }

    /**
     * The case a {@code (uuid)} arbiter missed. Upload, delete, upload again under a new uuid with the same serial
     * number and version -- which the create path allows, because it looks only at the live table -- then delete again.
     * The second tombstone collides on the serial-and-version unique, and because this writer is REQUIRED that
     * violation used to roll back the deletion calling it, leaving the re-created CBOM undeletable through the API.
     */
    @Test
    void tombstoningARecreatedCbomDoesNotViolateTheSerialAndVersionUnique() {
        tombstoneWriter.record(leanCbom.getUuid(), "urn:uuid:lean", 1, OffsetDateTime.now(), "operator");
        UUID recreated = cbom("urn:uuid:recreated", 9).getUuid();

        tombstoneWriter.record(recreated, "urn:uuid:lean", 1, OffsetDateTime.now(), "operator");

        assertThat(tombstoneRepository.count())
                .describedAs("the second tombstone is a no-op, not a violation that rolls the deletion back")
                .isEqualTo(1);
        assertThat(tombstoneRepository.findById(leanCbom.getUuid()))
                .describedAs("the first record of a deletion is the true one")
                .isPresent();
        assertThat(tombstoneRepository.findById(recreated)).isEmpty();
    }

    @Test
    void aDeletedCbomIsTombstonedOnceAndByItsOwnUuid() {
        tombstoneWriter.record(leanCbom.getUuid(), "urn:uuid:lean", 1, OffsetDateTime.now(), "operator");
        tombstoneWriter.record(leanCbom.getUuid(), "urn:uuid:lean", 1, OffsetDateTime.now(), "someone else");

        assertThat(tombstoneRepository.findAll())
                .describedAs("a retried deletion has nothing to add to the first record of it")
                .singleElement()
                .satisfies(tombstone -> {
                    assertThat(tombstone.getUuid()).isEqualTo(leanCbom.getUuid());
                    assertThat(tombstone.getDeletedBy()).isEqualTo("operator");
                });
        assertThat(tombstoneRepository.existsBySerialNumberAndVersion("urn:uuid:lean", 1)).isTrue();
        assertThat(tombstoneRepository.findById(leanCbom.getUuid())).map(CbomTombstone::getVersion).contains(1);
    }

    // ---- helpers ----

    private void assertKeysUnchanged(Map<UUID, String> keysBefore) {
        keysBefore
                .forEach((uuid, key) -> assertThat(asset(uuid).getIdentityKey())
                        .describedAs("no alias operation may move an asset's identity")
                        .isEqualTo(key));
    }

    private static CryptoAssetIdentityFields rsa2048() {
        return algorithm("RSA", "2048");
    }

    private static CryptoAssetIdentityFields algorithm(String name, String parameterSet) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null,
                name.toLowerCase(java.util.Locale.ROOT), "signature", parameterSet, null, null, null, null);
    }

    private CryptoAsset asset(UUID uuid) {
        return assetRepository.findById(uuid).orElseThrow();
    }

    private CryptoAssetSource source(UUID assetUuid, UUID cbomUuid) {
        return sourceRepository.findByAssetUuidAndCbomUuid(assetUuid, cbomUuid).orElseThrow();
    }

    private Cbom cbom(UUID uuid) {
        return cbomRepository.findById(uuid).orElseThrow();
    }

    private Cbom cbom(String serialNumber, int version) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.7");
        Optional<Cbom> saved = Optional.of(cbomRepository.save(cbom));
        return saved.orElseThrow();
    }

    /**
     * Upserts through the writer with a fixture key derived from the fields.
     *
     * <p>
     * The writer no longer computes the key -- the extraction pipeline does, from the whole component -- so a
     * persistence test has to supply one. {@link AssetRowKeys} makes it a stable function of the normalized fields,
     * which is what keeps every dedup assertion below meaning what it meant before.
     */
    private UUID upsert(CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard);
    }
}
