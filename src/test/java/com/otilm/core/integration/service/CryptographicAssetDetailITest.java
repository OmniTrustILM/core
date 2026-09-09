package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetEvidenceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetSourceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.OccurrenceEvidenceCapper;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * The detail operation ({@link CryptographicAssetExternalService#getCryptographicAsset}) end to end, through the
 * service interface: the elected-payload-beside-originals contract that is core#2145's own acceptance criterion,
 * verdict provenance, refuted-OID flagging, capped-evidence-with-true-count, normalized-field presence, and the
 * not-found path.
 */
class CryptographicAssetDetailITest extends BaseSpringBootTest {

    private static final OffsetDateTime NOW = OffsetDateTime.now();

    @Autowired
    private CryptographicAssetExternalService cryptographicAssetService;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetRepository cryptoAssetRepository;

    @Autowired
    private CryptoAssetSourceRepository cryptoAssetSourceRepository;

    /**
     * The detail endpoint's distinguishing obligation (core#2145 AC): the elected representative payload is one
     * source's payload verbatim, served BESIDE every source's original -- a sparse but crucial observation can lose the
     * election to a richer generic one, and the original must remain readable on the wire when it does.
     */
    @Test
    void servesElectedPayloadBesideDisagreeingPerSourceOriginals() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-128-GCM"), null);
        Cbom rich = newCbom("urn:uuid:rich");
        Cbom sparse = newCbom("urn:uuid:sparse");
        Map<String, Object> richPayload = Map.of("name", "AES-128-GCM", "primitive", "ae", "mode", "gcm");
        Map<String, Object> sparsePayload = Map.of("name", "AES-128-GCM", "nistQuantumSecurityLevel", 1);
        sourceWriter.upsertSource(assetUuid, rich.getUuid(), richPayload, occurrences("lib/a.c", 10), NOW);
        sourceWriter
                .upsertSource(assetUuid, sparse.getUuid(), sparsePayload, occurrences("lib/b.c", 20),
                        NOW.plusSeconds(5));

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        // election is by leaf count: the rich payload wins and is served verbatim
        assertEquals(richPayload, detail.getElectedPayload());
        // both originals are served beside it, in first-seen order, disagreement intact
        assertEquals(2, detail.getSources().size());
        assertEquals(richPayload, detail.getSources().get(0).getPayload());
        assertEquals(sparsePayload, detail.getSources().get(1).getPayload());
        assertEquals(sparse.getUuid(), detail.getSources().get(1).getCbomUuid());
        assertEquals("urn:uuid:sparse", detail.getSources().get(1).getSerialNumber());
        // the aggregate is the sum across sources: each occurrences() call above seeds exactly one occurrence, so 1 + 1
        assertEquals(2L, detail.getOccurrenceCount());
    }

    @Test
    void rowFieldsMatchTheListContract() throws NotFoundException {
        UUID assetUuid = upsert(fieldsWithOid("AES-256-GCM", "oid-aes-256-gcm"), null);
        Cbom cbom = newCbom("urn:uuid:contract");
        List<Map<String, Object>> threeOccurrences = List
                .of(new HashMap<>(Map.of("location", "src/a.c", "line", 1)),
                        new HashMap<>(Map.of("location", "src/b.c", "line", 2)),
                        new HashMap<>(Map.of("location", "src/c.c", "line", 3)));
        sourceWriter.upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "AES-256-GCM"), threeOccurrences, NOW);
        assetWriter.applyPqcVerdict(assetUuid, PqcVerdict.READY, "rule", "reason", 1, Map.of());

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getUuid()).isEqualTo(assetUuid);
        assertThat(detail.getName()).isEqualTo("aes-256-gcm");
        assertThat(detail.getType()).isEqualTo(CryptographicAssetType.ALGORITHM);
        assertThat(detail.getPqcVerdict()).isEqualTo(PqcVerdict.READY);
        assertThat(detail.getSourceCbomCount()).isEqualTo(1);
        assertThat(detail.getOccurrenceCount()).isEqualTo(3);
        assertThat(detail.isQuarantined()).isFalse();
    }

    @Test
    void servesVerdictProvenanceWhenEvaluated() throws NotFoundException {
        UUID assetUuid = upsert(fields("RSA-2048"), null);
        assetWriter
                .applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "shor-breakable", "RSA is Shor-breakable", 3,
                        Map.of());

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getVerdict()).isNotNull();
        assertThat(detail.getVerdict().getRuleId()).isEqualTo("shor-breakable");
        assertThat(detail.getVerdict().getReason()).isEqualTo("RSA is Shor-breakable");
        assertThat(detail.getVerdict().getRuleSetVersion()).isEqualTo(3);
        assertThat(detail.getVerdict().getDecidedAt()).isNotNull();
        assertThat(detail.getVerdict().getEvaluatedAt()).isNotNull();
        assertThat(detail.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
    }

    @Test
    void omitsVerdictProvenanceWhenNeverEvaluated() throws NotFoundException {
        UUID assetUuid = upsert(fields("ChaCha20-Poly1305"), null);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getVerdict()).isNull();
        assertThat(detail.getPqcVerdict())
                .describedAs("never evaluated -> UNKNOWN, not null")
                .isEqualTo(PqcVerdict.UNKNOWN);
        // the zero-source wire shape: no sources, no elected payload, zero aggregate occurrences
        assertThat(detail.getSources()).isEmpty();
        assertThat(detail.getElectedPayload()).isNull();
        assertThat(detail.getOccurrenceCount()).isZero();
    }

    /**
     * A refuted OID must never be served as fact -- the row's own display name and the per-OID flag both have to say so
     * -- while an unrefuted twin serves its OID as the name fallback exactly like the list contract does.
     */
    @Test
    void flagsARefutedOidAndSuppressesItAsName() throws NotFoundException {
        UUID refuted = upsert(fieldsWithOid(null, "1.2.840.113549.1.1.1"), CryptoAssetIdentityGuard.REFUTED_OID);
        UUID notRefuted = upsert(fieldsWithOid(null, "1.2.840.113549.1.1.2"), null);

        CryptographicAssetDetailDto refutedDetail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(refuted));
        assertThat(refutedDetail.getOids()).hasSize(1);
        assertThat(refutedDetail.getOids().get(0).getOid()).isEqualTo("1.2.840.113549.1.1.1");
        assertThat(refutedDetail.getOids().get(0).isRefuted()).isTrue();
        assertThat(refutedDetail.getName()).describedAs("the refuted OID is never served as the display name").isNull();
        assertThat(cryptoAssetRepository.findByUuid(SecuredUUID.fromUUID(refuted)).orElseThrow().getIdentityGuard())
                .isEqualTo(CryptoAssetIdentityGuard.REFUTED_OID);

        CryptographicAssetDetailDto notRefutedDetail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(notRefuted));
        assertThat(notRefutedDetail.getOids()).hasSize(1);
        assertThat(notRefutedDetail.getOids().get(0).isRefuted()).isFalse();
        assertThat(notRefutedDetail.getName())
                .describedAs("no name recorded -> the OID is the display fallback")
                .isEqualTo("1.2.840.113549.1.1.2");
    }

    @Test
    void servesEmptyOidListWhenNoOidRecorded() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-GCM"), null);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getOids()).isEmpty();
    }

    @Test
    void servesCappedEvidenceWithTrueCount() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-GCM"), null);
        Cbom cbom = newCbom("urn:uuid:capped");
        List<Map<String, Object>> manyOccurrences = new ArrayList<>();
        for (int i = 0; i < 55; i++) {
            manyOccurrences.add(Map.of("location", "src/f" + i + ".c", "line", i));
        }
        sourceWriter.upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "AES-GCM"), manyOccurrences, NOW);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).hasSize(1);
        CryptographicAssetSourceDto source = detail.getSources().get(0);
        assertThat(source.getEvidence())
                .describedAs("evidence is capped even though every occurrence was reported")
                .hasSize(OccurrenceEvidenceCapper.MAX_OCCURRENCES);
        assertThat(source.getOccurrenceCount()).describedAs("the true, unclipped count is still served").isEqualTo(55);
        assertThat(source.getEvidence().get(0).getLocation()).isEqualTo("src/f0.c");
        assertThat(source.getEvidence().get(0).getLine()).isEqualTo(0);
    }

    /**
     * F5: producers occasionally emit a numeric evidence field as a string, or a textual one as a number; the DTO must
     * still serve the value rather than let a type mismatch drop it silently. location is additionally
     * contract-REQUIRED, so an occurrence that lacks it entirely must still serve {@code ""}, never {@code null}.
     *
     * <p>
     * Seeded by saving the source row directly rather than through {@link CryptoAssetSourceWriter}:
     * {@code OccurrenceEvidenceCapper#sanitizeLocation} forces a non-string {@code location} to {@code ""} at write
     * time, so a stored numeric location can only be reached this way -- which is the point: this proves
     * {@code toEvidenceDto}'s own coercion against whatever shape is actually in the column, independent of what
     * today's writer happens to produce.
     */
    @Test
    void evidenceFieldsCoerceNumericStringsAndNumbers() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-EVIDENCE-COERCE"), null);
        Cbom cbom = newCbom("urn:uuid:evidence-coerce");
        Map<String, Object> occurrence = new HashMap<>();
        occurrence.put("location", 123);
        occurrence.put("line", "42");
        occurrence.put("offset", 7);
        Map<String, Object> occurrenceWithoutLocation = new HashMap<>();
        occurrenceWithoutLocation.put("line", 1);
        CryptoAssetSource source = new CryptoAssetSource();
        source.setAssetUuid(assetUuid);
        source.setCbomUuid(cbom.getUuid());
        source.setOccurrenceCount(2);
        source.setPropertiesLeafCount(0);
        source.setFirstSeenAt(NOW);
        source.setLastSeenAt(NOW);
        source.setEvidence(List.of(occurrence, occurrenceWithoutLocation));
        cryptoAssetSourceRepository.save(source);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        List<CryptographicAssetEvidenceDto> servedEvidence = detail.getSources().get(0).getEvidence();
        CryptographicAssetEvidenceDto evidence = servedEvidence.get(0);
        assertThat(evidence.getLocation()).isEqualTo("123");
        assertThat(evidence.getLine()).isEqualTo(42);
        assertThat(evidence.getOffset()).isEqualTo(7);
        assertThat(servedEvidence.get(1).getLocation())
                .describedAs("location is REQUIRED; an occurrence with no location key must not serve null")
                .isEqualTo("");
    }

    /**
     * F1: sources belong to the CBOM resource -- a caller denied CBOM object access must not read a contributing
     * document's serialNumber, version, source or payload through the detail endpoint, even though cryptoAssets:detail
     * itself is granted. The row-level badges stay global: they reconcile with the list, which is scoped by
     * CRYPTO_ASSET, not CBOM. electedPayload is one document's payload verbatim, so it is gated the same way sources[]
     * is, even though it is served from the asset row rather than a source row.
     */
    @Test
    void deniedCbomAccessHidesSourcesButKeepsGlobalBadges() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-CBOM-SCOPE"), null);
        Cbom cbomA = newCbom("urn:uuid:scope-a");
        Cbom cbomB = newCbom("urn:uuid:scope-b");
        sourceWriter
                .upsertSource(assetUuid, cbomA.getUuid(), Map.of("name", "AES-CBOM-SCOPE"), occurrences("a.c", 1), NOW);
        sourceWriter
                .upsertSource(assetUuid, cbomB.getUuid(), Map.of("name", "AES-CBOM-SCOPE"), occurrences("b.c", 2),
                        NOW.plusSeconds(1));

        denyObjectAccess(Resource.CBOM, ResourceAction.LIST);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).isEmpty();
        assertThat(detail.getSourceCbomCount()).isEqualTo(2);
        assertThat(detail.getOccurrenceCount()).isEqualTo(2L);
        assertThat(detail.getElectedPayload())
                .describedAs("the electing document is hidden by the same denial that empties sources[]")
                .isNull();
    }

    /**
     * F1's positive twin for electedPayload: a partial restriction that still leaves the ELECTING document visible
     * serves the payload normally.
     */
    @Test
    void partialCbomRestrictionServesElectedPayloadWhenTheElectingDocumentIsVisible() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-CBOM-ELECT-VISIBLE"), null);
        Cbom richCbom = newCbom("urn:uuid:elect-visible-rich");
        Cbom leanCbom = newCbom("urn:uuid:elect-visible-lean");
        Map<String, Object> richPayload = Map.of("name", "AES-CBOM-ELECT-VISIBLE", "primitive", "ae", "mode", "gcm");
        Map<String, Object> leanPayload = Map.of("name", "AES-CBOM-ELECT-VISIBLE");
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), richPayload, occurrences("rich.c", 1), NOW);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), leanPayload, occurrences("lean.c", 2), NOW.plusSeconds(1));

        forbidCbomObjects(List.of(leanCbom.getUuid()));

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).hasSize(1);
        assertThat(detail.getSources().get(0).getCbomUuid()).isEqualTo(richCbom.getUuid());
        assertThat(detail.getElectedPayload())
                .describedAs("the richest source elects and its document is visible, so the payload is served")
                .isEqualTo(richPayload);
    }

    /**
     * F1's sharp case for electedPayload: the electing (richest) document is HIDDEN while a different, non-electing
     * document is visible. sources[] serves exactly the visible row, but electedPayload must not re-elect among what
     * the caller can see -- election is global and deterministic, not per-caller -- so it is omitted rather than
     * silently substituting the visible document's own payload.
     */
    @Test
    void partialCbomRestrictionOmitsElectedPayloadWhenTheElectingDocumentIsHidden() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-CBOM-ELECT-HIDDEN"), null);
        Cbom richCbom = newCbom("urn:uuid:elect-hidden-rich");
        Cbom leanCbom = newCbom("urn:uuid:elect-hidden-lean");
        Map<String, Object> richPayload = Map.of("name", "AES-CBOM-ELECT-HIDDEN", "primitive", "ae", "mode", "gcm");
        Map<String, Object> leanPayload = Map.of("name", "AES-CBOM-ELECT-HIDDEN");
        sourceWriter.upsertSource(assetUuid, richCbom.getUuid(), richPayload, occurrences("rich.c", 1), NOW);
        sourceWriter
                .upsertSource(assetUuid, leanCbom.getUuid(), leanPayload, occurrences("lean.c", 2), NOW.plusSeconds(1));

        forbidCbomObjects(List.of(richCbom.getUuid()));

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).hasSize(1);
        assertThat(detail.getSources().get(0).getCbomUuid())
                .describedAs("the visible (non-electing) document still serves its own row")
                .isEqualTo(leanCbom.getUuid());
        assertThat(detail.getSources().get(0).getPayload()).isEqualTo(leanPayload);
        assertThat(detail.getElectedPayload())
                .describedAs("must not re-elect onto the visible document's payload -- election is global, not scoped")
                .isNull();
    }

    /**
     * F1's partial-restriction twin: a caller who can see A but not B gets exactly A's row, while the global badges
     * still count both.
     */
    @Test
    void partialCbomRestrictionServesOnlyTheVisibleSource() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-CBOM-PARTIAL"), null);
        Cbom cbomA = newCbom("urn:uuid:partial-a");
        Cbom cbomB = newCbom("urn:uuid:partial-b");
        sourceWriter
                .upsertSource(assetUuid, cbomA.getUuid(), Map.of("name", "AES-CBOM-PARTIAL"), occurrences("a.c", 1),
                        NOW);
        sourceWriter
                .upsertSource(assetUuid, cbomB.getUuid(), Map.of("name", "AES-CBOM-PARTIAL"), occurrences("b.c", 2),
                        NOW.plusSeconds(1));

        forbidCbomObjects(List.of(cbomB.getUuid()));

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).hasSize(1);
        assertThat(detail.getSources().get(0).getCbomUuid()).isEqualTo(cbomA.getUuid());
        assertThat(detail.getSourceCbomCount()).isEqualTo(2);
        assertThat(detail.getOccurrenceCount()).isEqualTo(2L);
    }

    /**
     * F3: the asset-level source fan-out has no cap of its own -- one row per contributing CBOM, unlike the per-source
     * evidence {@link OccurrenceEvidenceCapper} already bounds. 101 lightweight documents is enough to prove the served
     * list stays bounded while sourceCbomCount and occurrenceCount keep the true totals.
     */
    @Test
    void capsServedSourcesButKeepsTheTrueTotals() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES-SOURCE-CAP"), null);
        int total = 101;
        List<UUID> cbomUuidsOldestFirst = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            Cbom cbom = newCbom("urn:uuid:source-cap-" + i);
            cbomUuidsOldestFirst.add(cbom.getUuid());
            sourceWriter
                    .upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "AES-SOURCE-CAP"),
                            occurrences("f" + i + ".c", i), NOW.plusSeconds(i));
        }

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getSources()).hasSize(100);
        assertThat(detail.getSourceCbomCount()).isEqualTo(total);
        assertThat(detail.getOccurrenceCount()).isEqualTo((long) total);
        List<UUID> servedCbomUuids = detail
                .getSources()
                .stream()
                .map(CryptographicAssetSourceDto::getCbomUuid)
                .toList();
        assertThat(servedCbomUuids)
                .describedAs("the cap keeps the oldest-seeded row and drops the newest -- firstSeenAt-ascending order")
                .contains(cbomUuidsOldestFirst.get(0))
                .doesNotContain(cbomUuidsOldestFirst.get(100));
    }

    @Test
    void normalizedFieldsAbsentWhenNothingDerivable() throws NotFoundException {
        UUID assetUuid = upsert(fields("AES"), null);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getNormalizedFields()).isNull();
    }

    @Test
    void normalizedFieldsCarryTheDerivedColumns() throws NotFoundException {
        UUID assetUuid = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA", null, "ecdsa",
                "signature", "P-256", "secp256r1", null, null, null), null);

        CryptographicAssetDetailDto detail = cryptographicAssetService
                .getCryptographicAsset(SecuredUUID.fromUUID(assetUuid));

        assertThat(detail.getNormalizedFields()).isNotNull();
        assertThat(detail.getNormalizedFields().getAlgorithmFamily()).isEqualTo("ecdsa");
        assertThat(detail.getNormalizedFields().getPrimitive()).isEqualTo("signature");
        assertThat(detail.getNormalizedFields().getParameterSet()).isEqualTo("p-256");
        assertThat(detail.getNormalizedFields().getCurve()).isEqualTo("secp256r1");
    }

    @Test
    void throwsNotFoundForAnUnknownUuid() {
        assertThatThrownBy(
                () -> cryptographicAssetService.getCryptographicAsset(SecuredUUID.fromUUID(UUID.randomUUID())))
                .isInstanceOf(NotFoundException.class);
    }

    // ---- helpers ----

    private static CryptoAssetIdentityFields fields(String name) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null, null, null, null, null, null,
                null, null);
    }

    private static CryptoAssetIdentityFields fieldsWithOid(String name, String oid) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, oid, null, null, null, null, null,
                null, null);
    }

    private static List<Map<String, Object>> occurrences(String location, int line) {
        return List.of(new HashMap<>(Map.of("location", location, "line", line)));
    }

    private UUID upsert(CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard);
    }

    private Cbom newCbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }

    /**
     * Stubs the OPA object-access vote for {@code cboms:list} so every uuid in {@code forbidden} is denied while the
     * rest of the CBOM estate stays visible -- the CBOM twin of
     * {@code CryptographicAssetStatisticsITest#forbidCryptoAssetObjects}, needed here because {@link #denyObjectAccess}
     * denies everything and F1's partial-restriction case needs a real, known-size visible subset.
     */
    private void forbidCbomObjects(List<UUID> forbidden) {
        OpaObjectAccessResult partial = new OpaObjectAccessResult();
        partial.setActionAllowedForGroupOfObjects(true);
        partial.setAllowedObjects(List.of());
        partial.setForbiddenObjects(forbidden.stream().map(UUID::toString).toList());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.CBOM.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.LIST.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(partial);
    }
}
