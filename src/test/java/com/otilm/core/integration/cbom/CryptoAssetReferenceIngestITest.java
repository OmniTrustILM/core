package com.otilm.core.integration.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.ingest.CbomAssetDetachService;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.pqc.PqcVerdictSweeper;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.CryptoAssetReference;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetReferenceRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The references a certificate and a protocol make are resolved while the document is in hand and recorded against the
 * source that made them.
 */
class CryptoAssetReferenceIngestITest extends BaseSpringBootTest {

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-09-29T10:00:00Z");

    private static final CbomSyncPolicy POLICY = CbomSyncPolicy.DEFAULTS;

    private static final String KEY = """
            {"type":"cryptographic-asset","bom-ref":"key-rsa","name":"RSA-2048 public key",
             "cryptoProperties":{"assetType":"related-crypto-material",
              "relatedCryptoMaterialProperties":{"type":"public-key","size":2048}}}""";

    private static final String SIGNATURE = """
            {"type":"cryptographic-asset","bom-ref":"alg-sig","name":"SHA256withRSA",
             "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"signature"}}}""";

    private static final String AES = """
            {"type":"cryptographic-asset","bom-ref":"alg-aes","name":"AES-128-GCM",
             "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"ae"}}}""";

    private static final String PROTOCOL = """
            {"type":"cryptographic-asset","bom-ref":"tls","name":"TLSv1.3",
             "cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.3",
              "cipherSuites":[{"name":"TLS_AES_128_GCM_SHA256","identifiers":["0x13","0x01"],
                               "algorithms":["alg-aes","not-in-this-document"]}]}}}""";

    @Autowired
    private CbomAssetIngestService ingestService;

    @Autowired
    private CbomAssetDetachService detachService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CryptoAssetSourceRepository sourceRepository;

    @Autowired
    private CryptoAssetReferenceRepository referenceRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private PqcVerdictSweeper sweeper;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private Cbom cbom;

    @BeforeEach
    void seedCbom() {
        Cbom header = new Cbom();
        header.setSerialNumber("urn:uuid:references");
        header.setVersion(1);
        header.setSpecVersion("1.7");
        cbom = cbomRepository.save(header);
    }

    @Test
    void aCertificateAndAProtocolRecordWhatTheirReferencesResolveTo() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\",\"signatureAlgorithmRef\":\"alg-sig\""), KEY, SIGNATURE,
                AES, PROTOCOL);

        assertThat(referencesOf(CryptographicAssetType.CERTIFICATE))
                .extracting(CryptoAssetReference::getKind, CryptoAssetReference::getOrdinal,
                        CryptoAssetReference::getRef, CryptoAssetReference::getTargetAssetUuid)
                .containsExactly(
                        tuple(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, 0, "key-rsa", named("rsa-2048 public key")),
                        tuple(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, 0, "alg-sig", named("sha256withrsa")));
        assertThat(referencesOf(CryptographicAssetType.PROTOCOL))
                .extracting(CryptoAssetReference::getOrdinal, CryptoAssetReference::getRef,
                        CryptoAssetReference::getSuite, CryptoAssetReference::getTargetAssetUuid)
                .containsExactly(tuple(0, "alg-aes", "0x1301", named("aes-128-gcm")),
                        tuple(1, "not-in-this-document", "0x1301", null));
    }

    /**
     * The ingest stamps the referrers after their references, so a certificate reads its key's verdict and a protocol
     * with a suite algorithm outside the document defers rather than reading ready.
     */
    @Test
    void theIngestStampsCertificatesAndProtocolsFromWhatTheyReference() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\",\"signatureAlgorithmRef\":\"alg-sig\""), KEY, SIGNATURE,
                AES, PROTOCOL);

        CryptoAsset key = assetRepository.findById(named("rsa-2048 public key")).orElseThrow();
        CryptoAsset certificate = only(CryptographicAssetType.CERTIFICATE);
        assertThat(key.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(certificate.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(certificate.getPqcRuleId()).startsWith("CERT-");
        assertThat(certificate.getPqcReferencedAssetUuid()).isNotNull();
        assertThat(certificate.getPqcEvaluatedFields()).containsEntry("subjectPublicKeyRef", "key-rsa");

        CryptoAsset protocol = only(CryptographicAssetType.PROTOCOL);
        assertThat(protocol.getPqcRuleId()).isEqualTo("PROTOCOL-SUITE-UNRESOLVED");
        assertThat(protocol.getPqcVerdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(protocol.getPqcEvaluatedFields()).containsEntry("unresolvedRefs", List.of("not-in-this-document"));
    }

    /** A referrer's verdict is its target's, so a target evaluated after it puts it back on the sweep's work list. */
    @Test
    void aTargetEvaluatedAfterItsReferrerPutsTheReferrerBackOnTheWorkList() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY);
        UUID certificate = only(CryptographicAssetType.CERTIFICATE).getUuid();
        UUID key = named("rsa-2048 public key");
        assertThat(workList()).doesNotContain(certificate, key);
        assertThat(assetRepository.findStaleVerdictUuids(List.of(certificate, key))).isEmpty();

        assetWriter.applyPqcVerdict(key, PqcVerdict.READY, "LATER-RULE", "re-evaluated", Map.of());

        assertThat(workList()).contains(certificate);
        assertThat(assetRepository.findStaleVerdictUuids(List.of(certificate, key))).containsExactly(certificate);
    }

    /**
     * A rule change re-offers every row, so one sweep batch restamps a certificate and its key in one transaction: the
     * certificate is decided from the key's verdict as read before the batch, and both land at one
     * {@code CURRENT_TIMESTAMP}. The certificate must come back once the key has moved, however the two stamps compare.
     */
    @Test
    void aCertificateDecidedFromItsKeysSupersededVerdictComesBackAfterTheSameSweepRestampsTheKey() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY);
        UUID certificate = only(CryptographicAssetType.CERTIFICATE).getUuid();
        UUID key = named("rsa-2048 public key");
        stampAsIfByAnOlderRuleSet(key, "READY", "AN-OLDER-RULE", null);
        stampAsIfByAnOlderRuleSet(certificate, "READY", "CERT-SUBJECT-KEY", key + ":READY:AN-OLDER-RULE");

        sweeper.sweep();

        assertThat(assetRepository.findById(key).orElseThrow().getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(assetRepository.findById(certificate).orElseThrow().getPqcRuleId())
                .describedAs("decided from the key's verdict as it stood before the batch: ready, so deferred for "
                        + "the missing signature algorithm")
                .isEqualTo("CERT-NO-SIGNATURE-RECORDED");
        assertThat(workList())
                .describedAs("the key moved under the certificate's verdict")
                .containsExactly(certificate);

        sweeper.sweep();

        assertThat(assetRepository.findById(certificate).orElseThrow().getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(workList()).isEmpty();
    }

    /** A target that leaves the inventory changes what the referrer's verdict rests on, so the referrer comes back. */
    @Test
    void aTargetThatLeavesTheInventoryPutsTheReferrerBackOnTheWorkList() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY);
        UUID certificate = only(CryptographicAssetType.CERTIFICATE).getUuid();
        UUID key = named("rsa-2048 public key");
        assertThat(workList()).isEmpty();

        jdbcTemplate.update("DELETE FROM " + dbSchema + ".crypto_asset WHERE uuid = ?", key);

        assertThat(workList()).containsExactly(certificate);
        sweeper.sweep();
        assertThat(assetRepository.findById(certificate).orElseThrow().getPqcRuleId())
                .isEqualTo("CERT-REFERENCE-UNRESOLVED");
    }

    /** An older observation of the same document keeps neither its payload nor its references. */
    @Test
    void anOlderReplayLeavesTheReferencesOfTheNewerObservation() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY);

        JsonNode older = CbomIngestTestFixtures
                .read("{\"components\":["
                        + certificate("\"subjectPublicKeyRef\":\"key-rsa\",\"signatureAlgorithmRef\":\"alg-sig\"") + ","
                        + KEY + "," + SIGNATURE + "]}");
        ingestService.ingest(cbom.getUuid(), older, NOW.minusDays(1), POLICY);

        assertThat(referencesOf(CryptographicAssetType.CERTIFICATE))
                .extracting(CryptoAssetReference::getKind)
                .containsExactly(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY);
    }

    /** What a rule-change migration leaves: a verdict from the old rules, on a row whose revision it advanced. */
    private void stampAsIfByAnOlderRuleSet(UUID uuid, String verdict, String ruleId, String referenceBasis) {
        jdbcTemplate
                .update("UPDATE " + dbSchema + ".crypto_asset SET pqc_verdict = ?, pqc_rule_id = ?, "
                        + "pqc_reference_basis = ?, pqc_evaluated_revision = input_revision, "
                        + "input_revision = input_revision + 1 WHERE uuid = ?", verdict, ruleId, referenceBasis, uuid);
    }

    /**
     * A payload write whose transaction began before a sweep's and committed after it: its {@code i_upd} is earlier
     * than the stamp's {@code pqc_evaluated_at}. Staged by pushing the stamp's time forward, which is the state such a
     * pair leaves. The row must come back, because the verdict describes a revision it no longer has.
     */
    @Test
    void anInputWriteStampedEarlierThanTheVerdictStillPutsTheRowBackOnTheWorkList() {
        ingest(KEY);
        UUID key = named("rsa-2048 public key");
        jdbcTemplate
                .update("UPDATE " + dbSchema + ".crypto_asset SET pqc_evaluated_at = CURRENT_TIMESTAMP + INTERVAL "
                        + "'1 day' WHERE uuid = ?", key);
        assertThat(workList()).isEmpty();

        sourceWriter
                .upsertSource(key, cbom.getUuid(),
                        Map.of("relatedCryptoMaterialProperties", Map.of("type", "public-key", "size", 4096)),
                        List.of(), NOW.plusDays(1));

        assertThat(workList()).describedAs("the payload moved after the verdict was taken").contains(key);
    }

    /** The ingest takes row locks in the order the database sorts uuids, which is the sweep's order. */
    @Test
    void theIngestOrdersUuidsTheWayTheDatabaseDoes() {
        List<UUID> uuids = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            uuids.add(UUID.randomUUID());
        }
        uuids.add(UUID.fromString("7fffffff-ffff-4fff-bfff-ffffffffffff"));
        uuids.add(UUID.fromString("80000000-0000-4000-8000-000000000000"));

        List<UUID> byDatabase = jdbcTemplate
                .queryForList("SELECT u FROM unnest(CAST(? AS uuid[])) AS u ORDER BY u", UUID.class,
                        (Object) uuids.stream().map(UUID::toString).toArray(String[]::new));

        assertThat(uuids.stream().sorted(CbomAssetIngestService.DATABASE_UUID_ORDER).toList()).isEqualTo(byDatabase);
    }

    /**
     * A key in a later batch than its certificate has no row until that batch lands, which is why the references are
     * written after every batch rather than inside one.
     */
    @Test
    void aCertificateResolvesAKeyThatLandsInALaterBatch() {
        JsonNode document = CbomIngestTestFixtures
                .read("{\"components\":[" + certificate("\"subjectPublicKeyRef\":\"key-rsa\"") + "," + KEY + "]}");
        assertThat(ingestService.ingest(cbom.getUuid(), document, NOW, CbomIngestTestFixtures.policy(1)))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);

        assertThat(referencesOf(CryptographicAssetType.CERTIFICATE))
                .extracting(CryptoAssetReference::getTargetAssetUuid)
                .containsExactly(named("rsa-2048 public key"));
        assertThat(only(CryptographicAssetType.CERTIFICATE).getPqcRuleId()).isEqualTo("CERT-SUBJECT-KEY");
    }

    /**
     * The key-exchange gate reads a target's primitive, which a later report can fill in without moving its verdict, so
     * the primitive is part of what the protocol's verdict rests on.
     */
    @Test
    void aTargetWhosePrimitiveChangesPutsTheProtocolBackOnTheWorkList() {
        ingest(AES, PROTOCOL.replace(",\"not-in-this-document\"", ""));
        UUID protocol = only(CryptographicAssetType.PROTOCOL).getUuid();
        assertThat(only(CryptographicAssetType.PROTOCOL).getPqcRuleId()).isEqualTo("PROTOCOL-NO-KEY-EXCHANGE");
        assertThat(workList()).isEmpty();

        jdbcTemplate
                .update("UPDATE " + dbSchema + ".crypto_asset SET primitive = 'kem' WHERE uuid = ?",
                        named("aes-128-gcm"));

        assertThat(workList()).contains(protocol);
    }

    /** A 1.7 entry wins over the 1.6 field, and two entries of one kind name nothing. */
    @Test
    void twoRelatedKeysOfOneCertificateResolveToNothing() {
        ingest(certificate("\"subjectPublicKeyRef\":\"alg-sig\",\"relatedCryptographicAssets\":["
                + "{\"type\":\"publicKey\",\"ref\":\"key-rsa\"},{\"type\":\"public-key\",\"ref\":\"alg-sig\"}]"), KEY,
                SIGNATURE);

        assertThat(referencesOf(CryptographicAssetType.CERTIFICATE))
                .extracting(CryptoAssetReference::getRef, CryptoAssetReference::getTargetAssetUuid)
                .containsExactly(tuple("key-rsa", null), tuple("alg-sig", null));
    }

    @Test
    void aReIngestReplacesTheReferencesTheDocumentNoLongerMakes() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\",\"signatureAlgorithmRef\":\"alg-sig\""), KEY,
                SIGNATURE);

        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY, SIGNATURE);

        assertThat(referencesOf(CryptographicAssetType.CERTIFICATE))
                .extracting(CryptoAssetReference::getKind)
                .containsExactly(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY);
    }

    @Test
    void withdrawingTheDocumentTakesItsReferencesWithIt() {
        ingest(certificate("\"subjectPublicKeyRef\":\"key-rsa\""), KEY);
        assertThat(referenceRepository.count()).isEqualTo(1);

        detachService.withdraw(cbom.getUuid(), POLICY.assetBatchSize());

        assertThat(referenceRepository.count()).isZero();
    }

    private void ingest(String... components) {
        JsonNode document = CbomIngestTestFixtures.read("{\"components\":[" + String.join(",", components) + "]}");
        assertThat(ingestService.ingest(cbom.getUuid(), document, NOW, POLICY))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
    }

    private static String certificate(String members) {
        return "{\"type\":\"cryptographic-asset\",\"bom-ref\":\"cert\",\"name\":\"example.com\","
                + "\"cryptoProperties\":{\"assetType\":\"certificate\",\"certificateProperties\":{"
                + "\"subjectName\":\"CN=example.com,O=Example\",\"issuerName\":\"CN=Example CA,O=Example\"," + members
                + "}}}";
    }

    private List<CryptoAssetReference> referencesOf(CryptographicAssetType type) {
        CryptoAsset asset = assetRepository
                .findAll()
                .stream()
                .filter(row -> row.getAssetType() == type)
                .findFirst()
                .orElseThrow();
        UUID source = sourceRepository
                .findByAssetUuidAndCbomUuid(asset.getUuid(), cbom.getUuid())
                .orElseThrow()
                .getUuid();
        return referenceRepository
                .findAll()
                .stream()
                .filter(reference -> reference.getSourceUuid().equals(source))
                .sorted(Comparator
                        .comparing(CryptoAssetReference::getKind)
                        .thenComparing(CryptoAssetReference::getOrdinal))
                .toList();
    }

    private CryptoAsset only(CryptographicAssetType type) {
        return assetRepository.findAll().stream().filter(row -> row.getAssetType() == type).findFirst().orElseThrow();
    }

    private List<UUID> workList() {
        return assetRepository.staleVerdictRows(new UUID(0L, 0L), 100).stream().map(PqcStaleVerdictRow::uuid).toList();
    }

    private UUID named(String name) {
        return assetRepository
                .findAll()
                .stream()
                .filter(row -> name.equals(row.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no asset named " + name))
                .getUuid();
    }
}
