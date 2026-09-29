package com.otilm.core.integration.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.ingest.CbomAssetDetachService;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.CryptoAssetReference;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetReferenceRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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
