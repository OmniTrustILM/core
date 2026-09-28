package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CertificateController;
import com.otilm.api.model.client.certificate.CertificateKeystoreRequestDto;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.container.ContainerFixtures;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.ExportEnvelopeFixtures;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.builders.CertificateBuilder;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** A certificate downloaded with its chain and its private key, as the key's v2 connector exports the key. */
@SpringBootTest
class CertificateKeystoreITest extends BaseSpringBootTest {

    private static final String PASSPHRASE = "correct horse battery staple";

    private static Chain chain;

    @Autowired
    private CertificateController certificateController;
    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository keyEventHistoryRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;
    @Autowired
    private AuditLogRepository auditLogRepository;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private CryptographicKey key;
    private CryptographicKeyItem privateItem;
    private CryptographicKeyItem publicItem;
    private Certificate intermediate;
    private Certificate leaf;

    @BeforeAll
    static void keys() throws Exception {
        ContainerFixtures.registerProviders();
        chain = ContainerFixtures.rsaChain();
    }

    @BeforeEach
    void setUp() throws Exception {
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT);
        TokenProfile profile = v2Token.profile();
        profile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
        tokenProfileRepository.save(profile);
        key = persistKey(v2Token);
        KeyPair pair = chain.leafKey();
        privateItem = persistKeyItem(KeyType.PRIVATE_KEY, true);
        publicItem = persistPublicKeyItem(pair.getPublic());
        Certificate root = persistCertificate(chain.root(), "Root", null);
        intermediate = persistCertificate(chain.intermediate(), "Intermediate", root.getUuid());
        leaf = persistLeaf(chain.leaf(), "leaf.example.com", intermediate.getUuid());
        connectorMock.stubExportKeyAttributes("[]");
        connectorMock
                .stubExportKey(ExportEnvelopeFixtures
                        .keyPairResponseJson(
                                ExportEnvelopeFixtures.envelope(pair.getPrivate(), PASSPHRASE.toCharArray(), 100_000),
                                KeyAlgorithm.RSA, 2048, pair.getPublic()));
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void downloadKeystore_returnsTheKeyAndChainAsPkcs12() throws Exception {
        // given
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        var download = certificateController.downloadKeystore(leaf.getUuid(), request);

        // then
        assertThat(download.getStatusCode()).isEqualTo(HttpStatus.OK);
        HttpHeaders headers = download.getHeaders();
        assertThat(headers.getContentType()).hasToString(CertificateController.KEYSTORE_MEDIA_TYPE);
        assertThat(headers.getCacheControl()).isEqualTo("no-store, no-cache");
        assertThat(headers.getPragma()).isEqualTo("no-cache");
        assertThat(headers.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(headers.getContentDisposition().getFilename()).isEqualTo("leaf.example.com.p12");
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        String alias = onlyAlias(keystore);
        assertThat(keystore.isKeyEntry(alias)).isTrue();
        assertThat(keystore.getCertificateChain(alias)).containsExactly(x509(chain.leaf()), x509(chain.intermediate()));
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, PASSPHRASE.toCharArray());
        assertThat(signatureVerifies(privateKey, x509(chain.leaf()).getPublicKey())).isTrue();
        connectorMock.verifyExportKeyRequestContaining("{\"passphrase\":\"" + PASSPHRASE + "\"}");
        assertThat(request.getPassphrase().characters()).isEmpty();
    }

    @Test
    void downloadKeystore_leavesOutTheTrustAnchor() throws Exception {
        // when
        var download = certificateController.downloadKeystore(leaf.getUuid(), request(PASSPHRASE));

        // then
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        assertThat(keystore.getCertificateChain(onlyAlias(keystore))).hasSize(2).doesNotContain(x509(chain.root()));
    }

    /** An incomplete chain keeps every issuer the inventory holds, as its last one is not self-signed. */
    @Test
    void downloadKeystore_keepsTheIssuersOfAnIncompleteChain() throws Exception {
        // given an intermediate whose issuer the inventory does not hold
        UUID rootUuid = intermediate.getIssuerCertificateUuid();
        intermediate.setIssuerCertificateUuid(null);
        certificateRepository.save(intermediate);
        certificateRepository.deleteById(rootUuid);

        // when
        var download = certificateController.downloadKeystore(leaf.getUuid(), request(PASSPHRASE));

        // then
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        assertThat(keystore.getCertificateChain(onlyAlias(keystore)))
                .containsExactly(x509(chain.leaf()), x509(chain.intermediate()));
    }

    @Test
    void downloadKeystore_keepsASelfSignedLeaf() throws Exception {
        // given
        X509CertificateHolder selfSigned = ContainerFixtures.selfSigned(chain.leafKey(), "CN=self-signed.example.com");
        Certificate certificate = persistLeaf(selfSigned, "self-signed.example.com", null);

        // when
        var download = certificateController.downloadKeystore(certificate.getUuid(), request(PASSPHRASE));

        // then
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        assertThat(keystore.getCertificateChain(onlyAlias(keystore))).containsExactly(x509(selfSigned));
    }

    /** An issuer the inventory holds but has not linked yet is found, as the certificate's chain finds it. */
    @Test
    void downloadKeystore_findsAnIssuerTheInventoryHoldsButHasNotLinked() throws Exception {
        // given
        leaf.setIssuerCertificateUuid(null);
        certificateRepository.save(leaf);

        // when
        var download = certificateController.downloadKeystore(leaf.getUuid(), request(PASSPHRASE));

        // then
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        assertThat(keystore.getCertificateChain(onlyAlias(keystore)))
                .containsExactly(x509(chain.leaf()), x509(chain.intermediate()));
    }

    /** A self-issued issuer that another key signed, as a key rollover issues one, is no trust anchor. */
    @Test
    void downloadKeystore_keepsASelfIssuedIssuerThatIsNotSelfSigned() throws Exception {
        // given
        X509CertificateHolder rollover = rolloverOf(chain.root());
        intermediate.setIssuerCertificateUuid(persistCertificate(rollover, "Root", null).getUuid());
        certificateRepository.save(intermediate);

        // when
        var download = certificateController.downloadKeystore(leaf.getUuid(), request(PASSPHRASE));

        // then
        KeyStore keystore = opened(download.getBody().getContentAsByteArray());
        assertThat(keystore.getCertificateChain(onlyAlias(keystore)))
                .containsExactly(x509(chain.leaf()), x509(chain.intermediate()), x509(rollover));
    }

    @Test
    void downloadKeystore_recordsBothHistoriesAndTheAudit() throws Exception {
        // given
        auditLogs(false);

        // when
        certificateController.downloadKeystore(leaf.getUuid(), request(PASSPHRASE));

        // then
        assertThat(downloadEvents()).singleElement().satisfies(event -> {
            assertThat(event.getCertificateUuid()).isEqualTo(leaf.getUuid());
            assertThat(event.getStatus()).isEqualTo(CertificateEventStatus.SUCCESS);
        });
        assertThat(exportEvents()).singleElement().satisfies(event -> {
            assertThat(event.getKeyUuid()).isEqualTo(privateItem.getUuid());
            assertThat(event.getStatus()).isEqualTo(KeyEventStatus.SUCCESS);
        });
        AuditLog auditRecord = latestAuditRecord();
        assertThat(auditRecord.getOperation()).isEqualTo(Operation.EXPORT);
        assertThat(auditRecord.getOperationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.getResource()).isEqualTo(Resource.CERTIFICATE);
        assertThat(auditRecord.getLogRecord().resource().objects())
                .singleElement()
                .extracting(ResourceObjectIdentity::uuid)
                .isEqualTo(leaf.getUuid());
        assertThat(auditRecord.getAffiliatedResource()).isEqualTo(Resource.CRYPTOGRAPHIC_KEY_ITEM);
        assertThat(auditRecord.getLogRecord().affiliatedResource().objects())
                .containsExactly(new ResourceObjectIdentity(privateItem.getName(), privateItem.getUuid()));
    }

    @Test
    void downloadKeystore_refusesACertificateWithoutAPrivateKey() {
        // given
        cryptographicKeyItemRepository.delete(privateItem);
        UUID leafUuid = leaf.getUuid();
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        NotFoundException refused = assertThrows(NotFoundException.class,
                () -> certificateController.downloadKeystore(leafUuid, request));

        // then
        assertThat(refused.getMessage())
                .isEqualTo("Certificate %s has no private key in the platform.".formatted(leafUuid));
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void downloadKeystore_refusesAKeyThatDoesNotHoldTheCertificatesPublicKey() {
        // given
        auditLogs(false);
        leaf.setPublicKeyFingerprint("another-public-key");
        certificateRepository.save(leaf);
        UUID leafUuid = leaf.getUuid();
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> certificateController.downloadKeystore(leafUuid, request));

        // then
        assertThat(refused.getMessage())
                .isEqualTo("The key of certificate %s does not hold its public key.".formatted(leafUuid));
        AuditLog auditRecord = latestAuditRecord();
        assertThat(auditRecord.getOperationResult()).isEqualTo(OperationResult.FAILURE);
        assertThat(auditRecord.getLogRecord().affiliatedResource().objects())
                .containsExactly(new ResourceObjectIdentity(privateItem.getName(), privateItem.getUuid()));
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void downloadKeystore_refusesACertificateThatIsNotIssued() {
        // given
        Certificate requested = certificateRepository
                .save(aCertificate()
                        .withCommonName("requested.example.com")
                        .withState(CertificateState.REQUESTED)
                        .withKeyUuid(key.getUuid())
                        .withPublicKeyFingerprint(publicItem.getFingerprint())
                        .build());
        UUID requestedUuid = requested.getUuid();
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> certificateController.downloadKeystore(requestedUuid, request));

        // then
        assertThat(refused.getMessage()).isEqualTo("Cannot download the certificate, certificate is not issued.");
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void downloadKeystore_refusesAKeyNotExportable() {
        // given
        auditLogs(false);
        cryptographicKeyItemRepository.delete(privateItem);
        CryptographicKeyItem locked = persistKeyItem(KeyType.PRIVATE_KEY, false);
        UUID leafUuid = leaf.getUuid();
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> certificateController.downloadKeystore(leafUuid, request));

        // then
        assertThat(refused.getMessage())
                .isEqualTo("Key item %s was not created or imported as exportable.".formatted(locked.getUuid()));
        assertThat(latestAuditRecord().getOperationResult()).isEqualTo(OperationResult.FAILURE);
        assertThat(exportEvents())
                .singleElement()
                .extracting(CryptographicKeyEventHistory::getStatus)
                .isEqualTo(KeyEventStatus.FAILED);
        assertThat(downloadEvents()).isEmpty();
        assertThat(request.getPassphrase().characters()).isEmpty();
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void downloadKeystore_refusesACallerWithoutExportPermission() {
        // given
        auditLogs(false);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.EXPORT_KEY);
        UUID leafUuid = leaf.getUuid();
        CertificateKeystoreRequestDto request = request(PASSPHRASE);

        // when
        assertThrows(AccessDeniedException.class, () -> certificateController.downloadKeystore(leafUuid, request));

        // then
        assertThat(latestAuditRecord().getOperationResult()).isEqualTo(OperationResult.FAILURE);
        assertThat(downloadEvents()).isEmpty();
        connectorMock.verifyExportKeyRequests(0);
    }

    /**
     * An operator may turn on debug logging and verbose audit; neither may show the passphrase, whether the download
     * succeeds or the connector refuses the export in words that carry it.
     */
    @Test
    void downloadKeystore_neverRevealsThePassphrase() throws Exception {
        // given
        auditLogs(true);
        UUID leafUuid = leaf.getUuid();
        CertificateKeystoreRequestDto refusedRequest = request(PASSPHRASE);
        List<String> seen = new ArrayList<>();

        // when
        SecretLeakProbe probe = SecretLeakProbe.capture();
        try (probe) {
            var download = certificateController.downloadKeystore(leafUuid, request(PASSPHRASE));
            download.getHeaders().forEach((name, values) -> seen.addAll(values));
            connectorMock.stubExportKeyProblem(ErrorCode.KEY_NOT_EXPORTABLE, "refused for " + PASSPHRASE);
            seen
                    .add(assertThrows(ValidationException.class,
                            () -> certificateController.downloadKeystore(leafUuid, refusedRequest)).getMessage());
        }

        // then
        seen.addAll(probe.logged());
        List<String> auditRecords = SecretLeakProbe.auditRecords(jdbcTemplate);
        assertThat(auditRecords)
                .as("the verbose records leave the sensitive request out")
                .noneMatch(auditRecord -> auditRecord.contains("exportAttributes"));
        seen.addAll(auditRecords);
        for (CertificateEventHistory event : certificateEventHistoryRepository.findAll()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        for (CryptographicKeyEventHistory event : keyEventHistoryRepository.findAll()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        assertThat(auditLogRepository.count()).isEqualTo(2);
        assertThat(downloadEvents()).hasSize(1);
        assertThat(exportEvents()).hasSize(2);
        SecretLeakProbe.assertNoneReveals(seen, PASSPHRASE);
    }

    @Test
    void getCertificate_saysTheKeystoreIsAvailable() throws Exception {
        // when
        CertificateDetailDto detail = certificateService.getCertificate(leaf.getSecuredUuid());

        // then
        assertThat(detail.isKeystoreAvailable()).isTrue();
    }

    @Test
    void getCertificate_saysTheKeystoreIsUnavailableForAKeyNotExportable() throws Exception {
        // given
        cryptographicKeyItemRepository.delete(privateItem);
        persistKeyItem(KeyType.PRIVATE_KEY, false);

        // when
        CertificateDetailDto detail = certificateService.getCertificate(leaf.getSecuredUuid());

        // then
        assertThat(detail.isKeystoreAvailable()).isFalse();
    }

    // ---- fixtures ----

    private static CertificateKeystoreRequestDto request(String passphrase) {
        CertificateKeystoreRequestDto request = new CertificateKeystoreRequestDto();
        request.setPassphrase(new Passphrase(passphrase.toCharArray()));
        request.setExportAttributes(List.of());
        return request;
    }

    /** The file as the JDK opens it, with the passphrase it was downloaded under. */
    private static KeyStore opened(byte[] file) throws GeneralSecurityException, IOException {
        KeyStore keystore = KeyStore.getInstance("PKCS12", "SUN");
        keystore.load(new ByteArrayInputStream(file), PASSPHRASE.toCharArray());
        return keystore;
    }

    private static String onlyAlias(KeyStore keystore) throws GeneralSecurityException {
        List<String> aliases = Collections.list(keystore.aliases());
        assertThat(aliases).hasSize(1);
        return aliases.getFirst();
    }

    /** Whether a signature made with the private key verifies under the public key, so the two are one pair. */
    private static boolean signatureVerifies(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        byte[] data = "keystore round trip".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static X509Certificate x509(X509CertificateHolder certificate) throws GeneralSecurityException {
        return new JcaX509CertificateConverter().getCertificate(certificate);
    }

    /**
     * A certificate of the root's name and key that another key signed, as a key rollover issues one: self-issued, but
     * not self-signed. The key that signed it is in no inventory.
     */
    private static X509CertificateHolder rolloverOf(X509CertificateHolder root)
            throws GeneralSecurityException, OperatorCreationException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        Instant now = Instant.now();
        return new X509v3CertificateBuilder(root.getSubject(), BigInteger.TWO, Date.from(now.minus(Duration.ofDays(1))),
                Date.from(now.plus(Duration.ofDays(365))), root.getSubject(), root.getSubjectPublicKeyInfo())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(generator.generateKeyPair().getPrivate()));
    }

    private List<CertificateEventHistory> downloadEvents() {
        return certificateEventHistoryRepository
                .findAll()
                .stream()
                .filter(event -> event.getEvent() == CertificateEvent.DOWNLOAD_KEYSTORE)
                .toList();
    }

    private List<CryptographicKeyEventHistory> exportEvents() {
        return keyEventHistoryRepository
                .findAll()
                .stream()
                .filter(event -> event.getEvent() == KeyEvent.EXPORT)
                .toList();
    }

    private AuditLog latestAuditRecord() {
        return auditLogRepository.findAll().stream().max(Comparator.comparing(AuditLog::getId)).orElseThrow();
    }

    private void auditLogs(boolean verbose) {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.DATABASE);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        auditLogs.setVerbose(verbose);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingService.updateLoggingSettings(settings);
    }

    private Certificate persistCertificate(X509CertificateHolder x509, String commonName, UUID issuerUuid)
            throws IOException {
        return certificateRepository.save(certificate(x509, commonName, issuerUuid).build());
    }

    /** A certificate of the key's public key, linked to the key as the fingerprint linking links it. */
    private Certificate persistLeaf(X509CertificateHolder x509, String commonName, UUID issuerUuid) throws IOException {
        return certificateRepository
                .save(certificate(x509, commonName, issuerUuid)
                        .withKeyUuid(key.getUuid())
                        .withPublicKeyFingerprint(publicItem.getFingerprint())
                        .build());
    }

    private CertificateBuilder certificate(X509CertificateHolder x509, String commonName, UUID issuerUuid)
            throws IOException {
        CertificateContent content = certificateContentRepository
                .save(aCertificateContent().withContent(Base64.getEncoder().encodeToString(x509.getEncoded())).build());
        return aCertificate()
                .withCommonName(commonName)
                .withSubjectDn(x509.getSubject().toString())
                .withSubjectDnNormalized(CertificateUtil.normalizeSubjectDn(x509.getSubject()))
                .withIssuerDn(x509.getIssuer().toString())
                .withIssuerDnNormalized(CertificateUtil.normalizeSubjectDn(x509.getIssuer()))
                .withState(CertificateState.ISSUED)
                .withCertificateContent(content)
                .withIssuerCertificateUuid(issuerUuid);
    }

    private CryptographicKey persistKey(V2TokenFixture.V2Token v2Token) {
        CryptographicKey value = new CryptographicKey();
        value.setName("keystore-key");
        value.setTokenProfile(v2Token.profile());
        value.setTokenInstanceReference(v2Token.token());
        return cryptographicKeyRepository.save(value);
    }

    /** The public key, with the fingerprint the platform links certificates to it by. */
    private CryptographicKeyItem persistPublicKeyItem(PublicKey material) throws GeneralSecurityException {
        String spki = Base64.getEncoder().encodeToString(material.getEncoded());
        CryptographicKeyItem value = keyItem(KeyType.PUBLIC_KEY, false);
        value.setFormat(KeyFormat.SPKI);
        value.setKeyData(spki);
        value.setFingerprint(CertificateUtil.getThumbprint(spki.getBytes(StandardCharsets.UTF_8)));
        return cryptographicKeyItemRepository.save(value);
    }

    private CryptographicKeyItem persistKeyItem(KeyType type, boolean exportable) {
        return cryptographicKeyItemRepository.save(keyItem(type, exportable));
    }

    /** The export permission is written once, with the item; it cannot be granted afterwards. */
    private CryptographicKeyItem keyItem(KeyType type, boolean exportable) {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setUuid(UUID.randomUUID().toString());
        handle.setName("provider-handle");
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        handle.setProperties(new MetadataAttributeProperties());
        handle.setContent(List.of(new StringAttributeContentV3("handle-" + UUID.randomUUID())));
        CryptographicKeyItem value = new CryptographicKeyItem();
        value.setName(key.getName() + " " + type.getCode());
        value.setKey(key);
        value.setKeyUuid(key.getUuid());
        value.setType(type);
        value.setKeyAlgorithm(KeyAlgorithm.RSA);
        value.setFormat(KeyFormat.PRKI);
        value.setLength(2048);
        value.setState(KeyState.ACTIVE);
        value.setEnabled(true);
        value.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        value.setKeyMeta(List.of(handle));
        value.setExportable(exportable);
        return value;
    }
}
