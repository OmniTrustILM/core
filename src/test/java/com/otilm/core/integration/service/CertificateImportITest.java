package com.otilm.core.integration.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CertificateController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.api.model.client.certificate.CertificateImportResultDto;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.container.Container;
import com.otilm.core.container.ContainerEntry;
import com.otilm.core.container.ContainerFixtures;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.container.ContainerReader;
import com.otilm.core.container.KeyEntry;
import com.otilm.core.container.Pkcs12Fixtures;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.key.normalization.JavaKeyStoreFixtures;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.ImportedKeyRegistration;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.impl.CertificateImportServiceImpl;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.CertificateUploadTriggerSeeder;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.container.ContainerFixtures.LF;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static com.otilm.core.integration.service.CryptographicKeyImportV2ITest.imported;
import static com.otilm.core.integration.service.CryptographicKeyImportV2ITest.importedSecretKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

@SpringBootTest
class CertificateImportITest extends BaseSpringBootTest {

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    private static final char[] OPENSSH_PASSPHRASE = "openssh-test-passphrase".toCharArray();

    private static final byte[] LEAF_KEY_ID = {1, 2, 3, 4};

    private static final String NOT_REGISTERED = "A certificate of the entry was not uploaded. See Certificate Uploaded"
            + " Event History for more details.";

    private static final long NODE_TIMEOUT_SECONDS = 60;

    private static Chain chain;

    private static X509CertificateHolder other;

    private static PKCS10CertificationRequest signingRequest;

    @Autowired
    private CertificateController certificateController;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private ContainerReader containerReader;
    @Autowired
    private CertificateUploadService certificateUploadService;
    @Autowired
    private CertificateUploadTriggerSeeder certificateUploadTriggerSeeder;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository keyEventHistoryRepository;
    @Autowired
    private KeyImportRepository keyImportRepository;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AuditLogRepository auditLogRepository;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private KeyImportWriter keyImportWriter;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @MockitoSpyBean
    private CertificateInternalService certificateInternalService;
    @MockitoSpyBean
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private WireMockServer authService;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private TokenProfile profile;

    @BeforeAll
    static void keys() throws Exception {
        ContainerFixtures.registerProviders();
        chain = ContainerFixtures.rsaChain();
        other = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Other");
        signingRequest = ContainerFixtures.signingRequest(chain.leafKey());
    }

    @BeforeEach
    void setUp() throws Exception {
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        profile = v2Token.profile();
        connectorMock
                .stubImportableKeyTypes(Map
                        .of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA), KeyRequestType.SECRET,
                                Set.of(KeyAlgorithm.AES)));
        connectorMock.stubImportKeyAttributes("[]");
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
        if (authService != null) {
            authService.stop();
        }
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void importCertificates_importsTheSelectedEntriesOfAPkcs12() throws Exception {
        // given
        byte[] file = pkcs12(aes());
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()), importedSecretKey());
        CertificateImportRequestDto request = request(file, PASSPHRASE, entry(reference(other), null),
                entry(keyPairReference(), destination("leaf key")),
                entry(referenceOf(file, PASSPHRASE, InspectedEntryKind.SECRET_KEY), destination("secret key")));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .extracting(CertificateImportResultDto::getKind, CertificateImportResultDto::isImported,
                        CertificateImportResultDto::getCertificateOutcome, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getMessage)
                .containsExactly(tuple(InspectedEntryKind.CERTIFICATE, true, ImportOutcome.CREATED, null, null),
                        tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, true, ImportOutcome.CREATED,
                                ImportOutcome.CREATED, null),
                        tuple(InspectedEntryKind.SECRET_KEY, true, null, ImportOutcome.CREATED, null));
        assertThat(results.getFirst()).satisfies(certificate -> {
            assertThat(certificate.getCertificateUuid()).isEqualTo(inventoried(other).getUuid().toString());
            assertThat(certificate.getKeyUuid()).isNull();
        });
        Certificate leaf = inventoried(chain.leaf());
        assertThat(results.get(1)).satisfies(keyPair -> {
            assertThat(keyPair.getCertificateUuid()).isEqualTo(leaf.getUuid().toString());
            assertThat(leaf.getKeyUuid()).hasToString(keyPair.getKeyUuid());
        });
        assertThat(certificateRepository.findByFingerprint(reference(chain.intermediate()))).isPresent();
        assertThat(certificateRepository.findByFingerprint(reference(chain.root()))).isPresent();
        assertThat(results.get(2)).satisfies(secretKey -> {
            assertThat(secretKey.getCertificateUuid()).isNull();
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(UUID.fromString(secretKey.getKeyUuid()))))
                    .singleElement()
                    .extracting(CryptographicKeyItem::getType)
                    .isEqualTo(KeyType.SECRET_KEY);
        });
        connectorMock.verifyImportKeyRequests(2);
    }

    @Test
    void importCertificates_importsOnlyTheNamedEntries() throws Exception {
        // given
        byte[] file = pkcs12(aes());
        CertificateImportRequestDto request = request(file, PASSPHRASE, entry(reference(other), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results).singleElement().satisfies(certificate -> {
            assertThat(certificate.getEntryReference()).isEqualTo(reference(other));
            assertThat(certificate.isImported()).isTrue();
        });
        assertThat(certificateRepository.findAll())
                .extracting(Certificate::getFingerprint)
                .containsExactly(reference(other));
        assertThat(keyImportRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(0);
    }

    @Test
    void importCertificates_namesKeysFromTheirAliases() throws Exception {
        // given
        KeyPair first = rsa();
        KeyPair second = rsa();
        byte[] file = Pkcs12Fixtures
                .builder()
                .shroudedKeyBag(first.getPrivate(), PASSPHRASE, "first key", null)
                .shroudedKeyBag(second.getPrivate(), PASSPHRASE, "second key", null)
                .mac(PASSPHRASE, NISTObjectIdentifiers.id_sha256)
                .build();
        connectorMock.stubImportKeys(imported(first.getPublic()), imported(second.getPublic()));
        CertificateImportRequestDto request = request(file, PASSPHRASE,
                entry(sha256(first.getPublic().getEncoded()), destination(null)),
                entry(sha256(second.getPublic().getEncoded()), destination(null)));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .extracting(result -> nameOfKey(result.getKeyUuid()))
                .containsExactly("first key", "second key");
    }

    @Test
    void importCertificates_importsNothingTwiceForAResentRequest() throws Exception {
        // given
        byte[] file = pkcs12(aes());
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        List<CertificateImportResultDto> first = importCertificates(keyPairAndCertificate(file));
        long certificates = certificateRepository.count();
        long keys = cryptographicKeyRepository.count();

        // when
        List<CertificateImportResultDto> resent = importCertificates(keyPairAndCertificate(file));

        // then
        assertThat(first)
                .extracting(CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getKeyOutcome)
                .containsExactly(tuple(ImportOutcome.CREATED, ImportOutcome.CREATED),
                        tuple(ImportOutcome.CREATED, null));
        assertThat(resent)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getCertificateUuid, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid)
                .containsExactly(
                        tuple(true, ImportOutcome.EXISTING, first.getFirst().getCertificateUuid(),
                                ImportOutcome.EXISTING, first.getFirst().getKeyUuid()),
                        tuple(true, ImportOutcome.EXISTING, first.get(1).getCertificateUuid(), null, null));
        connectorMock.verifyImportKeyRequests(1);
        assertThat(certificateRepository.count()).isEqualTo(certificates);
        assertThat(cryptographicKeyRepository.count()).isEqualTo(keys);
    }

    /**
     * Two nodes import two files whose chains share a CA the inventory does not hold yet, and both have checked that it
     * is not there before either registers it. The node whose registration of the CA fails on the other's takes the CA
     * the other registered, and goes on to register its leaf.
     */
    @Test
    void importCertificates_takesTheCaAnotherNodeRegisteredMeanwhile() throws Exception {
        // given
        KeyPair caKey = ContainerFixtures.ec();
        X509CertificateHolder ca = ContainerFixtures.selfSigned(caKey, "CN=Shared CA");
        KeyPair firstKey = rsa();
        KeyPair secondKey = rsa();
        CertificateImportRequestDto first = keyPairIssuedBy(ca, caKey, firstKey, "First");
        CertificateImportRequestDto second = keyPairIssuedBy(ca, caKey, secondKey, "Second");
        connectorMock.stubImportKeys(imported(firstKey.getPublic()), imported(secondKey.getPublic()));
        CountDownLatch firstNodeWaits = new CountDownLatch(1);
        CountDownLatch secondNodeArrives = new CountDownLatch(1);
        holdTheFirstRegistrationUntilASecond(reference(ca), firstNodeWaits, secondNodeArrives);
        ListAppender<ILoggingEvent> importLog = captureImportLog();
        ExecutorService nodes = Executors.newFixedThreadPool(2);
        List<CertificateImportResultDto> results = new ArrayList<>();

        // when
        try {
            Future<List<CertificateImportResultDto>> firstNode = nodes.submit(onNode(first));
            awaitNode(firstNodeWaits);
            Future<List<CertificateImportResultDto>> secondNode = nodes.submit(onNode(second));
            results.addAll(firstNode.get(NODE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            results.addAll(secondNode.get(NODE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        } finally {
            nodes.shutdownNow();
            releaseImportLog(importLog);
        }

        // then
        assertThat(results)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getMessage)
                .containsExactly(tuple(true, ImportOutcome.CREATED, null), tuple(true, ImportOutcome.CREATED, null));
        assertThat(certificateRepository.findAll())
                .extracting(Certificate::getFingerprint)
                .containsOnlyOnce(reference(ca));
        assertThat(importLog.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .noneMatch(message -> message.endsWith("of a certificate import failed"));
    }

    @Test
    void importCertificates_keepsOtherEntriesWhenOneFails() throws Exception {
        // given
        KeyPair refused = rsa();
        KeyPair accepted = rsa();
        byte[] file = Pkcs12Fixtures
                .builder()
                .shroudedKeyBag(refused.getPrivate(), PASSPHRASE, "refused key", null)
                .shroudedKeyBag(accepted.getPrivate(), PASSPHRASE, "accepted key", null)
                .certBag(other, "other", null)
                .mac(PASSPHRASE, NISTObjectIdentifiers.id_sha256)
                .build();
        connectorMock
                .stubImportKeys(ProblemDetailExtended
                        .fromErrorCode(ErrorCode.KEY_TYPE_NOT_IMPORTABLE, "refused for reasons of its own", null, null),
                        imported(accepted.getPublic()));
        CertificateImportRequestDto request = request(file, PASSPHRASE,
                entry(sha256(refused.getPublic().getEncoded()), destination(null)),
                entry(sha256(accepted.getPublic().getEncoded()), destination(null)), entry(reference(other), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getMessage)
                .containsExactly(tuple(false, "The connector refused to import the key (KEY_TYPE_NOT_IMPORTABLE)."),
                        tuple(true, null), tuple(true, null));
        assertThat(results.getFirst().getKeyUuid()).isNull();
    }

    /** The key import could not tell the key from one the passphrase does not open, so it is not asked. */
    @Test
    void importCertificates_failsAKeyOfAnAlgorithmThePlatformDoesNotSupportAsTheInspectionReportsIt() throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .builder()
                .shroudedKeyBag(ContainerFixtures.ed25519().getPrivate(), PASSPHRASE, "ed25519 key", null)
                .mac(PASSPHRASE, NISTObjectIdentifiers.id_sha256)
                .build();
        CertificateImportRequestDto request = request(file, PASSPHRASE,
                entry(referenceOf(file, PASSPHRASE, InspectedEntryKind.PRIVATE_KEY), destination(null)));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getMessage)
                .containsExactly(false, "The platform does not support the key's algorithm.");
        assertThat(keyImportRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(0);
    }

    /**
     * The first request imports the key but cannot register its leaf; the resent entry finds the key imported and
     * registers the certificates the first request did not.
     */
    @Test
    void importCertificates_registersTheCertificatesOfAnEntryWhoseKeyAResendFindsImported() throws Exception {
        // given
        auditLogs(false);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        certificateUploadTriggerSeeder.seedIgnoreTrigger(FilterField.COMMON_NAME, "Leaf");
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        List<CertificateImportResultDto> first = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination(null))));
        certificateUploadTriggerSeeder.removeIgnoreTriggers();

        // when
        List<CertificateImportResultDto> resent = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination(null))));

        // then
        UUID keyUuid = keyImportRepository.findAll().getFirst().getKeyUuid();
        assertThat(first)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getKeyOutcome, CertificateImportResultDto::getKeyUuid,
                        CertificateImportResultDto::getMessage)
                .containsExactly(false, null, ImportOutcome.CREATED, keyUuid.toString(), NOT_REGISTERED);
        assertThat(importAuditRecord().getLogRecord().operationData())
                .isEqualTo(Map.of("certificateUuids", List.of(), "keyUuids", List.of(keyUuid.toString())));
        Certificate leaf = inventoried(chain.leaf());
        assertThat(resent).singleElement().satisfies(keyPair -> {
            assertThat(keyPair.isImported()).isTrue();
            assertThat(keyPair.getCertificateOutcome()).isEqualTo(ImportOutcome.CREATED);
            assertThat(keyPair.getKeyOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(keyPair.getKeyUuid()).isEqualTo(keyUuid.toString());
            assertThat(keyPair.getCertificateUuid()).isEqualTo(leaf.getUuid().toString());
        });
        assertThat(leaf.getKeyUuid()).isEqualTo(keyUuid);
        assertThat(nameOfKey(keyUuid.toString())).isEqualTo("Leaf");
        assertThat(certificateRepository.count()).isEqualTo(3);
        connectorMock.verifyImportKeyRequests(1);
    }

    /** The request's custom attributes are given to the certificates it registers, not to one already registered. */
    @Test
    void importCertificates_reportsACertificateAlreadyInTheInventory() throws Exception {
        // given
        X509CertificateHolder another = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Another");
        String registered = certificateUploadService
                .upload(Base64.getEncoder().encodeToString(other.getEncoded()), null, true);
        UUID registeredUuid = certificateRepository.findByFingerprint(registered).orElseThrow().getUuid();
        CustomAttributeV3 department = departmentAttribute();
        CertificateImportRequestDto request = request(ContainerFixtures.pem(LF, other, another), null,
                entry(reference(other), null), entry(reference(another), null));
        request.setCustomAttributes(List.of(departmentValue(UUID.fromString(department.getUuid()))));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getCertificateUuid)
                .containsExactly(tuple(true, ImportOutcome.EXISTING, registeredUuid.toString()),
                        tuple(true, ImportOutcome.CREATED, inventoried(another).getUuid().toString()));
        assertThat(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, registeredUuid)).isEmpty();
        assertThat(
                attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, inventoried(another).getUuid()))
                .extracting(ResponseAttribute::getName)
                .containsExactly("department");
    }

    @Test
    void importCertificates_adoptsTheKeyOfALeafAlreadyInTheInventory() throws Exception {
        // given — no auth service runs: the signed-in requester needs no lookup
        String registered = certificateUploadService
                .upload(Base64.getEncoder().encodeToString(chain.leaf().getEncoded()), null, true);
        Certificate leaf = certificateRepository.findByFingerprint(registered).orElseThrow();
        String recordName = nameOfKey(leaf.getKeyUuid().toString());
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination("adopted key"))));

        // then
        assertThat(results).singleElement().satisfies(keyPair -> {
            assertThat(keyPair.isImported()).isTrue();
            assertThat(keyPair.getCertificateOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(keyPair.getCertificateUuid()).isEqualTo(leaf.getUuid().toString());
            assertThat(keyPair.getKeyOutcome()).isEqualTo(ImportOutcome.ADOPTED);
            assertThat(keyPair.getKeyUuid()).isEqualTo(leaf.getKeyUuid().toString());
        });
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(leaf.getKeyUuid())))
                .extracting(CryptographicKeyItem::getType)
                .containsExactlyInAnyOrder(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY);
        assertThat(nameOfKey(leaf.getKeyUuid().toString())).isEqualTo(recordName).isNotEqualTo("adopted key");
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importCertificates_adoptsAPublicKeyTheInventoryHoldsWithoutItsCertificate() throws Exception {
        // given
        UUID recordUuid = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_public", chain.leafKey().getPublic(), 2048,
                        KeyImportWriterITest.fingerprintOf(chain.leafKey()));
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination("adopted key"))));

        // then
        assertThat(results).singleElement().satisfies(keyPair -> {
            assertThat(keyPair.isImported()).isTrue();
            assertThat(keyPair.getKeyOutcome()).isEqualTo(ImportOutcome.ADOPTED);
            assertThat(keyPair.getKeyUuid()).isEqualTo(recordUuid.toString());
            assertThat(keyPair.getCertificateOutcome()).isEqualTo(ImportOutcome.CREATED);
        });
        Certificate leaf = inventoried(chain.leaf());
        assertThat(results.getFirst().getCertificateUuid()).isEqualTo(leaf.getUuid().toString());
        assertThat(leaf.getKeyUuid()).isEqualTo(recordUuid);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid)))
                .extracting(CryptographicKeyItem::getType)
                .containsExactlyInAnyOrder(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY);
    }

    /**
     * A certificate brings the key's public key in while the key is registered, once the registration found nothing and
     * before it writes. The registration fails on the unique fingerprint, and the second one takes the record, whose
     * requester may update it. The certificate commits on a thread of its own, which borrows one connection while the
     * import holds one.
     */
    @Test
    void importCertificates_adoptsARecordACertificateBroughtInWhileTheKeyWasRegistered() throws Exception {
        // given
        authServiceKnowsTheRequester();
        KeyPair key = rsa();
        connectorMock.stubImportKeys(imported(key.getPublic()));
        String fingerprint = KeyImportWriterITest.fingerprintOf(key);
        try (ExecutorService certificateUpload = Executors.newSingleThreadExecutor()) {
            bringTheRecordInWhen(fingerprint, key, certificateUpload, CertificateImportITest::registering);

            // when
            List<CertificateImportResultDto> results = importCertificates(keyOnly(key, "raced key"));

            // then
            UUID recordUuid = cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElseThrow().getKeyUuid();
            assertThat(results)
                    .singleElement()
                    .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                            CertificateImportResultDto::getKeyUuid)
                    .containsExactly(true, ImportOutcome.ADOPTED, recordUuid.toString());
            assertThat(keyImportRepository.findAll())
                    .singleElement()
                    .extracting(KeyImport::getState)
                    .isEqualTo(KeyImportState.COMPLETED);
            assertThat(nameOfKey(recordUuid.toString())).isEqualTo("certKey_raced");
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
        }
    }

    /**
     * A retry resumes the attempt of an import whose answer was lost, and another node completes that attempt, from the
     * connector's answer to the first request, before the retry registers the key: the retry is answered with the key
     * the other node registered.
     */
    @Test
    void importCertificates_answersARetryWithTheKeyAnotherNodeRegisteredForItsAttempt() throws Exception {
        // given
        KeyPair key = rsa();
        connectorMock.stubImportKeyUnanswered();
        List<CertificateImportResultDto> lost = importCertificates(keyOnly(key, "resumed key"));
        KeyImportAttempt attempt = KeyImportAttempt.of(keyImportRepository.findAll().getFirst());
        connectorMock
                .stubImportKeyResult(CryptographicKeyImportV2ITest.status(OperationStatus.COMPLETED, key.getPublic()));
        TokenProfileFullModel registeredInto = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(profile.getUuid(),
                        profile.getTokenInstanceReferenceUuid())
                .orElseThrow();
        ImportedKeyRegistration otherNodesRegistration = KeyImportWriterITest
                .registration(registeredInto, key, attempt, Set.of());
        String fingerprint = KeyImportWriterITest.fingerprintOf(key);
        try (ExecutorService otherNode = Executors.newSingleThreadExecutor()) {
            meanwhileWhen(fingerprint, this::connectorWasAskedForTheResult, otherNode,
                    () -> keyImportWriter.complete(attempt.uuid(), otherNodesRegistration).orElseThrow());

            // when
            List<CertificateImportResultDto> results = importCertificates(keyOnly(key, "resumed key"));

            // then
            UUID keyUuid = keyImportRepository.findById(attempt.uuid()).orElseThrow().getKeyUuid();
            assertThat(lost)
                    .singleElement()
                    .extracting(CertificateImportResultDto::getMessage)
                    .isEqualTo(KeyImportSaga.UNCONFIRMED);
            assertThat(results)
                    .singleElement()
                    .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                            CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getMessage)
                    .containsExactly(true, ImportOutcome.EXISTING, keyUuid.toString(), null);
            assertThat(cryptographicKeyRepository.count()).isEqualTo(1);
        }
    }

    /**
     * A certificate brings the key's public key in once the connector was asked, after the checks made before it. The
     * record is taken only once its requester is shown, at the registration, to be allowed to update it.
     */
    @Test
    void importCertificates_adoptsARecordThatAppearedAfterTheFirstCheckWhenItsRequesterMayUpdateIt() throws Exception {
        // given
        authServiceKnowsTheRequester();
        KeyPair key = rsa();
        connectorMock.stubImportKeys(imported(key.getPublic()));
        String fingerprint = KeyImportWriterITest.fingerprintOf(key);
        try (ExecutorService certificateUpload = Executors.newSingleThreadExecutor()) {
            bringTheRecordInWhen(fingerprint, key, certificateUpload, this::connectorWasAsked);

            // when
            List<CertificateImportResultDto> results = importCertificates(keyOnly(key, "late key"));

            // then
            UUID recordUuid = cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElseThrow().getKeyUuid();
            assertThat(results)
                    .singleElement()
                    .extracting(CertificateImportResultDto::getKeyOutcome, CertificateImportResultDto::getKeyUuid)
                    .containsExactly(ImportOutcome.ADOPTED, recordUuid.toString());
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
        }
    }

    /**
     * The same, where the requester may not update the record another user owns: the import is refused as one of a key
     * held otherwise, the record is left as it was, and the attempt is the reconciliation's to undo at once.
     */
    @Test
    void importCertificates_refusesARecordThatAppearedAfterTheFirstCheckWhenItsRequesterMayNotUpdateIt()
            throws Exception {
        // given
        authServiceKnowsTheRequester();
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);
        KeyPair key = rsa();
        connectorMock.stubImportKeys(imported(key.getPublic()));
        String fingerprint = KeyImportWriterITest.fingerprintOf(key);
        try (ExecutorService certificateUpload = Executors.newSingleThreadExecutor()) {
            bringTheRecordInWhen(fingerprint, key, certificateUpload, this::connectorWasAsked);

            // when
            List<CertificateImportResultDto> results = importCertificates(keyOnly(key, "late key"));

            // then
            UUID recordUuid = cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElseThrow().getKeyUuid();
            assertThat(results)
                    .singleElement()
                    .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                            CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getMessage)
                    .containsExactly(false, null, null, CryptographicKeyWriter.KEY_ALREADY_HELD);
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
            assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getTokenProfileUuid()).isNull();
            assertThat(keyImportRepository.findAll()).singleElement().satisfies(attempt -> {
                assertThat(attempt.getState()).isEqualTo(KeyImportState.REQUESTED);
                assertThat(attempt.getNextCheckAt()).isBeforeOrEqualTo(OffsetDateTime.now());
            });
        }
    }

    /** The UUID of a certificate the import creates is checked like any other before the result carries it. */
    @Test
    void importCertificates_returnsTheUuidOfACertificateItCreatedToACallerWhoMaySeeIt() throws Exception {
        // given
        CertificateImportRequestDto request = request(ContainerFixtures.pem(LF, other), null,
                entry(reference(other), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        String registered = inventoried(other).getUuid().toString();
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getCertificateUuid)
                .containsExactly(ImportOutcome.CREATED, registered);
        assertThat(captureOpaRequests())
                .anyMatch(requested -> Resource.CERTIFICATE.getCode().equals(requested.getProperties().get("name"))
                        && ResourceAction.DETAIL.getCode().equals(requested.getProperties().get("action"))
                        && List.of(registered).equals(requested.getObjectUUIDs()));
    }

    /**
     * An uploaded certificate has no owner, so a caller the policy does not let see certificates in detail could not
     * open one it created either: the result reports it created, without its UUID.
     */
    @Test
    void importCertificates_reportsACertificateItCreatedWithoutItsUuidToACallerWhoMayNotSeeIt() throws Exception {
        // given
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);
        CertificateImportRequestDto request = request(ContainerFixtures.pem(LF, other), null,
                entry(reference(other), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getCertificateUuid)
                .containsExactly(true, ImportOutcome.CREATED, null);
        assertThat(certificateRepository.findByFingerprint(reference(other))).isPresent();
    }

    /**
     * A certificate already in the inventory that the caller may not see in detail is reported as found there without
     * its UUID, and the audit record does not name it either.
     */
    @Test
    void importCertificates_reportsACertificateTheCallerMayNotSeeWithoutItsUuid() throws Exception {
        // given
        auditLogs(false);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        X509CertificateHolder another = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Another");
        String hidden = certificateUploadService
                .upload(Base64.getEncoder().encodeToString(other.getEncoded()), null, true);
        UUID hiddenUuid = certificateRepository.findByFingerprint(hidden).orElseThrow().getUuid();
        denyDetailOf(hiddenUuid);
        CertificateImportRequestDto request = request(ContainerFixtures.pem(LF, other, another), null,
                entry(reference(other), null), entry(reference(another), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        String anotherUuid = inventoried(another).getUuid().toString();
        assertThat(results)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getCertificateOutcome,
                        CertificateImportResultDto::getCertificateUuid)
                .containsExactly(tuple(true, ImportOutcome.EXISTING, null),
                        tuple(true, ImportOutcome.CREATED, anotherUuid));
        assertThat(importAuditRecord().getLogRecord().operationData())
                .isEqualTo(Map.of("certificateUuids", List.of(anotherUuid), "keyUuids", List.of()));
        assertThat(jdbcTemplate.queryForList("SELECT log_record::text FROM audit_log", String.class))
                .isNotEmpty()
                .noneMatch(logRecord -> logRecord.contains(hiddenUuid.toString()));
    }

    /**
     * The key pair of another file the inventory holds already as a key of its own: nothing is asked of the connector,
     * and the entry reports the key as found there.
     */
    @Test
    void importCertificates_reportsAKeyPairTheInventoryHoldsAsExisting() throws Exception {
        // given
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        CertificateImportResultDto first = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination("leaf key")))).getFirst();

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(pkcs12(aes()), PASSPHRASE, entry(keyPairReference(), destination("the same key"))));

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getCertificateOutcome)
                .containsExactly(true, ImportOutcome.EXISTING, first.getKeyUuid(), ImportOutcome.EXISTING);
        assertThat(first.getKeyOutcome()).isEqualTo(ImportOutcome.CREATED);
        assertThat(nameOfKey(first.getKeyUuid())).isEqualTo("leaf key");
        connectorMock.verifyImportKeyRequests(1);
        assertThat(keyImportRepository.count()).isEqualTo(1);
    }

    /** The key pair the inventory holds, owned by another user the caller may not see keys of, has no UUID shown. */
    @Test
    void importCertificates_reportsAKeyPairTheInventoryHoldsWithoutItsUuidToACallerWhoMayNotSeeIt() throws Exception {
        // given
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        UUID keyUuid = UUID
                .fromString(importCertificates(
                        request(keyPairPem(), null, entry(keyPairReference(), destination("leaf key"))))
                        .getFirst()
                        .getKeyUuid());
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, keyUuid, UUID.randomUUID(), "another");
        denyKeyDetailOf(keyUuid);

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(pkcs12(aes()), PASSPHRASE, entry(keyPairReference(), destination("the same key"))));

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid)
                .containsExactly(true, ImportOutcome.EXISTING, null);
        connectorMock.verifyImportKeyRequests(1);
    }

    /**
     * The certificate's key is a record another user owns, which the caller may not update: the entry is refused in the
     * words a key held otherwise is, before the connector is asked, and the rest of the request goes on.
     */
    @Test
    void importCertificates_refusesTheKeyOfARecordTheCallerMayNotUpdate() throws Exception {
        // given
        String registered = certificateUploadService
                .upload(Base64.getEncoder().encodeToString(chain.leaf().getEncoded()), null, true);
        UUID recordUuid = certificateRepository.findByFingerprint(registered).orElseThrow().getKeyUuid();
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, UUID.randomUUID(), "another");
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);
        CertificateImportRequestDto request = request(pkcs12(aes()), PASSPHRASE,
                entry(keyPairReference(), destination("leaf key")), entry(reference(other), null));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        assertThat(results)
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getMessage)
                .containsExactly(tuple(false, null, null, CryptographicKeyWriter.KEY_ALREADY_HELD),
                        tuple(true, null, null, null));
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
    }

    /** A secret key has no public key; the key import's own record answers the same file sent again. */
    @Test
    void importCertificates_reportsASecretKeySentAgainAsExisting() throws Exception {
        // given
        SecretKey secretKey = aes();
        byte[] file = pkcs12(secretKey);
        connectorMock.stubImportKeys(importedSecretKey());
        String reference = referenceOf(file, PASSPHRASE, InspectedEntryKind.SECRET_KEY);
        CertificateImportResultDto first = importCertificates(
                request(file, PASSPHRASE, entry(reference, destination("secret key")))).getFirst();

        // when
        List<CertificateImportResultDto> again = importCertificates(
                request(file, PASSPHRASE, entry(reference, destination("secret key"))));

        // then
        assertThat(first.getKeyOutcome()).isEqualTo(ImportOutcome.CREATED);
        assertThat(again)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid)
                .containsExactly(true, ImportOutcome.EXISTING, first.getKeyUuid());
        connectorMock.verifyImportKeyRequests(1);
    }

    /**
     * A key the inventory held already, which changed hands since and the caller may not see in detail, is reported as
     * found there without its UUID, and the audit record of the import does not name it.
     */
    @Test
    void importCertificates_reportsAKeyTheCallerMayNotSeeWithoutItsUuid() throws Exception {
        // given
        auditLogs(false);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        CertificateImportRequestDto request = request(keyPairPem(), null, entry(keyPairReference(), destination(null)));
        UUID keyUuid = UUID.fromString(importCertificates(request).getFirst().getKeyUuid());
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, keyUuid, UUID.randomUUID(), "another");
        denyKeyDetailOf(keyUuid);

        // when
        List<CertificateImportResultDto> resent = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination(null))));

        // then
        String leafUuid = inventoried(chain.leaf()).getUuid().toString();
        assertThat(resent)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getCertificateUuid)
                .containsExactly(true, ImportOutcome.EXISTING, null, leafUuid);
        assertThat(lastImportAuditRecord().getLogRecord().operationData())
                .isEqualTo(Map.of("certificateUuids", List.of(leafUuid), "keyUuids", List.of()));
        connectorMock.verifyImportKeyRequests(1);
    }

    @ParameterizedTest
    @MethodSource("brokenSelections")
    void importCertificates_refusesSelectionsThatBreakARule(CertificateImportEntryDto broken,
            List<RequestAttribute> customAttributes, String message) throws Exception {
        // given
        X509CertificateHolder another = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Another");
        CertificateImportRequestDto request = request(rulesFile(another), null, entry(reference(another), null),
                broken);
        request.setCustomAttributes(customAttributes);

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> importCertificates(request));

        // then
        assertThat(refusal.getMessage()).isEqualTo(message);
        assertThat(certificateRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(0);
    }

    static Stream<Arguments> brokenSelections() throws Exception {
        String absent = sha256("absent".getBytes(StandardCharsets.US_ASCII));
        String key = sha256(chain.intermediateKey().getPublic().getEncoded());
        String certificateRequest = sha256(signingRequest.getEncoded());
        String certificate = reference(other);
        String profileUuid = UUID.randomUUID().toString();
        CertificateEntryKeyDestinationDto named = destinationTo(profileUuid, "a key");
        return Stream
                .of(breaking("an entry the file does not hold", entry(absent, null),
                        "The file holds no entry " + absent + "."),
                        breaking("a reference that is none", entry("not a reference", null),
                                "The file holds no such entry."),
                        breaking("a certificate request", entry(certificateRequest, null),
                                "Entry " + certificateRequest + " is a certificate request, which cannot be imported."),
                        breaking("a key without a destination", entry(key, null),
                                "Entry " + key + " carries key material and needs a keyDestination."),
                        breaking("a certificate with a destination", entry(certificate, named),
                                "Entry " + certificate + " carries no key material, so it takes no keyDestination."),
                        breaking("a key with no name to take", entry(key, destinationTo(profileUuid, null)),
                                "Entry " + key + " needs a keyName: it has no alias or certificate common name to"
                                        + " take one from."),
                        breaking("a profile that is not a UUID", entry(key, destinationTo("profile", "a key")),
                                "tokenProfileUuid must be a UUID"),
                        arguments(Named.of("a custom attribute no certificate has", entry(key, named)),
                                List.of(departmentValue(UUID.randomUUID())),
                                "Content for custom attribute department is provided but resource Certificate is not"
                                        + " associated with it"));
    }

    private static Arguments breaking(String rule, CertificateImportEntryDto entry, String message) {
        return arguments(Named.of(rule, entry), null, message);
    }

    @Test
    void importCertificates_needsCertificateCreateOnlyForCertificates() throws Exception {
        // given
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.CREATE);
        connectorMock.stubImportKeys(imported(chain.intermediateKey().getPublic()));
        CertificateImportRequestDto keyOnly = request(
                ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(chain.intermediateKey())), null,
                entry(sha256(chain.intermediateKey().getPublic().getEncoded()), destination("key only")));
        CertificateImportRequestDto keyPair = request(keyPairPem(), null,
                entry(keyPairReference(), destination("key pair")));

        // when
        List<CertificateImportResultDto> results = importCertificates(keyOnly);
        assertThrows(AccessDeniedException.class, () -> importCertificates(keyPair));

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::getKind, CertificateImportResultDto::isImported)
                .containsExactly(InspectedEntryKind.PRIVATE_KEY, true);
        connectorMock.verifyImportKeyRequests(1);
        assertThat(keyImportRepository.count()).isEqualTo(1);
        assertThat(certificateRepository.count()).isZero();
    }

    /**
     * Nothing is read for a caller who may import neither certificates nor keys, so the caller is refused, not the
     * file.
     */
    @Test
    void importCertificates_refusesACallerWithoutCertificateCreateOrKeyImportBeforeReadingTheFile() throws Exception {
        // given
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.CREATE);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        CertificateImportRequestDto request = request(pkcs12(aes()), "wrong passphrase".toCharArray(),
                entry(reference(other), null), entry(keyPairReference(), destination("leaf key")));

        // when
        AccessDeniedException refusal = assertThrows(AccessDeniedException.class, () -> importCertificates(request));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("Access denied to %s:%s"
                        .formatted(Resource.CRYPTOGRAPHIC_KEY.getCode(), ResourceAction.IMPORT_KEY.getCode()));
        assertThat(certificateRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(0);
    }

    @Test
    void importCertificates_importsFromJksAndJceks() throws Exception {
        // given
        KeyPair jceksKey = rsa();
        X509CertificateHolder jceksCertificate = ContainerFixtures.selfSigned(jceksKey, "CN=Jceks");
        SecretKey secretKey = aes();
        byte[] jks = JavaKeyStoreFixtures
                .jks(PASSPHRASE,
                        Map
                                .of("leaf",
                                        new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(),
                                                new X509Certificate[]{
                                                        x509(chain.leaf()),
                                                        x509(chain.intermediate()),
                                                        x509(chain.root())})));
        Map<String, KeyStore.Entry> jceksEntries = new LinkedHashMap<>();
        jceksEntries
                .put("jceks key", new KeyStore.PrivateKeyEntry(jceksKey.getPrivate(),
                        new X509Certificate[]{x509(jceksCertificate)}));
        jceksEntries.put("jceks secret", new KeyStore.SecretKeyEntry(secretKey));
        byte[] jceks = JavaKeyStoreFixtures.jceks(PASSPHRASE, jceksEntries);
        connectorMock
                .stubImportKeys(imported(chain.leafKey().getPublic()), imported(jceksKey.getPublic()),
                        importedSecretKey());

        // when
        List<CertificateImportResultDto> fromJks = importCertificates(
                request(jks, PASSPHRASE, entry(keyPairReference(), destination(null))));
        List<CertificateImportResultDto> fromJceks = importCertificates(
                request(jceks, PASSPHRASE, entry(sha256(jceksKey.getPublic().getEncoded()), destination(null)),
                        entry(referenceOf(jceks, PASSPHRASE, InspectedEntryKind.SECRET_KEY), destination(null))));

        // then
        assertThat(Stream.concat(fromJks.stream(), fromJceks.stream()))
                .extracting(CertificateImportResultDto::getKind, CertificateImportResultDto::isImported,
                        result -> nameOfKey(result.getKeyUuid()))
                .containsExactly(tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, true, "leaf"),
                        tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, true, "jceks key"),
                        tuple(InspectedEntryKind.SECRET_KEY, true, "jceks secret"));
        assertThat(inventoried(chain.leaf()).getKeyUuid()).hasToString(fromJks.getFirst().getKeyUuid());
        assertThat(inventoried(jceksCertificate).getKeyUuid()).hasToString(fromJceks.getFirst().getKeyUuid());
    }

    @Test
    void importCertificates_importsAnOpenSshKey() throws Exception {
        // given
        byte[] file = openSsh("rsa-bcrypt");
        PublicKey publicKey = publicKeyOf(file, OPENSSH_PASSPHRASE);
        connectorMock.stubImportKeys(imported(publicKey));

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(file, OPENSSH_PASSPHRASE, entry(sha256(publicKey.getEncoded()), destination("ssh key"))));

        // then
        assertThat(results).singleElement().satisfies(key -> {
            assertThat(key.getKind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(key.isImported()).isTrue();
            assertThat(nameOfKey(key.getKeyUuid())).isEqualTo("ssh key");
        });
        connectorMock.verifyImportKeyRequests(1);
    }

    /**
     * No passphrase opens a file protected with an empty password, and its key goes to the key import with an empty
     * one.
     */
    @Test
    void importCertificates_importsTheKeyPairOfAFileProtectedWithAnEmptyPassword() throws Exception {
        // given
        byte[] file = Pkcs12Fixtures.openSsl(Pkcs12Fixtures.OPENSSL_EMPTY_PASSWORD);
        PublicKey publicKey = publicKeyOf(file, new char[0]);
        connectorMock.stubImportKeys(imported(publicKey));

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(file, null, entry(sha256(publicKey.getEncoded()), destination(null))));

        // then
        assertThat(results).singleElement().satisfies(keyPair -> {
            assertThat(keyPair.getKind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(keyPair.isImported()).isTrue();
            assertThat(nameOfKey(keyPair.getKeyUuid())).isEqualTo(Pkcs12Fixtures.OPENSSL_ALIAS);
        });
        connectorMock.verifyImportKeyRequests(1);
    }

    /**
     * The key import names its key in the record; the record names the certificate the request produced instead, and
     * the certificate and the key as the operation's data.
     */
    @Test
    void importCertificates_isAudited() throws Exception {
        // given
        auditLogs(false);
        connectorMock.stubImportKeys(imported(chain.leafKey().getPublic()));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));

        // when
        List<CertificateImportResultDto> results = importCertificates(
                request(keyPairPem(), null, entry(keyPairReference(), destination("audited key"))));

        // then
        CertificateImportResultDto keyPair = results.getFirst();
        AuditLog auditRecord = importAuditRecord();
        assertThat(auditRecord.getOperationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.getResource()).isEqualTo(Resource.CERTIFICATE);
        assertThat(auditRecord.getLogRecord().resource().objects()).singleElement().satisfies(certificate -> {
            assertThat(certificate.uuid()).hasToString(keyPair.getCertificateUuid());
            assertThat(certificate.name()).isNotBlank();
        });
        assertThat(auditRecord.getLogRecord().operationData())
                .isEqualTo(Map
                        .of("certificateUuids", List.of(keyPair.getCertificateUuid()), "keyUuids",
                                List.of(keyPair.getKeyUuid())));
    }

    /**
     * A key-only import produces no certificate, so its record names no object, and the key is named in the operation's
     * data.
     */
    @Test
    void importCertificates_isAuditedWithTheKeyOfAKeyOnlyImport() throws Exception {
        // given
        auditLogs(false);
        connectorMock.stubImportKeys(imported(chain.intermediateKey().getPublic()));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        CertificateImportRequestDto request = request(
                ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(chain.intermediateKey())), null,
                entry(sha256(chain.intermediateKey().getPublic().getEncoded()), destination("key only")));

        // when
        List<CertificateImportResultDto> results = importCertificates(request);

        // then
        AuditLog auditRecord = importAuditRecord();
        assertThat(auditRecord.getOperationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.getLogRecord().resource().objects()).isNullOrEmpty();
        assertThat(auditRecord.getLogRecord().operationData())
                .isEqualTo(Map.of("certificateUuids", List.of(), "keyUuids", List.of(results.getFirst().getKeyUuid())));
    }

    /**
     * An operator may turn on debug logging and verbose audit; neither may show the passphrase, the file or a key it
     * holds, whether the import succeeds, the file does not open or the connector refuses in words of its own. The
     * request's own copies are overwritten once the file is read.
     */
    @Test
    void importCertificates_neverRevealsThePassphraseOrKeys() throws Exception {
        // given
        auditLogs(true);
        SecretKey secretKey = aes();
        byte[] pkcs12 = pkcs12(secretKey);
        KeyPair refusedKey = rsa();
        PemObject protectedKey = ContainerFixtures.encryptedPrivateKeyBlock(refusedKey);
        byte[] refusedFile = ContainerFixtures.pem(LF, protectedKey);
        connectorMock
                .stubImportKeys(imported(chain.leafKey().getPublic()), importedSecretKey(),
                        ProblemDetailExtended
                                .fromErrorCode(ErrorCode.KEY_DECRYPTION_FAILED,
                                        "refused " + new String(ContainerFixtures.PASSPHRASE), null, null));
        CertificateImportRequestDto importing = request(pkcs12, PASSPHRASE,
                entry(keyPairReference(), destination("leaf key")),
                entry(referenceOf(pkcs12, PASSPHRASE, InspectedEntryKind.SECRET_KEY), destination("secret key")));
        char[] wrongPassphrase = "wrong passphrase".toCharArray();
        CertificateImportRequestDto unreadable = request(pkcs12, wrongPassphrase, entry(reference(other), null));
        CertificateImportRequestDto refused = request(refusedFile, ContainerFixtures.PASSPHRASE,
                entry(sha256(refusedKey.getPublic().getEncoded()), destination("refused key")));
        List<String> secrets = new ArrayList<>(List
                .of(new String(PASSPHRASE), new String(wrongPassphrase), new String(ContainerFixtures.PASSPHRASE),
                        base64(pkcs12), base64(refusedFile), base64(protectedKey.getContent()),
                        base64(secretKey.getEncoded()), HexFormat.of().formatHex(secretKey.getEncoded())));
        for (KeyPair key : List.of(chain.leafKey(), refusedKey)) {
            secrets.add(base64(key.getPrivate().getEncoded()));
            secrets.add(HexFormat.of().formatHex(key.getPrivate().getEncoded()));
        }
        secrets.addAll(heldKeys(pkcs12, PASSPHRASE));
        List<String> seen = new ArrayList<>();

        // when
        SecretLeakProbe probe = SecretLeakProbe.capture();
        try (probe) {
            seen
                    .add(ObjectMapperFactory
                            .wire()
                            .writeValueAsString(certificateController.importCertificates(importing)));
            seen.add(assertThrows(ValidationException.class, () -> importCertificates(unreadable)).getMessage());
            seen.add(ObjectMapperFactory.wire().writeValueAsString(certificateController.importCertificates(refused)));
        }

        // then
        seen.addAll(probe.logged());
        seen
                .addAll(jdbcTemplate
                        .queryForList("SELECT coalesce(message, '') || log_record::text FROM audit_log", String.class));
        seen.addAll(jdbcTemplate.queryForList("SELECT row_to_json(key_import)::text FROM key_import", String.class));
        for (CryptographicKeyEventHistory event : keyEventHistoryRepository.findAll()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        for (CertificateEventHistory event : certificateEventHistoryRepository.findAll()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        for (String body : connectorMock.importKeyRequestBodies()) {
            JsonNode sent = ObjectMapperFactory.wire().readTree(body);
            secrets.add(sent.get("passphrase").asText());
            secrets.add(sent.get("material").get("encryptedPrivateKeyInfo").asText());
        }
        assertThat(auditLogRepository.count()).isEqualTo(3);
        assertThat(connectorMock.importKeyRequestBodies()).hasSize(3);
        SecretLeakProbe.assertNoneReveals(seen, secrets.toArray(new String[0]));
        for (CertificateImportRequestDto request : List.of(importing, unreadable, refused)) {
            assertThat(request.getFile().length()).isZero();
            assertThat(request.getPassphrase().characters()).isEmpty();
        }
    }

    // ---- fixtures ----

    private List<CertificateImportResultDto> importCertificates(CertificateImportRequestDto request) throws Exception {
        return certificateController.importCertificates(request).getResults();
    }

    /** The key pair with its chain, the certificate that is in no chain, and the secret key, all in one file. */
    private static byte[] pkcs12(SecretKey secretKey) throws Exception {
        return Pkcs12Fixtures
                .builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", LEAF_KEY_ID)
                .secretBag(secretKey, PASSPHRASE, "secret")
                .encryptedSafe(PASSPHRASE, Pkcs12Fixtures.PBES2_AES_256)
                .certBag(chain.leaf(), "leaf", LEAF_KEY_ID)
                .certBag(chain.intermediate(), null, null)
                .certBag(chain.root(), null, null)
                .certBag(other, "other", null)
                .mac(PASSPHRASE, NISTObjectIdentifiers.id_sha256)
                .build();
    }

    /** The key pair with its chain, as PEM without protection, which names no alias. */
    private static byte[] keyPairPem() throws IOException {
        return ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.leaf(), chain.intermediate(),
                        chain.root());
    }

    /** A key without a certificate, two certificates in no chain and a certificate request. */
    private static byte[] rulesFile(X509CertificateHolder another) throws Exception {
        return ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.intermediateKey()), other, another, signingRequest);
    }

    private CertificateImportRequestDto keyPairAndCertificate(byte[] file) {
        return request(file, PASSPHRASE, entry(keyPairReference(), destination("leaf key")),
                entry(reference(other), null));
    }

    private static CertificateImportRequestDto request(byte[] file, char[] passphrase,
            CertificateImportEntryDto... entries) {
        CertificateImportRequestDto request = new CertificateImportRequestDto();
        request.setFile(new UploadedFile(file));
        request.setPassphrase(passphrase == null ? null : new Passphrase(passphrase));
        request.setEntries(List.of(entries));
        return request;
    }

    private static CertificateImportEntryDto entry(String reference, CertificateEntryKeyDestinationDto destination) {
        CertificateImportEntryDto entry = new CertificateImportEntryDto();
        entry.setEntryReference(reference);
        entry.setKeyDestination(destination);
        return entry;
    }

    private CertificateEntryKeyDestinationDto destination(String keyName) {
        return destinationTo(profile.getUuid().toString(), keyName);
    }

    private static CertificateEntryKeyDestinationDto destinationTo(String tokenProfileUuid, String keyName) {
        CertificateEntryKeyDestinationDto destination = new CertificateEntryKeyDestinationDto();
        destination.setTokenProfileUuid(tokenProfileUuid);
        destination.setKeyName(keyName);
        return destination;
    }

    private static String keyPairReference() {
        return sha256(chain.leafKey().getPublic().getEncoded());
    }

    private static String reference(X509CertificateHolder certificate) {
        try {
            return sha256(certificate.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The reference of the file's first entry of the kind, as the inspection reports it. */
    private String referenceOf(byte[] file, char[] passphrase, InspectedEntryKind kind) {
        Container container = containerReader.read(file, new Passphrase(passphrase));
        try {
            return container
                    .entries()
                    .stream()
                    .filter(entry -> entry.kind() == kind)
                    .map(ContainerEntry::reference)
                    .findFirst()
                    .orElseThrow();
        } finally {
            container.clear();
        }
    }

    /** The public key of the file's first key. */
    private PublicKey publicKeyOf(byte[] file, char[] passphrase) throws Exception {
        Container container = containerReader.read(file, new Passphrase(passphrase));
        try {
            KeyEntry key = container
                    .entries()
                    .stream()
                    .filter(KeyEntry.class::isInstance)
                    .map(KeyEntry.class::cast)
                    .findFirst()
                    .orElseThrow();
            return KeyFactory
                    .getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(key.description().subjectPublicKeyInfo()));
        } finally {
            container.clear();
        }
    }

    /** Each key of the file as the file holds it, base64-encoded, which is how a text rendering of it shows. */
    private List<String> heldKeys(byte[] file, char[] passphrase) {
        Container container = containerReader.read(file, new Passphrase(passphrase));
        try {
            return container
                    .entries()
                    .stream()
                    .filter(KeyEntry.class::isInstance)
                    .map(entry -> base64(((KeyEntry) entry).keyFile()))
                    .toList();
        } finally {
            container.clear();
        }
    }

    /** A key pair whose leaf the CA issued, as PEM holding the key, the leaf and the CA, to import under the name. */
    private CertificateImportRequestDto keyPairIssuedBy(X509CertificateHolder ca, KeyPair caKey, KeyPair key,
            String name) throws Exception {
        X509CertificateHolder leaf = ContainerFixtures
                .certificate("CN=" + name, key.getPublic(), ca.getSubject().toString(), caKey.getPrivate(),
                        Instant.now().minus(Duration.ofDays(1)));
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(key), leaf, ca);
        return request(file, null, entry(sha256(key.getPublic().getEncoded()), destination(name)));
    }

    /**
     * Holds the first registration of the certificate, in its transaction and past the check that the certificate is
     * not there yet, until a second registration of it has come as far.
     */
    private void holdTheFirstRegistrationUntilASecond(String fingerprint, CountDownLatch firstWaits,
            CountDownLatch secondArrives) {
        AtomicBoolean held = new AtomicBoolean();
        doAnswer(invocation -> {
            if (fingerprint.equals(invocation.getArgument(0))) {
                if (held.compareAndSet(false, true)) {
                    firstWaits.countDown();
                    awaitNode(secondArrives);
                } else {
                    secondArrives.countDown();
                }
            }
            return invocation.callRealMethod();
        }).when(certificateInternalService).checkAddCertificateContent(anyString(), anyString());
    }

    /**
     * The import as a node of its own serves it: on a thread of its own, so with connections of its own, for the caller
     * of the test.
     */
    private Callable<List<CertificateImportResultDto>> onNode(CertificateImportRequestDto request) {
        Authentication caller = SecurityContextHolder.getContext().getAuthentication();
        return () -> {
            SecurityContextHolder.getContext().setAuthentication(caller);
            try {
                return importCertificates(request);
            } finally {
                SecurityContextHolder.clearContext();
            }
        };
    }

    private static void awaitNode(CountDownLatch reached) throws InterruptedException {
        if (!reached.await(NODE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new IllegalStateException("A node did not come as far in time");
        }
    }

    private static ListAppender<ILoggingEvent> captureImportLog() {
        ListAppender<ILoggingEvent> importLog = new ListAppender<>();
        importLog.start();
        ((Logger) LoggerFactory.getLogger(CertificateImportServiceImpl.class)).addAppender(importLog);
        return importLog;
    }

    private static void releaseImportLog(ListAppender<ILoggingEvent> importLog) {
        ((Logger) LoggerFactory.getLogger(CertificateImportServiceImpl.class)).detachAppender(importLog);
    }

    /** A file holding only the key, imported under the name. */
    private CertificateImportRequestDto keyOnly(KeyPair key, String name) throws IOException {
        return request(ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(key)), null,
                entry(sha256(key.getPublic().getEncoded()), destination(name)));
    }

    /**
     * Brings the public key in as a certificate's, owned by another user, on a thread of its own and committed, when
     * the import first looks for it where the condition holds.
     */
    private void bringTheRecordInWhen(String fingerprint, KeyPair key, ExecutorService certificateUpload,
            BooleanSupplier condition) {
        meanwhileWhen(fingerprint, condition, certificateUpload, () -> {
            UUID recordUuid = certificateKeyWriter
                    .uploadCertificatePublicKey("certKey_raced", key.getPublic(), 2048, fingerprint);
            objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, UUID.randomUUID(), "another");
            return recordUuid;
        });
    }

    /**
     * Has another node do what it does meanwhile, on a thread of its own and committed, when the import first looks for
     * the public key where the condition holds: before the look, or right after it as the attempt completes.
     */
    private void meanwhileWhen(String fingerprint, BooleanSupplier condition, ExecutorService otherNode,
            Callable<?> meanwhile) {
        Thread importing = Thread.currentThread();
        AtomicBoolean done = new AtomicBoolean();
        // A repository is a proxy, whose real method a spy cannot call; the spy's own answer calls through to it.
        Answer<?> repository = Mockito
                .mockingDetails(cryptographicKeyItemRepository)
                .getMockCreationSettings()
                .getDefaultAnswer();
        doAnswer(invocation -> {
            boolean due = fingerprint.equals(invocation.getArgument(0)) && Thread.currentThread() == importing
                    && condition.getAsBoolean() && done.compareAndSet(false, true);
            if (due && registering()) {
                Object found = repository.answer(invocation);
                otherNode.submit(meanwhile).get(NODE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                return found;
            }
            if (due) {
                otherNode.submit(meanwhile).get(NODE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            return repository.answer(invocation);
        }).when(cryptographicKeyItemRepository).findByFingerprint(anyString());
    }

    /** Whether the call runs as the attempt completes, which registers the imported key. */
    private static boolean registering() {
        String transaction = TransactionSynchronizationManager.getCurrentTransactionName();
        return transaction != null && transaction.endsWith("KeyImportWriter.complete");
    }

    private boolean connectorWasAsked() {
        return !connectorMock.importKeyRequestBodies().isEmpty();
    }

    private boolean connectorWasAskedForTheResult() {
        return connectorMock.importKeyResultRequestsReceived() > 0;
    }

    /** The auth service answers for the caller, so a check made as the requester can resolve them. */
    private void authServiceKnowsTheRequester() {
        NameAndUuidDto caller = AuthHelper.getUserIdentification();
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.fromString(caller.getUuid()), caller.getName());
    }

    /** The audit record of the first import. */
    private AuditLog importAuditRecord() {
        return auditLogRepository
                .findAll()
                .stream()
                .filter(log -> log.getOperation() == Operation.IMPORT)
                .min(Comparator.comparing(AuditLog::getId))
                .orElseThrow();
    }

    /** The audit record of the last import. */
    private AuditLog lastImportAuditRecord() {
        return auditLogRepository
                .findAll()
                .stream()
                .filter(log -> log.getOperation() == Operation.IMPORT)
                .max(Comparator.comparing(AuditLog::getId))
                .orElseThrow();
    }

    private Certificate inventoried(X509CertificateHolder certificate) {
        return certificateRepository.findByFingerprint(reference(certificate)).orElseThrow();
    }

    /** Refuses the caller the detail of the one certificate, as the policy does for a certificate of someone else. */
    private void denyDetailOf(UUID certificateUuid) {
        when(opaClient
                .checkResourceAccess(Mockito.any(), Mockito
                        .argThat(requested -> requested != null && requested.getProperties() != null
                                && Resource.CERTIFICATE.getCode().equals(requested.getProperties().get("name"))
                                && ResourceAction.DETAIL.getCode().equals(requested.getProperties().get("action"))
                                && requested.getObjectUUIDs() != null
                                && requested.getObjectUUIDs().contains(certificateUuid.toString())),
                        Mockito.any(), Mockito.any()))
                .thenReturn(OpaResourceAccessResult.unauthorized());
    }

    /** Refuses the caller the detail of the one key, as the policy does for a key of someone else. */
    private void denyKeyDetailOf(UUID keyUuid) {
        when(opaClient
                .checkResourceAccess(Mockito.any(), Mockito
                        .argThat(requested -> requested != null && requested.getProperties() != null
                                && Resource.CRYPTOGRAPHIC_KEY.getCode().equals(requested.getProperties().get("name"))
                                && ResourceAction.DETAIL.getCode().equals(requested.getProperties().get("action"))
                                && requested.getObjectUUIDs() != null
                                && requested.getObjectUUIDs().contains(keyUuid.toString())),
                        Mockito.any(), Mockito.any()))
                .thenReturn(OpaResourceAccessResult.unauthorized());
    }

    private String nameOfKey(String keyUuid) {
        return cryptographicKeyRepository.findByUuid(UUID.fromString(keyUuid)).orElseThrow().getName();
    }

    private CustomAttributeV3 departmentAttribute() throws Exception {
        CustomAttributeV3 department = new CustomAttributeV3();
        department.setUuid(UUID.randomUUID().toString());
        department.setName("department");
        department.setType(AttributeType.CUSTOM);
        department.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Department");
        department.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(department, List.of(Resource.CERTIFICATE));
        return department;
    }

    private static RequestAttribute departmentValue(UUID definitionUuid) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(definitionUuid);
        attribute.setName("department");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3("Sales")));
        return attribute;
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

    private static byte[] openSsh(String name) throws IOException {
        try (InputStream in = CertificateImportITest.class
                .getClassLoader()
                .getResourceAsStream("key/openssh/" + name)) {
            if (in == null) {
                throw new IOException("No fixture " + name);
            }
            return in.readAllBytes();
        }
    }

    private static X509Certificate x509(X509CertificateHolder certificate) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(certificate);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static SecretKey aes() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    private static String base64(byte[] content) {
        return Base64.getEncoder().encodeToString(content);
    }
}
