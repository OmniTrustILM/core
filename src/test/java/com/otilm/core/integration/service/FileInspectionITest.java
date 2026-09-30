package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.InspectionController;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryDto;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.api.model.client.inspection.InspectionResponseDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.container.ContainerFixtures;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.key.normalization.JavaKeyStoreFixtures;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.container.ContainerFixtures.LF;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;

@SpringBootTest
class FileInspectionITest extends BaseSpringBootTest {

    private static final byte[] NOT_A_FILE = "not a certificate or a key".getBytes(StandardCharsets.US_ASCII);

    private static Chain chain;

    @Autowired
    private InspectionController inspectionController;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private KeyImportRepository keyImportRepository;
    @Autowired
    private SettingExternalService settingService;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private TokenProfile profile;

    @BeforeAll
    static void keys() throws Exception {
        ContainerFixtures.registerProviders();
        chain = ContainerFixtures.rsaChain();
    }

    @BeforeEach
    void setUp() throws Exception {
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        profile = v2Token.profile();
        connectorMock.stubImportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void inspect_listsWhatAFileHolds() throws Exception {
        // given
        X509CertificateHolder other = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Other");
        PKCS10CertificationRequest signingRequest = ContainerFixtures.signingRequest(chain.intermediateKey());
        byte[] file = ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.leaf(), chain.intermediate(),
                        chain.root(), other, signingRequest);

        // when
        InspectionResponseDto inspection = inspectionController.inspect(request(file, null, null));

        // then
        assertThat(inspection.getContainerDigest()).isEqualTo(sha256(file));
        assertThat(inspection.getEntries())
                .extracting(InspectedEntryDto::getKind, InspectedEntryDto::getEntryReference)
                .containsExactly(
                        tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, sha256(chain.leafKey().getPublic().getEncoded())),
                        tuple(InspectedEntryKind.CERTIFICATE, sha256(other.getEncoded())),
                        tuple(InspectedEntryKind.SIGNING_REQUEST, sha256(signingRequest.getEncoded())));
        assertThat(inspection.getEntries().getFirst()).satisfies(keyPair -> {
            assertThat(keyPair.getSubjectDn()).isEqualTo("CN=Leaf");
            assertThat(keyPair.getIssuerDn()).isEqualTo("CN=Intermediate");
            assertThat(keyPair.getFingerprint()).isEqualTo(sha256(chain.leaf().getEncoded()));
            assertThat(keyPair.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
            assertThat(keyPair.getKeyLength()).isEqualTo(2048);
            assertThat(keyPair.getChainLength()).isEqualTo(3);
        });
        assertThat(inspection.getEntries().get(1).getSubjectDn()).isEqualTo("CN=Other");
        assertThat(inspection.getEntries().get(2).getSubjectDn()).isEqualTo("CN=Request");
        assertThat(inspection.getEntries()).allSatisfy(entry -> {
            assertThat(entry.getImportable()).isNull();
            assertThat(entry.getNotImportableReason()).isNull();
        });
        connectorMock.verifyImportableKeyTypesRequests(0);
    }

    /** The profile's answer is asked for once and recorded, so the second inspection reads it. */
    @Test
    void inspect_reportsImportabilityForANamedProfile() throws Exception {
        // given
        byte[] rsaFile = ContainerFixtures
                .pem(LF, chain.leaf(), ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.root());
        byte[] ecFile = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(ContainerFixtures.ec()));
        String profileUuid = profile.getUuid().toString();

        // when
        InspectionResponseDto rsa = inspectionController.inspect(request(rsaFile, null, profileUuid));
        InspectionResponseDto ecdsa = inspectionController.inspect(request(ecFile, null, profileUuid));

        // then
        assertThat(rsa.getEntries())
                .extracting(InspectedEntryDto::getKind, InspectedEntryDto::getImportable,
                        InspectedEntryDto::getNotImportableReason)
                .containsExactly(tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, true, null),
                        tuple(InspectedEntryKind.CERTIFICATE, null, null));
        assertThat(ecdsa.getEntries()).singleElement().satisfies(key -> {
            assertThat(key.getKind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(key.getImportable()).isFalse();
            assertThat(key.getNotImportableReason())
                    .isEqualTo("Token profile " + profile.getName()
                            + " does not import the ECDSA algorithm for a key pair.");
        });
        connectorMock.verifyImportableKeyTypesRequests(1);
    }

    @Test
    void inspect_reportsImportabilityForEachKindOfKeyAStoreHoldsFromOneAnswer() throws Exception {
        // given
        KeyPair ec = ContainerFixtures.ec();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        KeyStore.PrivateKeyEntry rsaEntry = new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(),
                new X509Certificate[]{converter.getCertificate(chain.leaf())});
        KeyStore.PrivateKeyEntry ecEntry = new KeyStore.PrivateKeyEntry(ec.getPrivate(),
                new X509Certificate[]{converter.getCertificate(ContainerFixtures.selfSigned(ec, "CN=EC"))});
        byte[] store = JavaKeyStoreFixtures.jks(ContainerFixtures.PASSPHRASE, Map.of("rsa", rsaEntry, "ec", ecEntry));

        // when
        InspectionResponseDto inspection = inspectionController
                .inspect(request(store, ContainerFixtures.PASSPHRASE, profile.getUuid().toString()));

        // then
        assertThat(inspection.getEntries())
                .extracting(InspectedEntryDto::getKeyAlgorithm, InspectedEntryDto::getImportable,
                        InspectedEntryDto::getNotImportableReason)
                .containsExactlyInAnyOrder(tuple(KeyAlgorithm.RSA, true, null), tuple(KeyAlgorithm.ECDSA, false,
                        "Token profile " + profile.getName() + " does not import the ECDSA algorithm for a key pair."));
        connectorMock.verifyImportableKeyTypesRequests(1);
    }

    @Test
    void inspect_reportsAKeyOfAnAlgorithmThePlatformDoesNotSupportAsNotImportable() throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(ContainerFixtures.ed25519()));

        // when
        InspectionResponseDto inspection = inspectionController
                .inspect(request(file, null, profile.getUuid().toString()));

        // then
        assertThat(inspection.getEntries()).singleElement().satisfies(key -> {
            assertThat(key.getImportable()).isFalse();
            assertThat(key.getNotImportableReason()).isEqualTo("The platform does not support the key's algorithm.");
        });
    }

    /** What the connector cannot answer is not importable now; the file is still listed. */
    @Test
    void inspect_reportsKeysAsNotImportableWhenTheConnectorDoesNotAnswer() throws Exception {
        // given
        connectorMock.stubImportableKeyTypesFailing();
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()));

        // when
        InspectionResponseDto inspection = inspectionController
                .inspect(request(file, null, profile.getUuid().toString()));

        // then
        assertThat(inspection.getEntries()).singleElement().satisfies(key -> {
            assertThat(key.getImportable()).isFalse();
            assertThat(key.getNotImportableReason())
                    .isEqualTo("The connector of token profile " + profile.getName()
                            + " did not answer what the profile imports. Try again.");
        });
    }

    /** Nothing is read for a caller who may not inspect: the file is refused only after the caller is. */
    @Test
    void inspect_refusesACallerWithoutCertificateCreateOrKeyImport() {
        // given
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.CREATE);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        InspectionRequestDto request = request(NOT_A_FILE, null, profile.getUuid().toString());

        // when
        AccessDeniedException refusal = assertThrows(AccessDeniedException.class,
                () -> inspectionController.inspect(request));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("Access denied to %s:%s"
                        .formatted(Resource.CRYPTOGRAPHIC_KEY.getCode(), ResourceAction.IMPORT_KEY.getCode()));
        connectorMock.verifyImportableKeyTypesRequests(0);
    }

    @Test
    void inspect_letsAKeyImporterInspect() throws Exception {
        // given
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.CREATE);
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()));

        // when
        InspectionResponseDto inspection = inspectionController
                .inspect(request(file, null, profile.getUuid().toString()));

        // then
        assertThat(inspection.getEntries()).singleElement().satisfies(key -> assertThat(key.getImportable()).isTrue());
    }

    @Test
    void inspect_letsACertificateCreatorInspectWithoutAProfile() throws Exception {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        byte[] file = ContainerFixtures.pem(LF, chain.leaf());

        // when
        InspectionResponseDto inspection = inspectionController.inspect(request(file, null, null));

        // then
        assertThat(inspection.getEntries())
                .singleElement()
                .satisfies(certificate -> assertThat(certificate.getSubjectDn()).isEqualTo("CN=Leaf"));
    }

    /** Naming a profile takes the checks the key import makes on it, before the file is read. */
    @ParameterizedTest
    @CsvSource({"CRYPTOGRAPHIC_KEY, IMPORT_KEY", "TOKEN_PROFILE, DETAIL", "TOKEN, DETAIL", "TOKEN, MEMBERS"})
    void inspect_refusesACallerWhoMayNotImportIntoTheNamedProfile(Resource resource, ResourceAction action) {
        // given
        denyResourceAccess(resource, action);
        InspectionRequestDto request = request(NOT_A_FILE, null, profile.getUuid().toString());

        // when
        assertThrows(AccessDeniedException.class, () -> inspectionController.inspect(request));

        // then
        connectorMock.verifyImportableKeyTypesRequests(0);
    }

    @Test
    void inspect_answersNotFoundForAnUnknownProfile() throws Exception {
        // given
        InspectionRequestDto request = request(ContainerFixtures.pem(LF, chain.leaf()), null,
                UUID.randomUUID().toString());

        // when
        // then
        assertThrows(NotFoundException.class, () -> inspectionController.inspect(request));
    }

    @Test
    void inspect_refusesATokenProfileUuidThatIsNotAUuid() throws Exception {
        // given
        InspectionRequestDto request = request(ContainerFixtures.pem(LF, chain.leaf()), null, "not-a-uuid");

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> inspectionController.inspect(request));

        // then
        assertThat(refusal.getMessage()).isEqualTo("tokenProfileUuid must be a UUID");
    }

    @Test
    void inspect_storesNothing() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.leaf(), chain.intermediate(),
                        chain.root(), ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Other"));

        // when
        inspectionController.inspect(request(file, null, profile.getUuid().toString()));

        // then
        assertThat(certificateRepository.count()).isZero();
        assertThat(cryptographicKeyRepository.count()).isZero();
        assertThat(cryptographicKeyItemRepository.count()).isZero();
        assertThat(keyImportRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(0);
    }

    @Test
    void inspect_isAudited() throws Exception {
        // given
        auditLogs(false);
        byte[] file = ContainerFixtures.pem(LF, chain.leaf());

        // when
        inspectionController.inspect(request(file, null, profile.getUuid().toString()));

        // then
        assertThat(auditRecords()).singleElement().satisfies(auditRecord -> {
            assertThat(auditRecord.operation()).isEqualTo(Operation.INSPECT);
            assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
            assertThat(auditRecord.module()).isEqualTo(Module.CERTIFICATES);
            assertThat(auditRecord.resource().type()).isEqualTo(Resource.CERTIFICATE);
            assertThat(auditRecord.affiliatedResource().type()).isEqualTo(Resource.TOKEN_PROFILE);
            assertThat(auditRecord.affiliatedResource().objects())
                    .extracting(ResourceObjectIdentity::uuid, ResourceObjectIdentity::name)
                    .containsExactly(tuple(profile.getUuid(), profile.getName()));
        });
    }

    /**
     * An operator may turn on debug logging and verbose audit; neither may show the file, its passphrase or its key,
     * whether the file opens or not. The request's own copies are overwritten once the file is read.
     */
    @Test
    void inspect_neverRevealsThePassphraseOrKey() throws Exception {
        // given
        auditLogs(true);
        KeyPair key = chain.leafKey();
        PemObject protectedKey = ContainerFixtures.encryptedPrivateKeyBlock(key);
        byte[] file = ContainerFixtures.pem(LF, chain.leaf(), protectedKey);
        char[] wrongPassphrase = "wrong passphrase".toCharArray();
        String profileUuid = profile.getUuid().toString();
        InspectionRequestDto opened = request(file, ContainerFixtures.PASSPHRASE, profileUuid);
        InspectionRequestDto refused = request(file, wrongPassphrase, profileUuid);
        List<String> seen = new ArrayList<>();

        // when
        SecretLeakProbe probe = SecretLeakProbe.capture();
        try (probe) {
            seen.add(ObjectMapperFactory.wire().writeValueAsString(inspectionController.inspect(opened)));
            seen.add(assertThrows(ValidationException.class, () -> inspectionController.inspect(refused)).getMessage());
        }

        // then
        seen.addAll(probe.logged());
        List<LogRecord> auditRecords = auditRecords();
        assertThat(auditRecords).hasSize(2);
        for (LogRecord auditRecord : auditRecords) {
            seen.add(ObjectMapperFactory.wire().writeValueAsString(auditRecord));
        }
        List<String> secrets = List
                .of(new String(ContainerFixtures.PASSPHRASE), new String(wrongPassphrase),
                        Base64.getEncoder().encodeToString(file), encryptedKeyLine(file),
                        Base64.getEncoder().encodeToString(protectedKey.getContent()),
                        Base64.getEncoder().encodeToString(key.getPrivate().getEncoded()),
                        HexFormat.of().formatHex(key.getPrivate().getEncoded()));
        SecretLeakProbe.assertNoneReveals(seen, secrets.toArray(new String[0]));
        assertThat(opened.getFile().length()).isZero();
        assertThat(opened.getPassphrase().characters()).isEmpty();
        assertThat(refused.getFile().length()).isZero();
        assertThat(refused.getPassphrase().characters()).isEmpty();
    }

    /** A line of the encrypted key's body as the file wraps it, which is what printing the file's text shows. */
    private static String encryptedKeyLine(byte[] file) {
        List<String> lines = new String(file, StandardCharsets.US_ASCII).lines().toList();
        int begin = lines.indexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        assertThat(begin).isNotNegative();
        return lines.get(begin + 2);
    }

    private static InspectionRequestDto request(byte[] file, char[] passphrase, String tokenProfileUuid) {
        InspectionRequestDto request = new InspectionRequestDto();
        request.setFile(new UploadedFile(file));
        request.setPassphrase(passphrase == null ? null : new Passphrase(passphrase));
        request.setTokenProfileUuid(tokenProfileUuid);
        return request;
    }

    /** The records the audit queue was handed, which is where an inspection's record goes. */
    private List<LogRecord> auditRecords() {
        ArgumentCaptor<AuditLogMessage> sent = ArgumentCaptor.forClass(AuditLogMessage.class);
        verify(auditLogsProducer, atLeastOnce()).produceMessage(sent.capture());
        return sent.getAllValues().stream().map(AuditLogMessage::getLogRecord).toList();
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
}
