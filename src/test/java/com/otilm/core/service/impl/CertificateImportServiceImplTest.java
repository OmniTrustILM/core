package com.otilm.core.service.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.api.model.client.certificate.CertificateImportResultDto;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.container.CertificateEntry;
import com.otilm.core.container.Container;
import com.otilm.core.container.ContainerEntry;
import com.otilm.core.container.ContainerFixtures;
import com.otilm.core.container.ContainerReader;
import com.otilm.core.container.KeyEntry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyImportSaga;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.UnexpectedRollbackException;

import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * What an entry comes to when a concurrent request registers its certificate first, or when it fails in a way the
 * database and the connector cannot be made to stage.
 */
class CertificateImportServiceImplTest {

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    private static final String NOT_IMPORTED = "The entry could not be imported. Retry it, or see the Core log for why.";

    private static X509CertificateHolder certificate;

    private final AuthorizationEnforcer authorizationEnforcer = mock(AuthorizationEnforcer.class);
    private final KeyImportGates keyImportGates = mock(KeyImportGates.class);
    private final ContainerReader containerReader = mock(ContainerReader.class);
    private final CryptographicKeyImportExternalService keyImport = mock(CryptographicKeyImportExternalService.class);
    private final CertificateUploadService upload = mock(CertificateUploadService.class);
    private final CertificateRepository certificates = mock(CertificateRepository.class);
    private final CertificateImportServiceImpl service = new CertificateImportServiceImpl(authorizationEnforcer,
            keyImportGates, containerReader, keyImport, upload, certificates, mock(AttributeEngine.class));

    @BeforeAll
    static void issueCertificate() throws Exception {
        ContainerFixtures.registerProviders();
        certificate = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Concurrent");
    }

    @AfterEach
    void clearAuditResource() {
        LoggingHelper.clearLogResourceObject();
    }

    @Test
    void importCertificates_takesACertificateARequestRegisteredSinceItWasLookedUp() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        Certificate registered = new Certificate();
        registered.setUuid(UUID.randomUUID());
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty(), Optional.of(registered));
        when(upload.upload(any(), any(), eq(true))).thenThrow(new AlreadyExistException("registered meanwhile"));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getCertificateOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(result.getCertificateUuid()).isEqualTo(registered.getUuid().toString());
        });
    }

    /**
     * The upload checks that the certificate is not there before it inserts it, so an upload racing another of the same
     * certificate fails on the unique fingerprint once the other commits. The entry takes what the other registered.
     */
    @Test
    void importCertificates_takesACertificateAnUploadRacingThisOneRegistered() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        Certificate registered = new Certificate();
        registered.setUuid(UUID.randomUUID());
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty(), Optional.of(registered));
        when(upload.upload(any(), any(), eq(true)))
                .thenThrow(new DataIntegrityViolationException("duplicate key value violates unique constraint"));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();

        // when
        List<CertificateImportResultDto> results = importLogging(request, logs);

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getCertificateOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(result.getCertificateUuid()).isEqualTo(registered.getUuid().toString());
        });
        assertThat(logs.list).isEmpty();
    }

    /**
     * The upload refuses a certificate it cannot read, or custom attributes it does not accept, in words of its own.
     * With no other request having registered the certificate, the refusal is the entry's.
     */
    @Test
    void importCertificates_failsAnEntryWithTheUploadsRefusal() throws Exception {
        // given
        String refused = "Uploaded certificate content has invalid or unsupported format.";
        CertificateImportRequestDto request = certificateRequest();
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty());
        when(upload.upload(any(), any(), eq(true))).thenThrow(new ValidationException(refused));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();

        // when
        List<CertificateImportResultDto> results = importLogging(request, logs);

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getCertificateOutcome()).isNull();
            assertThat(result.getMessage()).isEqualTo(refused);
        });
        verify(certificates, times(2)).findByFingerprint(reference());
        assertThat(logs.list).isEmpty();
    }

    /**
     * A denial of permission during the upload is not a failed insert, so it refuses the request even when the
     * certificate is there by the time it would be looked up again.
     */
    @Test
    void importCertificates_letsADenialDuringTheUploadRefuseTheRequest() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        Certificate registered = new Certificate();
        registered.setUuid(UUID.randomUUID());
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty(), Optional.of(registered));
        when(upload.upload(any(), any(), eq(true))).thenThrow(new AccessDeniedException("denied"));

        // when
        // then
        assertThrows(AccessDeniedException.class, () -> service.importCertificates(request));
        verify(certificates).findByFingerprint(reference());
    }

    /** When no other request registered the certificate, the upload's failure is the entry's. */
    @Test
    void importCertificates_failsAnEntryWhoseUploadFailedWithNoOtherRegisteringItsCertificate() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty());
        when(upload.upload(any(), any(), eq(true))).thenThrow(new UnexpectedRollbackException("rolled back"));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();

        // when
        List<CertificateImportResultDto> results = importLogging(request, logs);

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getCertificateOutcome()).isNull();
            assertThat(result.getMessage()).isEqualTo(NOT_IMPORTED);
        });
        verify(certificates, times(2)).findByFingerprint(reference());
        assertThat(logs.list).singleElement().satisfies(warning -> {
            assertThat(warning.getLevel()).isEqualTo(Level.WARN);
            assertThat(warning.getThrowableProxy().getMessage()).isEqualTo("rolled back");
        });
    }

    /** The refusal to show the certificate names it by its outcome only; it does not refuse the request. */
    @Test
    void importCertificates_leavesOutTheUuidOfACertificateTheCallerMayNotSee() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        Certificate registered = new Certificate();
        registered.setUuid(UUID.randomUUID());
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.of(registered));
        doThrow(new AccessDeniedException("denied"))
                .when(authorizationEnforcer)
                .enforce(eq(Resource.CERTIFICATE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getCertificateOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(result.getCertificateUuid()).isNull();
        });
        verifyNoInteractions(upload);
    }

    /**
     * The words of a failure the platform did not write are not repeated to the caller, who is sent to the Core log for
     * them: a warning there names the entry and carries the failure.
     */
    @Test
    void importCertificates_reportsAnUnexpectedFailureWithoutItsWords() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        when(certificates.findByFingerprint(reference()))
                .thenThrow(new IllegalStateException("could not execute statement [select from certificate]"));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();

        // when
        List<CertificateImportResultDto> results = importLogging(request, logs);

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getMessage()).isEqualTo(NOT_IMPORTED);
        });
        assertThat(logs.list).singleElement().satisfies(warning -> {
            assertThat(warning.getLevel()).isEqualTo(Level.WARN);
            assertThat(warning.getFormattedMessage()).contains(reference());
            assertThat(warning.getThrowableProxy().getMessage()).contains("could not execute statement");
        });
    }

    /** The key import's own words stand for the entry, and its copies of the key and the passphrase are overwritten. */
    @Test
    void importCertificates_reportsTheKeyImportsOutcomeAndOverwritesWhatItHandedOver() throws Exception {
        // given
        KeyImportRequestDto[] handedOver = new KeyImportRequestDto[1];
        CertificateImportRequestDto request = keyRequest();
        when(keyImport.importKeyWithOutcome(any(), any(), eq(KeyRequestType.KEY_PAIR), any()))
                .thenAnswer(invocation -> {
                    handedOver[0] = invocation.getArgument(3);
                    throw new ConnectorServerException(KeyImportSaga.UNCONFIRMED, HttpStatus.BAD_GATEWAY);
                });

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getMessage()).isEqualTo(KeyImportSaga.UNCONFIRMED);
        });
        assertThat(handedOver[0].getName()).isEqualTo("the key");
        assertThat(handedOver[0].getFile().length()).isZero();
        assertThat(handedOver[0].getInputPassphrase().characters()).isEmpty();
        assertThat(request.getPassphrase().characters()).isEqualTo(PASSPHRASE);
    }

    @Test
    void importCertificates_letsAnEntryDeniedAccessRefuseTheRequest() throws Exception {
        // given
        CertificateImportRequestDto request = keyRequest();
        when(keyImport.importKeyWithOutcome(any(), any(), any(), any())).thenThrow(new AccessDeniedException("denied"));

        // when
        // then
        assertThrows(AccessDeniedException.class, () -> service.importCertificates(request));
    }

    /** The refusal to show a key the inventory held already names it by its outcome only; it refuses nothing. */
    @Test
    void importCertificates_leavesOutTheUuidOfAKeyTheCallerMayNotSee() throws Exception {
        // given
        CertificateImportRequestDto request = keyRequest();
        ImportedKey existing = new ImportedKey(key(UUID.randomUUID()), ImportOutcome.EXISTING);
        when(keyImport.importKeyWithOutcome(any(), any(), any(), any())).thenReturn(existing);
        doThrow(new AccessDeniedException("denied"))
                .when(authorizationEnforcer)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getKeyOutcome()).isEqualTo(ImportOutcome.EXISTING);
            assertThat(result.getKeyUuid()).isNull();
        });
    }

    /**
     * Whether the caller may see the key is asked once, as part of the entry: a failure to answer fails that entry, as
     * any other failure does, and leaves the rest of the request to go on.
     */
    @Test
    void importCertificates_failsOnlyTheEntryWhoseKeyCannotBeShown() throws Exception {
        // given
        CertificateImportRequestDto request = keyRequest();
        ImportedKey existing = new ImportedKey(key(UUID.randomUUID()), ImportOutcome.EXISTING);
        when(keyImport.importKeyWithOutcome(any(), any(), any(), any())).thenReturn(existing);
        doThrow(new IllegalStateException("the policy could not be asked"))
                .when(authorizationEnforcer)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();

        // when
        List<CertificateImportResultDto> results = importLogging(request, logs);

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid, CertificateImportResultDto::getMessage)
                .containsExactly(false, null, null, NOT_IMPORTED);
        verify(authorizationEnforcer)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        assertThat(logs.list)
                .singleElement()
                .satisfies(warning -> assertThat(warning.getThrowableProxy().getMessage())
                        .isEqualTo("the policy could not be asked"));
    }

    /** A key the call created or adopted is the caller's to see, so its UUID is named without asking. */
    @ParameterizedTest
    @EnumSource(value = ImportOutcome.class, names = {"CREATED", "ADOPTED"})
    void importCertificates_namesAKeyTheCallMadeOrAdoptedByItsUuid(ImportOutcome outcome) throws Exception {
        // given
        CertificateImportRequestDto request = keyRequest();
        UUID keyUuid = UUID.randomUUID();
        ImportedKey imported = new ImportedKey(key(keyUuid), outcome);
        when(keyImport.importKeyWithOutcome(any(), any(), any(), any())).thenReturn(imported);

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results)
                .singleElement()
                .extracting(CertificateImportResultDto::isImported, CertificateImportResultDto::getKeyOutcome,
                        CertificateImportResultDto::getKeyUuid)
                .containsExactly(true, outcome, keyUuid.toString());
        verify(authorizationEnforcer, never())
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    private static CryptographicKeyFullModel key(UUID uuid) {
        CryptographicKeyFullModel key = mock(CryptographicKeyFullModel.class);
        when(key.uuid()).thenReturn(uuid);
        return key;
    }

    /** The results of the import, with what the service logged meanwhile captured instead of written out. */
    private List<CertificateImportResultDto> importLogging(CertificateImportRequestDto request,
            ListAppender<ILoggingEvent> logs) throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(CertificateImportServiceImpl.class);
        boolean additive = logger.isAdditive();
        logs.start();
        logger.addAppender(logs);
        logger.setAdditive(false);
        try {
            return service.importCertificates(request).getResults();
        } finally {
            logger.setAdditive(additive);
            logger.detachAppender(logs);
        }
    }

    private CertificateImportRequestDto certificateRequest() throws Exception {
        whenTheFileHolds(new CertificateEntry(reference(), null, certificate));
        return request(entry(reference(), null));
    }

    /** A key without a certificate going to a profile the caller may import into. */
    private CertificateImportRequestDto keyRequest() throws Exception {
        String reference = sha256(new byte[]{4});
        whenTheFileHolds(new KeyEntry(reference, "the key", new byte[]{1, 2, 3},
                new KeyDescription(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, 2048, new byte[]{4}, null), null,
                List.of(), false));
        UUID profileUuid = UUID.randomUUID();
        TokenInstanceFullModel token = mock(TokenInstanceFullModel.class);
        when(token.uuid()).thenReturn(UUID.randomUUID());
        TokenProfileFullModel profile = mock(TokenProfileFullModel.class);
        when(profile.uuid()).thenReturn(profileUuid);
        when(profile.tokenInstance()).thenReturn(token);
        when(keyImportGates.requireAccess(profileUuid)).thenReturn(profile);
        CertificateEntryKeyDestinationDto destination = new CertificateEntryKeyDestinationDto();
        destination.setTokenProfileUuid(profileUuid.toString());
        return request(entry(reference, destination));
    }

    private void whenTheFileHolds(ContainerEntry entry) {
        when(containerReader.read(any(), any())).thenReturn(new Container("digest", List.of(entry)));
    }

    private static CertificateImportRequestDto request(CertificateImportEntryDto entry) {
        CertificateImportRequestDto request = new CertificateImportRequestDto();
        request.setFile(new UploadedFile(new byte[]{5, 6, 7, 8}));
        request.setPassphrase(new Passphrase(PASSPHRASE));
        request.setEntries(List.of(entry));
        return request;
    }

    private static CertificateImportEntryDto entry(String reference, CertificateEntryKeyDestinationDto destination) {
        CertificateImportEntryDto entry = new CertificateImportEntryDto();
        entry.setEntryReference(reference);
        entry.setKeyDestination(destination);
        return entry;
    }

    private static String reference() throws Exception {
        return sha256(certificate.getEncoded());
    }
}
