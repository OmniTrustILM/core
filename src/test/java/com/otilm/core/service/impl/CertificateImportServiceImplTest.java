package com.otilm.core.service.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.api.model.client.certificate.CertificateImportResultDto;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.logging.enums.AuthMethod;
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
import com.otilm.core.dao.entity.CertificateImportEntryState;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.certificate.CertificateImportRecord;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.writer.CertificateImportWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * What an entry comes to when a concurrent request records or registers it first, or when it fails in a way the
 * database and the connector cannot be made to stage.
 */
class CertificateImportServiceImplTest {

    private static final UUID REQUESTER = UUID.randomUUID();

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    private static X509CertificateHolder certificate;

    private final AuthorizationEnforcer authorizationEnforcer = mock(AuthorizationEnforcer.class);
    private final KeyImportGates keyImportGates = mock(KeyImportGates.class);
    private final ContainerReader containerReader = mock(ContainerReader.class);
    private final CertificateImportWriter writer = mock(CertificateImportWriter.class);
    private final CryptographicKeyImportExternalService keyImport = mock(CryptographicKeyImportExternalService.class);
    private final CertificateUploadService upload = mock(CertificateUploadService.class);
    private final CertificateRepository certificates = mock(CertificateRepository.class);
    private final CertificateImportServiceImpl service = new CertificateImportServiceImpl(authorizationEnforcer,
            keyImportGates, containerReader, writer, keyImport, upload, certificates, mock(AttributeEngine.class));

    @BeforeAll
    static void issueCertificate() throws Exception {
        ContainerFixtures.registerProviders();
        certificate = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Concurrent");
    }

    @BeforeEach
    void authenticate() {
        AuthenticationInfo requester = new AuthenticationInfo(AuthMethod.USER_PROXY, REQUESTER.toString(), "requester",
                List.of());
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(requester)));
    }

    @AfterEach
    void clearAuthenticationAndAuditResource() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearLogResourceObject();
    }

    @Test
    void importCertificates_answersAnEntryARequestCompletedSinceItWasLookedUp() throws Exception {
        // given
        UUID registered = UUID.randomUUID();
        CertificateImportRequestDto request = certificateRequest();
        when(writer.open(eq(REQUESTER), eq(importIdOf(request)), anyString()))
                .thenReturn(recorded(CertificateImportEntryState.COMPLETED, registered));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getCertificateUuid()).isEqualTo(registered.toString());
        });
        verifyNoInteractions(upload);
        verify(writer, never()).complete(any(), any(), any());
    }

    @Test
    void importCertificates_refusesAnEntryWhoseImportIdARequestUsedSinceItWasLookedUp() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        when(writer.open(eq(REQUESTER), eq(importIdOf(request)), anyString()))
                .thenThrow(new AlreadyExistException("Object of type 'CertificateImportEntry' already exists."));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getMessage())
                    .isEqualTo("The importId of entry " + reference() + " was already used to import something else.");
        });
        verifyNoInteractions(upload);
    }

    @Test
    void importCertificates_takesACertificateARequestRegisteredSinceItWasLookedUp() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        CertificateImportRecord opened = recorded(CertificateImportEntryState.OPEN, null);
        when(writer.open(eq(REQUESTER), eq(importIdOf(request)), anyString())).thenReturn(opened);
        Certificate registered = new Certificate();
        registered.setUuid(UUID.randomUUID());
        when(certificates.findByFingerprint(reference())).thenReturn(Optional.empty(), Optional.of(registered));
        when(upload.upload(any(), any(), eq(true))).thenThrow(new AlreadyExistException("registered meanwhile"));

        // when
        List<CertificateImportResultDto> results = service.importCertificates(request).getResults();

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isTrue();
            assertThat(result.getCertificateUuid()).isEqualTo(registered.getUuid().toString());
        });
        verify(writer).complete(opened.uuid(), registered.getUuid(), null);
    }

    /**
     * The words of a failure the platform did not write are not repeated to the caller, who is sent to the Core log for
     * them: a warning there names the entry and carries the failure. A replay retries the entry.
     */
    @Test
    void importCertificates_reportsAnUnexpectedFailureWithoutItsWords() throws Exception {
        // given
        CertificateImportRequestDto request = certificateRequest();
        when(writer.open(eq(REQUESTER), eq(importIdOf(request)), anyString()))
                .thenReturn(recorded(CertificateImportEntryState.OPEN, null));
        when(certificates.findByFingerprint(reference()))
                .thenThrow(new IllegalStateException("could not execute statement [select from certificate]"));
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(CertificateImportServiceImpl.class);
        boolean additive = logger.isAdditive();
        logs.start();
        logger.addAppender(logs);
        logger.setAdditive(false);

        // when
        List<CertificateImportResultDto> results;
        try {
            results = service.importCertificates(request).getResults();
        } finally {
            logger.setAdditive(additive);
            logger.detachAppender(logs);
        }

        // then
        assertThat(results).singleElement().satisfies(result -> {
            assertThat(result.isImported()).isFalse();
            assertThat(result.getMessage())
                    .isEqualTo("The entry could not be imported. Retry it, or see the Core log for why.");
        });
        assertThat(logs.list).singleElement().satisfies(warning -> {
            assertThat(warning.getLevel()).isEqualTo(Level.WARN);
            assertThat(warning.getFormattedMessage()).contains(reference());
            assertThat(warning.getThrowableProxy().getMessage()).contains("could not execute statement");
        });
        verify(writer, never()).complete(any(), any(), any());
    }

    /** The key import's own words stand for the entry, and its copies of the key and the passphrase are overwritten. */
    @Test
    void importCertificates_reportsTheKeyImportsOutcomeAndOverwritesWhatItHandedOver() throws Exception {
        // given
        KeyImportRequestDto[] handedOver = new KeyImportRequestDto[1];
        CertificateImportRequestDto request = keyRequest();
        when(keyImport.importKey(any(), any(), eq(KeyRequestType.KEY_PAIR), any())).thenAnswer(invocation -> {
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
        when(keyImport.importKey(any(), any(), any(), any())).thenThrow(new AccessDeniedException("denied"));

        // when
        // then
        assertThrows(AccessDeniedException.class, () -> service.importCertificates(request));
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
        CertificateImportRequestDto request = request(entry(reference, destination));
        when(writer.open(eq(REQUESTER), eq(importIdOf(request)), anyString()))
                .thenReturn(recorded(CertificateImportEntryState.OPEN, null));
        return request;
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
        entry.setImportId("import of " + reference);
        entry.setKeyDestination(destination);
        return entry;
    }

    private static String importIdOf(CertificateImportRequestDto request) {
        return request.getEntries().getFirst().getImportId();
    }

    private static CertificateImportRecord recorded(CertificateImportEntryState state, UUID certificateUuid) {
        return new CertificateImportRecord(UUID.randomUUID(), "digest", state, certificateUuid, null);
    }

    private static String reference() throws Exception {
        return sha256(certificate.getEncoded());
    }
}
