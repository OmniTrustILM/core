package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.EstSourceCertificate;
import com.otilm.core.service.est.authentication.EstSourceCertificates;
import com.otilm.core.service.est.enrollment.EstRequestClaims.ClaimedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import com.otilm.core.service.writer.est.EstRequestClaimWriter;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.EstClientCredentialsFixtures;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstReenrollmentTest {

    private static final String LABEL = "devices";
    private static final String SUBJECT = "CN=device-1";

    private static Map<String, OidRecord> savedRdnCache;

    @Mock
    private EstSourceCertificates sourceCertificates;

    @Mock
    private ClientOperationInternalService clientOperationService;

    @Mock
    private EstRequestClaimWriter claimWriter;

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;

    @Mock
    private EstRequestClaims claims;

    private final EstClientCredentials credentials = EstClientCredentialsFixtures.noCredentials();

    private EstReenrollment reenrollment;
    private EstRoute route;

    @BeforeAll
    static void registerBouncyCastleAndSeedRdnCache() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @BeforeEach
    void createReenrollmentOnARoute() {
        var answers = new EstAnswers(certificateRepository);
        reenrollment = new EstReenrollment(sourceCertificates, clientOperationService, certificateRepository,
                registrationAuthorizationRepository, answers, claims);
        EstProfile estProfile = anEstProfile()
                .withUuid(UUID.randomUUID())
                .withAllowRenewal(true)
                .withAllowRekey(true)
                .build();
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        route = new EstRoute(estProfile, raProfile, false, LABEL);
    }

    @Test
    void refusesClientWithoutVerifyingTheSignature_whenItsCertificateIsNotAccepted() throws Exception {
        // given
        Pkcs10CertificateRequest forgedRequest = spy(EstRequestDecoder.decode(EstCsrFixtures.forgedRequestBody()));
        var notAccepted = new EstException(EstError.CERTIFICATE_REJECTED, LABEL);
        when(sourceCertificates.authenticate(route, credentials)).thenThrow(notAccepted);

        // when
        ThrowingCallable reenroll = () -> reenrollment.reenroll(route, forgedRequest, credentials);

        // then
        assertThatThrownBy(reenroll).isSameAs(notAccepted);
        verifyNoInteractions(forgedRequest, clientOperationService, registrationAuthorizationRepository);
    }

    @Test
    void carriesTheOnStoredHookInTheProtocolInfo_whenRenewing() throws Exception {
        // given
        KeyPair sourceKeys = PkiFixtures.keyPair();
        EstSourceCertificate source = dueSourceOf(sourceKeys);
        Pkcs10CertificateRequest csr = requestOf(sourceKeys);
        Consumer<UUID> onStored = storedUuid -> {
        };
        submitsWith(onStored);
        authenticatesAs(source);
        when(clientOperationService.renewCertificate(any(), any(), eq(source.uuid().toString()), any(), any(), any()))
                .thenThrow(new IllegalStateException("stop after capturing"));

        // when
        ThrowingCallable reenroll = () -> reenrollment.reenroll(route, csr, credentials);

        // then
        assertThatThrownBy(reenroll).isInstanceOf(EstException.class);
        CertificateProtocolInfo info = protocolInfoOf(clientOperationService, true);
        assertProtocolInfo(info, onStored);
    }

    @Test
    void carriesTheOnStoredHookInTheProtocolInfo_whenRekeying() throws Exception {
        // given
        EstSourceCertificate source = dueSourceOf(PkiFixtures.keyPair());
        Pkcs10CertificateRequest csr = requestOf(PkiFixtures.keyPair());
        Consumer<UUID> onStored = storedUuid -> {
        };
        submitsWith(onStored);
        authenticatesAs(source);
        when(clientOperationService.rekeyCertificate(any(), any(), eq(source.uuid().toString()), any(), any(), any()))
                .thenThrow(new IllegalStateException("stop after capturing"));

        // when
        ThrowingCallable reenroll = () -> reenrollment.reenroll(route, csr, credentials);

        // then
        assertThatThrownBy(reenroll).isInstanceOf(EstException.class);
        CertificateProtocolInfo info = protocolInfoOf(clientOperationService, false);
        assertProtocolInfo(info, onStored);
    }

    @Test
    void rethrowsTheLostClaimUnmapped_whenRenewalFailsBecauseTheClaimWasTakenOver() throws Exception {
        // given
        KeyPair sourceKeys = PkiFixtures.keyPair();
        EstSourceCertificate source = dueSourceOf(sourceKeys);
        Pkcs10CertificateRequest csr = requestOf(sourceKeys);
        submitsWith(storedUuid -> {
        });
        authenticatesAs(source);
        var claimLost = new EstRequestClaimLostException(UUID.randomUUID());
        when(clientOperationService.renewCertificate(any(), any(), any(), any(), any(), any()))
                .thenThrow(shapedFailureCausedBy(claimLost));

        // when
        ThrowingCallable reenroll = () -> reenrollment.reenroll(route, csr, credentials);

        // then
        assertThatThrownBy(reenroll).isSameAs(claimLost);
    }

    @Test
    void rethrowsTheLostClaimUnmapped_whenRekeyFailsBecauseTheClaimWasTakenOver() throws Exception {
        // given
        EstSourceCertificate source = dueSourceOf(PkiFixtures.keyPair());
        Pkcs10CertificateRequest csr = requestOf(PkiFixtures.keyPair());
        submitsWith(storedUuid -> {
        });
        authenticatesAs(source);
        var claimLost = new EstRequestClaimLostException(UUID.randomUUID());
        when(clientOperationService.rekeyCertificate(any(), any(), any(), any(), any(), any()))
                .thenThrow(shapedFailureCausedBy(claimLost));

        // when
        ThrowingCallable reenroll = () -> reenrollment.reenroll(route, csr, credentials);

        // then
        assertThatThrownBy(reenroll).isSameAs(claimLost);
    }

    @Test
    void answersAcceptedWithTheRetryAfterOfTheEstProfile_whenTheCertificateIsNotReady() throws Exception {
        // given
        route = new EstRoute(anEstProfile().withUuid(UUID.randomUUID()).withRetryAfter(7).build(), route.raProfile(),
                false, LABEL);
        KeyPair sourceKeys = PkiFixtures.keyPair();
        Pkcs10CertificateRequest csr = requestOf(sourceKeys);
        authenticatesAs(dueSourceOf(sourceKeys));
        when(claims.answerOnce(any(), any(), any(), any(), any())).thenAnswer(invocation -> {
            ClaimedRequest request = invocation.getArgument(4);
            return request.pending();
        });

        // when
        ResponseEntity<byte[]> response = reenrollment.reenroll(route, csr, credentials);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("7");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Has the claims helper submit once with the hook, as it does for the winner of a claim, and answer nothing. */
    private void submitsWith(Consumer<UUID> onStored) {
        when(claims.answerOnce(any(), any(), any(), any(), any())).thenAnswer(invocation -> {
            ClaimedRequest request = invocation.getArgument(4);
            request.submit(onStored);
            return null;
        });
    }

    private void authenticatesAs(EstSourceCertificate source) {
        when(sourceCertificates.authenticate(route, credentials)).thenReturn(source);
    }

    private static CertificateProtocolInfo protocolInfoOf(ClientOperationInternalService service, boolean renewal)
            throws Exception {
        ArgumentCaptor<CertificateProtocolInfo> info = ArgumentCaptor.forClass(CertificateProtocolInfo.class);
        if (renewal) {
            verify(service).renewCertificate(any(), any(), any(), any(), info.capture(), any());
        } else {
            verify(service).rekeyCertificate(any(), any(), any(), any(), info.capture(), any());
        }
        return info.getValue();
    }

    private void assertProtocolInfo(CertificateProtocolInfo info, Consumer<UUID> onStored) {
        assertThat(info.getProtocol()).isEqualTo(CertificateProtocol.EST);
        assertThat(info.getProtocolProfileUuid()).isEqualTo(route.estProfile().getUuid());
        assertThat(info.getOnStored()).isSameAs(onStored);
    }

    private static EstSourceCertificate dueSourceOf(KeyPair keys) throws Exception {
        Instant now = Instant.now();
        PublicKey publicKey = CryptographyUtil.decodePublicKey(keys.getPublic().getEncoded());
        return new EstSourceCertificate(UUID.randomUUID(), "fingerprint", publicKey, SUBJECT, null,
                Date.from(now.minus(Duration.ofDays(100))), Date.from(now.plus(Duration.ofDays(1))));
    }

    private static Pkcs10CertificateRequest requestOf(KeyPair keys) throws Exception {
        return new Pkcs10CertificateRequest(
                Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody(keys, SUBJECT)));
    }

    private static CertificateOperationException shapedFailureCausedBy(Throwable cause) {
        var shapedFailure = new CertificateOperationException("Failed to submit");
        shapedFailure.initCause(cause);
        return shapedFailure;
    }
}
