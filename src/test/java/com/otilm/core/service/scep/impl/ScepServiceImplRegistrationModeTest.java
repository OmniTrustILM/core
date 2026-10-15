package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.ScepException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.protocol.ProtocolChallengeSource;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.scep.ScepTransactionRepository;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.service.scep.message.ScepRequest;
import com.otilm.core.service.scep.message.ScepResponse;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.util.CertificateUtil;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScepServiceImplRegistrationModeTest {

    private static final UUID RA_PROFILE_UUID = UUID.randomUUID();
    private static final UUID CANDIDATE_UUID = UUID.randomUUID();
    private static final String CHALLENGE = "registration-challenge";
    /** Pinned copy of the wire contract: changing the production message must consciously change this test. */
    private static final String REGISTRATION_REJECTION = "The request does not match an active certificate registration.";

    private static KeyPair keyPair;
    private static Map<String, OidRecord> savedRdnCache;

    private ScepServiceImpl service;
    private ScepProfile profile;
    private CertificateRepository certificateRepository;
    private CertificateEventHistoryInternalService eventHistoryService;
    private ScepTransactionRepository scepTransactionRepository;
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private RegistrationChallengeStore registrationChallengeStore;
    private ClientOperationExternalService clientOperationExternalService;
    private CertificateInternalService certificateService;
    private ScepRegistrationTrackingWriter scepRegistrationTrackingWriter;

    @BeforeAll
    static void setUpClass() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

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
    void setUp() {
        service = new ScepServiceImpl();
        profile = mock(ScepProfile.class);
        when(profile.getChallengeSource()).thenReturn(ProtocolChallengeSource.CERTIFICATE_REGISTRATION);
        certificateRepository = mock(CertificateRepository.class);
        eventHistoryService = mock(CertificateEventHistoryInternalService.class);
        scepTransactionRepository = mock(ScepTransactionRepository.class);
        registrationAuthorizationRepository = mock(CertificateRegistrationAuthorizationRepository.class);
        registrationChallengeStore = mock(RegistrationChallengeStore.class);
        clientOperationExternalService = mock(ClientOperationExternalService.class);
        certificateService = mock(CertificateInternalService.class);
        scepRegistrationTrackingWriter = mock(ScepRegistrationTrackingWriter.class);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);
        raProfile.setAuthorityInstanceReference(authority);

        ReflectionTestUtils.setField(service, "scepProfile", profile);
        ReflectionTestUtils.setField(service, "raProfile", raProfile);
        ReflectionTestUtils.setField(service, "certificateRepository", certificateRepository);
        ReflectionTestUtils.setField(service, "certificateEventHistoryService", eventHistoryService);
        ReflectionTestUtils.setField(service, "scepTransactionRepository", scepTransactionRepository);
        ReflectionTestUtils
                .setField(service, "registrationAuthorizationRepository", registrationAuthorizationRepository);
        ReflectionTestUtils.setField(service, "registrationChallengeStore", registrationChallengeStore);
        ReflectionTestUtils.setField(service, "clientOperationExternalService", clientOperationExternalService);
        ReflectionTestUtils.setField(service, "certificateService", certificateService);
        ReflectionTestUtils.setField(service, "scepRegistrationTrackingWriter", scepRegistrationTrackingWriter);
    }

    @Test
    void missingChallengeRejectsWithGenericMessage() throws Exception {
        ScepRequest request = scepRequest("CN=device-1", null);

        ScepException ex = scepRejection(() -> ReflectionTestUtils.invokeMethod(service, "matchRegistration", request));

        Assertions.assertEquals(REGISTRATION_REJECTION, ex.getMessage());
        Assertions.assertEquals(FailInfo.BAD_MESSAGE_CHECK, ex.getFailInfo());
    }

    @Test
    void noMatchRejectsWithGenericMessage() throws Exception {
        stubCandidates(registeredCertificate("CN=other-device", null));
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE);

        ScepException ex = scepRejection(() -> ReflectionTestUtils.invokeMethod(service, "matchRegistration", request));

        Assertions.assertEquals(REGISTRATION_REJECTION, ex.getMessage());
        Assertions.assertEquals(FailInfo.BAD_MESSAGE_CHECK, ex.getFailInfo());
    }

    @Test
    void ambiguousMatchRejectsWithGenericMessage() throws Exception {
        stubCandidates(registeredCertificate("CN=device-1", null), registeredCertificate("CN=device-1", null));
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE);

        ScepException ex = scepRejection(() -> ReflectionTestUtils.invokeMethod(service, "matchRegistration", request));

        Assertions.assertEquals(REGISTRATION_REJECTION, ex.getMessage());
    }

    @Test
    void sanMismatchRejectsWithGenericMessageAndRecordsEventHistory() throws Exception {
        stubCandidates(registeredCertificate("CN=device-1",
                CertificateUtil.serializeSans(Map.of("dNSName", List.of("a.example")))));
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE, "b.example");

        ScepException ex = scepRejection(() -> ReflectionTestUtils.invokeMethod(service, "matchRegistration", request));

        Assertions.assertEquals(REGISTRATION_REJECTION, ex.getMessage());
        verify(eventHistoryService)
                .addEventHistory(eq(CANDIDATE_UUID), eq(CertificateEvent.ISSUE), eq(CertificateEventStatus.FAILED),
                        anyString(), anyString());
    }

    @Test
    void matchedEnrolmentReturnsTheRegisteredCertificate() throws Exception {
        stubCandidates(registeredCertificate("CN=device-1",
                CertificateUtil.serializeSans(Map.of("dNSName", List.of("a.example")))));
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE, "a.example");

        Certificate matched = ReflectionTestUtils.invokeMethod(service, "matchRegistration", request);

        Assertions.assertEquals(CANDIDATE_UUID, matched.getUuid());
    }

    @Test
    void completionReturnsPendingAndStoresTransaction() throws Exception {
        Certificate matched = registeredCertificate("CN=device-1", null);
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE);
        when(request.getTransactionId()).thenReturn("tx-1");

        ScepResponse response = ReflectionTestUtils.invokeMethod(service, "completeRegistration", request, matched);

        Assertions.assertEquals(PkiStatus.PENDING, response.getPkiStatus());
        verify(clientOperationExternalService)
                .issueExistingCertificate(any(), any(), eq(matched.getUuid().toString()),
                        Mockito.argThat(dto -> CHALLENGE.equals(dto.getAuthorizationSecret())));
        verify(scepRegistrationTrackingWriter).recordPollMapping(eq("tx-1"), eq(matched.getUuid()), any());
        verify(certificateService).applyProtocolAssociations(eq(matched.getUuid()), any());
    }

    @Test
    void completionDenialMapsToGenericMessage() throws Exception {
        Certificate matched = registeredCertificate("CN=device-1", null);
        ScepRequest request = scepRequest("CN=device-1", "wrong-challenge");
        when(clientOperationExternalService.issueExistingCertificate(any(), any(), anyString(), any()))
                .thenThrow(new ValidationException("The certificate registration challenge is invalid."));

        ScepException ex = scepRejection(
                () -> ReflectionTestUtils.invokeMethod(service, "completeRegistration", request, matched));

        Assertions.assertEquals(REGISTRATION_REJECTION, ex.getMessage());
        Assertions.assertEquals(FailInfo.BAD_MESSAGE_CHECK, ex.getFailInfo());
    }

    @Test
    void associationFailureDoesNotFailTheCompletedEnrolment() throws Exception {
        Certificate matched = registeredCertificate("CN=device-1", null);
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE);
        when(request.getTransactionId()).thenReturn("tx-2");
        doThrow(new RuntimeException("association failed"))
                .when(certificateService)
                .applyProtocolAssociations(any(), any());

        ScepResponse response = ReflectionTestUtils.invokeMethod(service, "completeRegistration", request, matched);

        Assertions.assertEquals(PkiStatus.PENDING, response.getPkiStatus());
        verify(scepRegistrationTrackingWriter).recordPollMapping(eq("tx-2"), eq(matched.getUuid()), any());
    }

    @Test
    void envelopePasswordIsTheProfilePasswordOutsideRegistrationMode() {
        when(profile.getChallengeSource()).thenReturn(ProtocolChallengeSource.PROTOCOL_DEFAULT);
        when(profile.getChallengePassword()).thenReturn("profile-password");

        Assertions
                .assertEquals("profile-password",
                        ReflectionTestUtils.invokeMethod(service, "resolveEnvelopePassword", (Object) null));
    }

    @Test
    void envelopePasswordIsThePresentedChallengeOnEnrolment() throws Exception {
        ScepRequest request = scepRequest("CN=device-1", CHALLENGE);

        Assertions
                .assertEquals(CHALLENGE, ReflectionTestUtils.invokeMethod(service, "resolveEnvelopePassword", request));
    }

    @Test
    void envelopePasswordOnPollIsRecoveredFromTheAuthorization() {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getTransactionId()).thenReturn("tx-3");
        ScepTransaction transaction = new ScepTransaction();
        transaction.setCertificateUuid(CANDIDATE_UUID);
        when(scepTransactionRepository.findByTransactionIdAndScepProfile("tx-3", profile))
                .thenReturn(Optional.of(transaction));
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        when(registrationAuthorizationRepository.findByCertificateUuid(CANDIDATE_UUID))
                .thenReturn(Optional.of(authorization));
        when(registrationChallengeStore.resolvePlaintext(authorization)).thenReturn("stored-challenge");

        Assertions
                .assertEquals("stored-challenge",
                        ReflectionTestUtils.invokeMethod(service, "resolveEnvelopePassword", request));
    }

    @Test
    void envelopePasswordIsNullForUnknownPollTransaction() {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getTransactionId()).thenReturn("tx-unknown");
        when(scepTransactionRepository.findByTransactionIdAndScepProfile("tx-unknown", profile))
                .thenReturn(Optional.empty());

        Assertions.assertNull(ReflectionTestUtils.invokeMethod(service, "resolveEnvelopePassword", request));
    }

    /**
     * The private methods are invoked reflectively, which wraps their checked {@link ScepException} in an
     * {@link UndeclaredThrowableException}; this unwraps it for assertion.
     */
    private static ScepException scepRejection(Executable invocation) {
        UndeclaredThrowableException wrapped = Assertions.assertThrows(UndeclaredThrowableException.class, invocation);
        return Assertions.assertInstanceOf(ScepException.class, wrapped.getUndeclaredThrowable());
    }

    private void stubCandidates(Certificate... candidates) {
        // Match the exact normalized subject the caller must derive from the CSR — every test enrols
        // CN=device-1 — so a caller that stops normalizing (or passes the wrong value) misses the stub,
        // yields no candidates, and fails the test rather than passing on an over-broad matcher.
        when(certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(RA_PROFILE_UUID,
                        CertificateUtil.normalizeSubjectDn(new X500Name("CN=device-1"))))
                .thenReturn(Arrays.asList(candidates));
    }

    private Certificate registeredCertificate(String subjectDn, String serializedSans) {
        Certificate certificate = new Certificate();
        certificate.setUuid(CANDIDATE_UUID);
        certificate.setSubjectDn(subjectDn);
        certificate.setSubjectAlternativeNames(serializedSans);
        return certificate;
    }

    /**
     * Builds the CSR and the {@link ScepRequest} stub from the same challenge argument, so the CSR content and the
     * presented challenge cannot diverge: {@code null} yields a CSR without the challengePassword attribute AND a null
     * presented challenge, a wrong value is embedded and presented as that wrong value.
     */
    private static ScepRequest scepRequest(String subjectDn, String challengePassword, String... dnsSans)
            throws Exception {
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());
        if (challengePassword != null) {
            builder
                    .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                            new DERPrintableString(challengePassword));
        }
        if (dnsSans.length > 0) {
            GeneralName[] names = Arrays
                    .stream(dnsSans)
                    .map(dns -> new GeneralName(GeneralName.dNSName, dns))
                    .toArray(GeneralName[]::new);
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(builder.build(signer));

        ScepRequest request = mock(ScepRequest.class);
        when(request.getPkcs10Request()).thenReturn(csr);
        when(request.getChallengePassword()).thenReturn(challengePassword);
        return request;
    }
}
