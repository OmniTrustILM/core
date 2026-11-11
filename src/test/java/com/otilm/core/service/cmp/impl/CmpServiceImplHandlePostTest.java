package com.otilm.core.service.cmp.impl;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cmp.CmpProfileVariant;
import com.otilm.api.model.core.cmp.CmpTransactionState;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditOperationOverride;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.cmp.CmpTransaction;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.CertificateKeyServiceImpl;
import com.otilm.core.service.cmp.message.CmpTransactionService;
import com.otilm.core.service.cmp.message.handler.CrmfMessageHandler;
import com.otilm.core.service.cmp.message.validator.impl.BodyValidator;
import com.otilm.core.service.cmp.message.validator.impl.HeaderValidator;
import com.otilm.core.service.cmp.message.validator.impl.ProtectionValidator;
import com.otilm.core.util.SecretLeakProbe;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Drives {@link CmpServiceImpl#handlePost(String, byte[])} through its error paths to verify that the wire-visible
 * {@code PKIFreeText} carries a shaped message and never leaks a raw runtime exception.
 */
class CmpServiceImplHandlePostTest {

    private static final String PROFILE_NAME = "missing-profile";
    private static final UUID RA_PROFILE_UUID = UUID.randomUUID();
    private static final String SIXTEEN_BYTE_TRANSACTION_ID = "0102030405060708";
    private static final String LEAKY_MESSAGE = "ERROR: duplicate key value violates unique constraint \"ra_profile_pkey\"";

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void handlePost_returnsShapedProfileError_whenProfileNotResolved() throws Exception {
        // given: a raProfile-scoped request whose RA profile cannot be resolved, so profile validation fails
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.empty());
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), null, false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the shaped domain message reaches the wire; the response is a well-formed CMP error
        assertThat(response.getBody()).isNotNull();
        assertThat(wireStatusText(response.getBody())).contains("Requested CMP Profile not found");
    }

    @Test
    void handlePost_replacesRawMessageWithGenericDetail_whenProcessingThrowsNonDomainException() throws Exception {
        // given: a fully resolved profile so processing proceeds past validation
        CmpProfile cmpProfile = resolvedCmpProfile();
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        // and: the header validator throws a non-domain exception carrying a sensitive message
        HeaderValidator headerValidator = mock(HeaderValidator.class);
        when(headerValidator.validate(any(), any())).thenThrow(new RuntimeException(LEAKY_MESSAGE));

        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), headerValidator,
                true);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the sensitive message never reaches the wire-visible PKIFreeText
        assertThat(response.getBody()).isNotNull();
        assertThat(wireStatusText(response.getBody()))
                .isEqualTo("CMP request handling failed")
                .doesNotContain("ra_profile_pkey");
    }

    @Test
    void handlePost_returnsProtectedShapedError_whenProcessingThrowsDomainException() throws Exception {
        // given: a fully resolved, shared-secret-protected profile so a ConfigurationContext exists and the
        // error response can be protected (RFC 4210 §5.1.3)
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getSharedSecret()).thenReturn("shared-secret-value");
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        // and: the header validator fails with a Core-authored domain exception
        HeaderValidator headerValidator = mock(HeaderValidator.class);
        when(headerValidator.validate(any(), any()))
                .thenThrow(new CmpProcessingException(PKIFailureInfo.badRequest, "sender name is not trusted"));

        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), headerValidator,
                false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, macProtectedRevocationRequest());

        // then: the shaped domain message reaches the wire in a protected CMP error
        assertThat(response.getBody()).isNotNull();
        PKIMessage responseMessage = PKIMessage.getInstance(response.getBody());
        assertThat(responseMessage.getProtection()).isNotNull();
        assertThat(wireStatusText(response.getBody())).contains("sender name is not trusted");
    }

    @Test
    void handlePost_replacesRawMessageWithGenericDetail_whenProfileValidationThrowsNonDomainException()
            throws Exception {
        // given: a resolved, enabled profile that uses SIGNATURE protection but whose signing certificate has
        // no content, so profile validation trips a NullPointerException — a non-domain exception whose (helpful)
        // message would otherwise leak internal class/method names to the wire
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getResponseProtectionMethod()).thenReturn(ProtectionMethod.SIGNATURE);
        when(cmpProfile.getSigningCertificate()).thenReturn(mock(Certificate.class)); // getCertificateContent() -> null
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), null, false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the raw exception message never reaches the wire-visible PKIFreeText
        assertThat(response.getBody()).isNotNull();
        assertThat(wireStatusText(response.getBody()))
                .isEqualTo("CMP request handling failed")
                .doesNotContain("getCertificateContent");
    }

    @Test
    void handlePost_returnsUnprotectedShapedError_whenResolvedProfileDisabled() throws Exception {
        // given: a profile that resolves but is disabled, so validation fails before any
        // ConfigurationContext exists to protect the response (RFC 4210 allows unprotected errors)
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getEnabled()).thenReturn(false);
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), null, false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the shaped domain message reaches the wire in an unprotected CMP error
        assertThat(response.getBody()).isNotNull();
        PKIMessage responseMessage = PKIMessage.getInstance(response.getBody());
        assertThat(responseMessage.getProtection()).isNull();
        assertThat(responseMessage.getHeader().getProtectionAlg()).isNull();
        assertThat(wireStatusText(response.getBody())).contains("CMP Profile is not enabled");
    }

    @Test
    void handlePost_failsTransaction_whenProfileValidationFails() throws Exception {
        // given: a request whose CMP profile cannot be resolved, plus a matching in-flight transaction
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.empty());
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), null, false);

        CmpTransaction transaction = new CmpTransaction();
        CmpTransactionService cmpTransactionService = (CmpTransactionService) ReflectionTestUtils
                .getField(service, "cmpTransactionService");
        when(cmpTransactionService.findByTransactionId(anyString())).thenReturn(List.of(transaction));

        // when
        service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the error path funnels through handleTrxError, marking the transaction FAILED and persisting it
        ArgumentCaptor<CmpTransaction> captor = ArgumentCaptor.forClass(CmpTransaction.class);
        verify(cmpTransactionService).save(captor.capture());
        assertThat(captor.getValue().getState()).isEqualTo(CmpTransactionState.FAILED);
    }

    @Test
    void handlePost_returnsCmpRejection_whenSignatureMessageHitsSharedSecretProfile() throws Exception {
        // given: a shared-secret profile (both request and response protection are sharedSecret) that receives a
        // signature-protected message — e.g. a KUR against a PBM-only profile
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getRequestProtectionMethod()).thenReturn(ProtectionMethod.SHARED_SECRET);
        when(cmpProfile.getSharedSecret()).thenReturn("shared-secret-value");
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        // and: header/body validation pass, so the real ProtectionValidator runs
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class),
                mock(HeaderValidator.class), false);
        ReflectionTestUtils.setField(service, "bodyValidator", mock(BodyValidator.class));
        ReflectionTestUtils.setField(service, "protectionValidator", new ProtectionValidator());

        // when: instead of an NPE escaping to the JSON error handler, handlePost returns a CMP response
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, signatureProtectedRevocationRequest());

        // then: the response is a well-formed, protected CMP rejection carrying a badMessageCheck status string
        assertThat(response.getBody()).isNotNull();
        PKIMessage responseMessage = PKIMessage.getInstance(response.getBody());
        assertThat(responseMessage.getBody().getType()).isEqualTo(PKIBody.TYPE_ERROR);
        assertThat(responseMessage.getProtection()).isNotNull();
        assertThat(wireStatusText(response.getBody())).contains("only accepts PBM");
    }

    @Test
    void handlePost_returnsUnprotectedError_whenProtectedErrorResponseCannotBeBuilt() throws Exception {
        // given: a sharedSecret-response profile whose shared secret is null, so building the *protected* error
        // response throws while handling a domain exception — the endpoint must still answer with a CMP error
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getSharedSecret()).thenReturn(null);
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        // and: a domain exception is raised during processing so the catch path builds the error response
        HeaderValidator headerValidator = mock(HeaderValidator.class);
        when(headerValidator.validate(any(), any()))
                .thenThrow(new CmpProcessingException(PKIFailureInfo.badRequest, "sender name is not trusted"));
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), headerValidator,
                false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the endpoint falls back to an unprotected CMP error rather than leaking to the JSON handler
        assertThat(response.getBody()).isNotNull();
        PKIMessage responseMessage = PKIMessage.getInstance(response.getBody());
        assertThat(responseMessage.getBody().getType()).isEqualTo(PKIBody.TYPE_ERROR);
        assertThat(responseMessage.getProtection()).isNull();
        assertThat(wireStatusText(response.getBody())).contains("sender name is not trusted");
    }

    @Test
    void handlePost_failsTransactionWithoutNpe_whenExceptionMessageIsNull() throws Exception {
        // given: a resolved profile, a matching in-flight transaction, and processing that throws an exception
        // carrying a null message (the branch that previously NPE'd in handleTrxError's substring call)
        CmpProfile cmpProfile = resolvedCmpProfile();
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        HeaderValidator headerValidator = mock(HeaderValidator.class);
        when(headerValidator.validate(any(), any())).thenThrow(new RuntimeException());
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), headerValidator,
                false);

        CmpTransaction transaction = new CmpTransaction();
        CmpTransactionService cmpTransactionService = (CmpTransactionService) ReflectionTestUtils
                .getField(service, "cmpTransactionService");
        when(cmpTransactionService.findByTransactionId(anyString())).thenReturn(List.of(transaction));

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: no NPE escapes; the transaction is marked FAILED with the exception's class name as the reason
        assertThat(response.getBody()).isNotNull();
        verify(cmpTransactionService).save(transaction);
        assertThat(transaction.getState()).isEqualTo(CmpTransactionState.FAILED);
        assertThat(transaction.getCustomReason()).isEqualTo("RuntimeException");
    }

    @Test
    void rejectsInitialRequest_whenSignerCertificateIsSelfMade() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        CmpServiceImpl service = createSignatureProfileService(crmfMessageHandler, mock(CertificateRepository.class));
        var selfMadeSignerKeys = CmpTestUtil.generateKeyPairEC();
        var selfMadeSignerCertificate = createSelfSignedCertificate(selfMadeSignerKeys);

        // when
        ResponseEntity<byte[]> response = service
                .handlePost(PROFILE_NAME, createSignedInitialRequest(selfMadeSignerKeys, selfMadeSignerCertificate));

        // then
        verify(crmfMessageHandler, never()).handle(any(), any());
        assertThat(readWireFailInfo(response.getBody())).isEqualTo(PKIFailureInfo.signerNotTrusted);
    }

    @Test
    void handsInitialRequestToHandler_whenSignerCertificateIsIssuedForTheRaProfile() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        var certificateRepository = mock(CertificateRepository.class);
        CmpServiceImpl service = createSignatureProfileService(crmfMessageHandler, certificateRepository);
        var signerKeys = CmpTestUtil.generateKeyPairEC();
        var signerCertificate = createSelfSignedCertificate(signerKeys);
        Certificate protectionCertificate = CmpEntityUtil
                .createProtectionCertificate(signerCertificate, RA_PROFILE_UUID);
        when(certificateRepository.findByFingerprint(protectionCertificate.getFingerprint()))
                .thenReturn(Optional.of(protectionCertificate));

        // when
        service.handlePost(PROFILE_NAME, createSignedInitialRequest(signerKeys, signerCertificate));

        // then
        ArgumentCaptor<ConfigurationContext> configuration = ArgumentCaptor.forClass(ConfigurationContext.class);
        verify(crmfMessageHandler).handle(any(), configuration.capture());
        assertThat(configuration.getValue().getProtectionCertificate()).isSameAs(protectionCertificate);
    }

    @Test
    void recordsIssueAsTheAuditOperation_whenInitialRequestIsHandled() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        var certificateRepository = mock(CertificateRepository.class);
        CmpServiceImpl service = createSignatureProfileService(crmfMessageHandler, certificateRepository);
        var auditOperationOverride = mock(AuditOperationOverride.class);
        service.setAuditOperationOverride(auditOperationOverride);
        var signerKeys = CmpTestUtil.generateKeyPairEC();
        var signerCertificate = createSelfSignedCertificate(signerKeys);
        Certificate protectionCertificate = CmpEntityUtil
                .createProtectionCertificate(signerCertificate, RA_PROFILE_UUID);
        when(certificateRepository.findByFingerprint(protectionCertificate.getFingerprint()))
                .thenReturn(Optional.of(protectionCertificate));
        byte[] initialRequest = createSignedInitialRequest(signerKeys, signerCertificate);
        when(crmfMessageHandler.handle(any(), any())).thenReturn(PKIMessage.getInstance(initialRequest));

        // when
        service.handlePost(PROFILE_NAME, initialRequest);

        // then
        verify(auditOperationOverride).set(Operation.ISSUE);
    }

    @Test
    void recordsIssueAsTheAuditOperation_whenTheHandlerFails() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        var certificateRepository = mock(CertificateRepository.class);
        CmpServiceImpl service = createSignatureProfileService(crmfMessageHandler, certificateRepository);
        var auditOperationOverride = mock(AuditOperationOverride.class);
        service.setAuditOperationOverride(auditOperationOverride);
        var signerKeys = CmpTestUtil.generateKeyPairEC();
        var signerCertificate = createSelfSignedCertificate(signerKeys);
        Certificate protectionCertificate = CmpEntityUtil
                .createProtectionCertificate(signerCertificate, RA_PROFILE_UUID);
        when(certificateRepository.findByFingerprint(protectionCertificate.getFingerprint()))
                .thenReturn(Optional.of(protectionCertificate));
        when(crmfMessageHandler.handle(any(), any())).thenThrow(new IllegalStateException("handler failed"));
        byte[] initialRequest = createSignedInitialRequest(signerKeys, signerCertificate);

        // when
        service.handlePost(PROFILE_NAME, initialRequest);

        // then
        verify(auditOperationOverride).set(Operation.ISSUE);
    }

    @Test
    void rejectsInitialRequest_whenUnprotected() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getRequestProtectionMethod()).thenReturn(ProtectionMethod.SHARED_SECRET);
        when(cmpProfile.getSharedSecret()).thenReturn("shared-secret-value");
        CmpServiceImpl service = createServiceWithRealValidators(cmpProfile, crmfMessageHandler,
                mock(CertificateRepository.class));

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, createUnprotectedInitialRequest());

        // then
        verify(crmfMessageHandler, never()).handle(any(), any());
        assertThat(readWireFailInfo(response.getBody())).isEqualTo(PKIFailureInfo.notAuthorized);
    }

    @Test
    void logsTheFailureWithoutTheConnectorsText_whenTheConnectorRefusesTheInitialRequest() throws Exception {
        // given
        var crmfMessageHandler = mock(CrmfMessageHandler.class);
        var certificateRepository = mock(CertificateRepository.class);
        CmpServiceImpl service = createSignatureProfileService(crmfMessageHandler, certificateRepository);
        var signerKeys = CmpTestUtil.generateKeyPairEC();
        var signerCertificate = createSelfSignedCertificate(signerKeys);
        Certificate protectionCertificate = CmpEntityUtil
                .createProtectionCertificate(signerCertificate, RA_PROFILE_UUID);
        when(certificateRepository.findByFingerprint(protectionCertificate.getFingerprint()))
                .thenReturn(Optional.of(protectionCertificate));
        var echoedSecret = "passphrase-the-connector-echoed";
        when(crmfMessageHandler.handle(any(), any())).thenAnswer(invocation -> {
            throw createIssueFailureEchoing(echoedSecret);
        });
        byte[] initialRequest = createSignedInitialRequest(signerKeys, signerCertificate);

        // when
        List<String> logged;
        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            service.handlePost(PROFILE_NAME, initialRequest);
            logged = probe.logged();
        }

        // then
        SecretLeakProbe.assertNoneReveals(logged, echoedSecret);
        assertThat(logged).anyMatch(line -> line.contains(ConnectorException.class.getName()));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** An issuance failure as the CRMF handler raises it when the connector refused the request in its own words. */
    private static CmpProcessingException createIssueFailureEchoing(String connectorText) {
        var shapedFailure = new CertificateOperationException("Failed to submit certificate request");
        shapedFailure.initCause(new ConnectorException(connectorText));
        var transactionId = new DEROctetString(SIXTEEN_BYTE_TRANSACTION_ID.getBytes(StandardCharsets.UTF_8));
        return new CmpProcessingException(transactionId, PKIFailureInfo.systemFailure, "cannot issue certificate",
                shapedFailure);
    }

    private CmpServiceImpl createSignatureProfileService(CrmfMessageHandler crmfMessageHandler,
            CertificateRepository certificateRepository) throws Exception {
        String responseSigningContent = Base64
                .getEncoder()
                .encodeToString(createSelfSignedCertificate(CmpTestUtil.generateKeyPairEC()).getEncoded());
        CmpProfile cmpProfile = resolvedCmpProfile();
        when(cmpProfile.getRequestProtectionMethod()).thenReturn(ProtectionMethod.SIGNATURE);
        when(cmpProfile.getResponseProtectionMethod()).thenReturn(ProtectionMethod.SIGNATURE);
        when(cmpProfile.getSigningCertificate()).thenReturn(createResponseSigningCertificate(responseSigningContent));
        CmpServiceImpl service = createServiceWithRealValidators(cmpProfile, crmfMessageHandler, certificateRepository);

        CertificateDetailDto chainCertificate = new CertificateDetailDto();
        chainCertificate.setValidationStatus(CertificateValidationStatus.VALID);
        chainCertificate.setCertificateContent(responseSigningContent);
        CertificateChainResponseDto chain = new CertificateChainResponseDto();
        chain.setCertificates(List.of(chainCertificate));
        CertificateInternalService certificateService = mock(CertificateInternalService.class);
        when(certificateService.getCertificateChain(any(), anyBoolean())).thenReturn(chain);
        ReflectionTestUtils.setField(service, "certificateService", certificateService);

        CertificateKeyServiceImpl certificateKeyService = mock(CertificateKeyServiceImpl.class);
        when(certificateKeyService.getPrivateKey(any()))
                .thenReturn(new PlatformPrivateKey(
                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.ECDSA)));
        ReflectionTestUtils.setField(service, "certificateKeyServiceImpl", certificateKeyService);
        return service;
    }

    private CmpServiceImpl createServiceWithRealValidators(CmpProfile cmpProfile, CrmfMessageHandler crmfMessageHandler,
            CertificateRepository certificateRepository) {
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class),
                new HeaderValidator(), false);
        ProtectionValidator protectionValidator = new ProtectionValidator();
        protectionValidator.setCertificateRepository(certificateRepository);
        ReflectionTestUtils.setField(service, "bodyValidator", new BodyValidator());
        ReflectionTestUtils.setField(service, "protectionValidator", protectionValidator);
        service.setCrmfMessageHandler(crmfMessageHandler);
        return service;
    }

    private static Certificate createResponseSigningCertificate(String content) {
        CryptographicKeyItem privateKey = aKeyItem().withType(KeyType.PRIVATE_KEY).withState(KeyState.ACTIVE).build();
        privateKey.setUsage(List.of(KeyUsage.SIGN));
        CryptographicKey key = aCryptographicKey().build();
        key.setItems(Set.of(privateKey));
        return aCertificate()
                .withUuid(UUID.randomUUID())
                .withState(CertificateState.ISSUED)
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withCertificateContent(CmpEntityUtil.createCertContent("response-signing", content))
                .withKey(key)
                .build();
    }

    private static X509CertificateHolder createSelfSignedCertificate(KeyPair keys) throws Exception {
        return CmpTestUtil.makeV3Certificate(BigInteger.TEN, keys, "CN=device", keys, "CN=device");
    }

    private static byte[] createSignedInitialRequest(KeyPair signerKeys, X509CertificateHolder signerCertificate)
            throws Exception {
        return CmpTestUtil
                .createSignatureBasedMessage(SIXTEEN_BYTE_TRANSACTION_ID, signerKeys, signerCertificate,
                        CmpTestUtil.createCrmfBody(CmpTestUtil.generateKeyPairEC(), 0L))
                .toASN1Structure()
                .getEncoded();
    }

    private static byte[] createUnprotectedInitialRequest() throws Exception {
        PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=user")), new GeneralName(new X500Name("CN=ManagementCA")));
        headerBuilder.setTransactionID(SIXTEEN_BYTE_TRANSACTION_ID.getBytes(StandardCharsets.UTF_8));
        headerBuilder.setSenderNonce(new byte[16]);
        PKIBody body = CmpTestUtil.createCrmfBody(CmpTestUtil.generateKeyPairEC(), 0L);
        return new PKIMessage(headerBuilder.build(), body).getEncoded();
    }

    private static int readWireFailInfo(byte[] response) {
        ErrorMsgContent error = (ErrorMsgContent) PKIMessage.getInstance(response).getBody().getContent();
        return error.getPKIStatusInfo().getFailInfo().intValue();
    }

    private CmpServiceImpl newService(RaProfileRepository raProfileRepository,
            CmpProfileRepository cmpProfileRepository, HeaderValidator headerValidator, boolean verbose) {
        CmpServiceImpl service = new CmpServiceImpl();
        service.setRaProfileRepository(raProfileRepository);
        service.setCmpProfileRepository(cmpProfileRepository);
        service.setAuditOperationOverride(mock(AuditOperationOverride.class));

        CmpTransactionService cmpTransactionService = mock(CmpTransactionService.class);
        when(cmpTransactionService.findByTransactionId(anyString()))
                .thenReturn(Collections.<CmpTransaction>emptyList());

        ReflectionTestUtils.setField(service, "cmpTransactionService", cmpTransactionService);
        ReflectionTestUtils.setField(service, "headerValidator", headerValidator);
        ReflectionTestUtils.setField(service, "verbose", verbose);

        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                "/v1/protocols/cmp/raProfile/" + PROFILE_NAME);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return service;
    }

    private static CmpProfile resolvedCmpProfile() {
        CmpProfile cmpProfile = mock(CmpProfile.class);
        when(cmpProfile.getEnabled()).thenReturn(true);
        when(cmpProfile.getResponseProtectionMethod()).thenReturn(ProtectionMethod.SHARED_SECRET);
        when(cmpProfile.getVariant()).thenReturn(CmpProfileVariant.V2);
        when(cmpProfile.getUuid()).thenReturn(UUID.randomUUID());
        when(cmpProfile.getName()).thenReturn("testCmpProfile");
        return cmpProfile;
    }

    private static RaProfile resolvedRaProfile(CmpProfile cmpProfile) {
        RaProfile raProfile = mock(RaProfile.class);
        when(raProfile.getUuid()).thenReturn(RA_PROFILE_UUID);
        when(raProfile.getCmpProfile()).thenReturn(cmpProfile);
        when(raProfile.getEnabled()).thenReturn(true);
        return raProfile;
    }

    private static byte[] revocationRequest() throws Exception {
        PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=user")), new GeneralName(new X500Name("CN=ManagementCA")));
        headerBuilder.setTransactionID(new byte[]{1, 2, 3, 4});
        headerBuilder.setSenderNonce("12345".getBytes(StandardCharsets.UTF_8));
        PKIBody body = CmpTestUtil.createRevocationBody(BigInteger.ONE);
        return new PKIMessage(headerBuilder.build(), body).getEncoded();
    }

    private static byte[] macProtectedRevocationRequest() throws Exception {
        PKIBody body = CmpTestUtil.createRevocationBody(BigInteger.ONE);
        return CmpTestUtil
                .createMacBasedMessage("transaction1", "shared-secret-value", body)
                .toASN1Structure()
                .getEncoded();
    }

    private static byte[] signatureProtectedRevocationRequest() throws Exception {
        PKIBody body = CmpTestUtil.createRevocationBody(BigInteger.ONE);
        var keyPair = CmpTestUtil.generateKeyPairEC();
        return CmpTestUtil
                .createSignatureBasedMessage("transaction1", keyPair.getPrivate(), body)
                .toASN1Structure()
                .getEncoded();
    }

    private static String wireStatusText(byte[] response) {
        return CmpTestUtil.wireStatusText(PKIMessage.getInstance(response).getBody());
    }
}
