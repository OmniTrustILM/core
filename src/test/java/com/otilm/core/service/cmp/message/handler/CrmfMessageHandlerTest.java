package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cmp.CmpTransactionState;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.cmp.CmpTransaction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.CmpTransactionService;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link CrmfMessageHandler#loadCaCertificateChain} (issue #1830).
 *
 * <p>A certificate can be genuinely ISSUED while its CertificateValidationStatus is still
 * NOT_CHECKED — validation is advanced asynchronously (event-driven after issuance, hourly
 * batch as fallback). NOT_CHECKED is a transient state, not a verdict: the CA-chain builder
 * waits briefly for the in-flight validation to land (so a definitively bad status is still
 * caught) and accepts NOT_CHECKED if it doesn't — the response must reflect issuance
 * success, never fail on validation progress.</p>
 */
class CrmfMessageHandlerTest {

    private CertificateInternalService certificateService;
    private PollFeature pollFeature;
    private CrmfMessageHandler handler;

    @BeforeEach
    void setUp() {
        certificateService = Mockito.mock(CertificateInternalService.class);
        pollFeature = Mockito.mock(PollFeature.class);
        handler = new CrmfMessageHandler();
        handler.setCertificateService(certificateService);
        handler.setPollFeature(pollFeature);
    }

    @Test
    void doesNotWait_whenChainCertificateAlreadyValid() throws NotFoundException {
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.VALID);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
        Mockito.verifyNoInteractions(pollFeature);
    }

    @Test
    void accepts_whenAsyncValidationResolvesToValidDuringWait() throws NotFoundException {
        // Common case: the event-driven post-issuance validation lands ~100 ms after ISSUED;
        // the wait observes it and the chain is accepted.
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));
        Mockito.when(pollFeature.pollValidationStatus(Mockito.eq(chainCert.getUuid()), Mockito.anyLong()))
                .thenReturn(CertificateValidationStatus.VALID);

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
    }

    @Test
    void accepts_whenStillNotCheckedAfterWait() throws NotFoundException {
        // NOT_CHECKED is a transient state, not a verdict (issue #1830 expected behavior):
        // even if the validation never lands within the budget, a certificate whose
        // issuance already succeeded must not be rejected.
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));
        Mockito.when(pollFeature.pollValidationStatus(Mockito.eq(chainCert.getUuid()), Mockito.anyLong()))
                .thenReturn(CertificateValidationStatus.NOT_CHECKED);

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
    }

    @Test
    void rejects_whenWaitResolvesToInvalid() throws NotFoundException {
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));
        Mockito.when(pollFeature.pollValidationStatus(Mockito.eq(chainCert.getUuid()), Mockito.anyLong()))
                .thenReturn(CertificateValidationStatus.INVALID);

        assertThatThrownBy(() -> invokeLoadCaCertificateChain(leaf))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining("Status: Invalid");
    }

    @Test
    void rejects_whenChainCertificateDefinitivelyRevoked() throws NotFoundException {
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.REVOKED);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));

        assertThatThrownBy(() -> invokeLoadCaCertificateChain(leaf))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining("Status: Revoked");
        Mockito.verifyNoInteractions(pollFeature);
    }

    @Test
    void accepts_whenEntityNoLongerFoundDuringWait() throws NotFoundException {
        // The wait failing to find the entity resolves nothing — the status stays
        // NOT_CHECKED, which is transient, so the chain certificate passes.
        Certificate leaf = leafCertificate();
        CertificateDetailDto chainCert = chainCertificateDto(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateChain(Mockito.any(SecuredUUID.class), Mockito.eq(true)))
                .thenReturn(chainResponse(chainCert));
        Mockito.when(pollFeature.pollValidationStatus(Mockito.eq(chainCert.getUuid()), Mockito.anyLong()))
                .thenThrow(new NotFoundException(Certificate.class, chainCert.getUuid()));

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
    }

    @Test
    void asyncAcceptance_returnsIpWithStatusWaiting_notBarePollRep() {
        // RFC 4210 §5.3.22: the polling exchange is initiated by the server returning an
        // ip/cp/kup whose PKIStatusInfo is 'waiting' — the client then sends pollReq. A bare
        // pollRep as the direct answer to ir is out-of-state and conformant clients
        // (openssl cmp) abort with "unexpected pkibody", orphaning the issued certificate.
        CmpTransactionService cmpTransactionService = Mockito.mock(CmpTransactionService.class);
        Mockito.when(cmpTransactionService.createTransactionEntity(
                        Mockito.anyString(), Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any()))
                .thenReturn(new CmpTransaction());
        CrmfIrCrMessageHandler irCrMessageHandler = Mockito.mock(CrmfIrCrMessageHandler.class);
        Mockito.when(irCrMessageHandler.getTransactionState()).thenReturn(CmpTransactionState.CERT_ISSUED);
        handler.setCmpTransactionService(cmpTransactionService);
        handler.setCrmfIrCrMessageHandler(irCrMessageHandler);

        ConfigurationContext configuration = configurationWithMockedProtection();
        CertRequest certRequest = new CertRequest(
                new ASN1Integer(0),
                new CertTemplateBuilder().setSubject(new X500Name("CN=cmp-certificate")).build(),
                null);
        PKIMessage request = irMessage(certRequest);
        ClientCertificateDataResponseDto requestedCert = new ClientCertificateDataResponseDto();
        requestedCert.setUuid(UUID.randomUUID().toString());

        PKIMessage response = (PKIMessage) ReflectionTestUtils.invokeMethod(
                handler, "handleAsynchronousAcceptance",
                request.getHeader().getTransactionID(), request, configuration,
                "ir", requestedCert, certRequest);

        assertThat(response).isNotNull();
        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_INIT_REP);
        CertRepMessage repMessage = (CertRepMessage) response.getBody().getContent();
        CertResponse certResponse = repMessage.getResponse()[0];
        assertThat(certResponse.getStatus().getStatus().intValue()).isEqualTo(PKIStatus.WAITING);
        assertThat(certResponse.getCertifiedKeyPair()).isNull();
        assertThat(certResponse.getCertReqId().getValue()).isEqualTo(BigInteger.ZERO);
    }

    private static PKIMessage irMessage(CertRequest certRequest) {
        PKIHeader header = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=test-sender")),
                new GeneralName(new X500Name("CN=test-recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .setSenderNonce(new DEROctetString(new byte[]{5, 6, 7, 8}))
                .build();
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg(certRequest, null, null));
        return new PKIMessage(header, new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages));
    }

    private static ConfigurationContext configurationWithMockedProtection() {
        ConfigurationContext cfg = Mockito.mock(ConfigurationContext.class);
        ProtectionStrategy strategy = Mockito.mock(ProtectionStrategy.class);
        try {
            Mockito.when(cfg.getProtectionStrategy()).thenReturn(strategy);
            Mockito.when(cfg.getRecipient()).thenReturn(new GeneralName(new X500Name("CN=test-recipient")));
            Mockito.when(strategy.getSender()).thenReturn(new GeneralName(new X500Name("CN=test-sender")));
            Mockito.when(strategy.getProtectionAlg()).thenReturn(new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1.2")));
            Mockito.when(strategy.getSenderKID()).thenReturn(new DEROctetString(new byte[]{1, 2, 3}));
            Mockito.when(strategy.getProtectingExtraCerts()).thenReturn(List.of());
            Mockito.when(strategy.createProtection(Mockito.any(PKIHeader.class), Mockito.any(PKIBody.class)))
                    .thenReturn(new DERBitString(new byte[]{0x01, 0x02}));
        } catch (Exception e) {
            throw new RuntimeException("test setup failed", e);
        }
        return cfg;
    }

    @SuppressWarnings("unchecked")
    private List<X509Certificate> invokeLoadCaCertificateChain(Certificate leaf) {
        return (List<X509Certificate>) ReflectionTestUtils.invokeMethod(
                handler, "loadCaCertificateChain", new DEROctetString(new byte[]{1, 2, 3, 4}), 0, leaf);
    }

    private static Certificate leafCertificate() {
        Certificate leaf = new Certificate();
        leaf.setUuid(UUID.randomUUID());
        leaf.setSerialNumber("01");
        return leaf;
    }

    private static CertificateChainResponseDto chainResponse(CertificateDetailDto... certificates) {
        CertificateChainResponseDto response = new CertificateChainResponseDto();
        response.setCompleteChain(true);
        response.setCertificates(List.of(certificates));
        return response;
    }

    private static CertificateDetailDto chainCertificateDto(CertificateValidationStatus status) {
        CertificateDetailDto dto = new CertificateDetailDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setFingerprint("aa:bb:cc");
        dto.setValidationStatus(status);
        dto.setCertificateContent(generateSelfSignedCertBase64());
        return dto;
    }

    // Real, self-signed X.509 cert (base64 DER) so CertificateUtil.parseCertificate
    // succeeds once the validation-status gate passes — same technique as
    // PollReqMessageHandlerTest.certificateContentWithRealPem() in this same package.
    private static String generateSelfSignedCertBase64() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            X500Name name = new X500Name("CN=test-ca-chain");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    name, BigInteger.ONE, notBefore, notAfter, name, kp.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
            X509Certificate x509 = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            return Base64.getEncoder().encodeToString(x509.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("test setup failed: cannot build self-signed cert", e);
        }
    }
}
