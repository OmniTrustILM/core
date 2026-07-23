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
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
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
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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

    private static final String SELF_SIGNED_CERT_BASE64 = generateSelfSignedCertBase64();

    private CertificateInternalService certificateService;
    private CertificateValidationStatusPoller validationStatusPoller;
    private CrmfMessageHandler handler;

    @BeforeEach
    void setUp() {
        certificateService = mock(CertificateInternalService.class);
        validationStatusPoller = mock(CertificateValidationStatusPoller.class);
        handler = new CrmfMessageHandler();
        handler.setCertificateService(certificateService);
        handler.setValidationStatusPoller(validationStatusPoller);
    }

    @Test
    void acceptsLeaf_whenResolveOrKeepReturnsValid() throws NotFoundException {
        // The leaf is resolved through the poller (its DTO may be VALID already, or NOT_CHECKED
        // that resolves during the wait — both surface here as VALID).
        UUID leafUuid = UUID.randomUUID();
        Certificate leaf = leafCertificate(leafUuid);
        CertificateDetailDto leafDto = certificateDto(leafUuid.toString(), CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateChain(any(SecuredUUID.class), eq(true)))
                .thenReturn(chainResponse(leafDto));
        when(validationStatusPoller.resolveOrKeep(leafDto)).thenReturn(CertificateValidationStatus.VALID);

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
    }

    @Test
    void acceptsLeaf_whenResolveOrKeepReturnsNotChecked() throws NotFoundException {
        // NOT_CHECKED is a transient state for the freshly-issued leaf, not a verdict : if the poller cannot resolve it within the budget, the leaf still passes.
        UUID leafUuid = UUID.randomUUID();
        Certificate leaf = leafCertificate(leafUuid);
        CertificateDetailDto leafDto = certificateDto(leafUuid.toString(), CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateChain(any(SecuredUUID.class), eq(true)))
                .thenReturn(chainResponse(leafDto));
        when(validationStatusPoller.resolveOrKeep(leafDto)).thenReturn(CertificateValidationStatus.NOT_CHECKED);

        List<X509Certificate> chain = invokeLoadCaCertificateChain(leaf);

        assertThat(chain).hasSize(1);
    }

    @Test
    void rejectsLeaf_whenResolveOrKeepReturnsInvalid() throws NotFoundException {
        UUID leafUuid = UUID.randomUUID();
        Certificate leaf = leafCertificate(leafUuid);
        CertificateDetailDto leafDto = certificateDto(leafUuid.toString(), CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateChain(any(SecuredUUID.class), eq(true)))
                .thenReturn(chainResponse(leafDto));
        when(validationStatusPoller.resolveOrKeep(leafDto)).thenReturn(CertificateValidationStatus.INVALID);

        assertThatThrownBy(() -> invokeLoadCaCertificateChain(leaf))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining("Status: Invalid");
    }

    @Test
    void rejectsNonLeafCaCertificate_whenNotChecked() throws NotFoundException {
        // Security: the NOT_CHECKED tolerance is ONLY for the freshly-issued
        // leaf. A CA / issuer cert in the chain that is still NOT_CHECKED must be rejected, not
        // waited on and advertised. The leaf here is VALID; the CA entry is NOT_CHECKED.
        UUID leafUuid = UUID.randomUUID();
        Certificate leaf = leafCertificate(leafUuid);
        CertificateDetailDto leafDto = certificateDto(leafUuid.toString(), CertificateValidationStatus.VALID);
        CertificateDetailDto caDto = certificateDto(UUID.randomUUID().toString(), CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateChain(any(SecuredUUID.class), eq(true)))
                .thenReturn(chainResponse(leafDto, caDto));
        when(validationStatusPoller.resolveOrKeep(leafDto)).thenReturn(CertificateValidationStatus.VALID);

        assertThatThrownBy(() -> invokeLoadCaCertificateChain(leaf))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining("Status: Not checked");
        // The CA cert must never be resolved/waited on — only the leaf goes through the poller.
        verify(validationStatusPoller).resolveOrKeep(leafDto);
        verify(validationStatusPoller, never()).resolveOrKeep(caDto);
    }

    @Test
    void asyncAcceptance_returnsIpWithStatusWaiting_notBarePollRep() {
        // RFC 4210 §5.3.22: the polling exchange is initiated by the server returning an
        // ip/cp/kup whose PKIStatusInfo is 'waiting' — the client then sends pollReq. A bare
        // pollRep as the direct answer to ir is out-of-state and conformant clients
        // (openssl cmp) abort with "unexpected pkibody", orphaning the issued certificate.
        CmpTransactionService cmpTransactionService = mock(CmpTransactionService.class);
        when(cmpTransactionService.createTransactionEntity(
                        anyString(), any(), anyString(), any(), any()))
                .thenReturn(new CmpTransaction());
        CrmfIrCrMessageHandler irCrMessageHandler = mock(CrmfIrCrMessageHandler.class);
        when(irCrMessageHandler.getTransactionState()).thenReturn(CmpTransactionState.CERT_ISSUED);
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
        ConfigurationContext cfg = mock(ConfigurationContext.class);
        ProtectionStrategy strategy = mock(ProtectionStrategy.class);
        try {
            when(cfg.getProtectionStrategy()).thenReturn(strategy);
            when(cfg.getRecipient()).thenReturn(new GeneralName(new X500Name("CN=test-recipient")));
            when(strategy.getSender()).thenReturn(new GeneralName(new X500Name("CN=test-sender")));
            when(strategy.getProtectionAlg()).thenReturn(new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1.2")));
            when(strategy.getSenderKID()).thenReturn(new DEROctetString(new byte[]{1, 2, 3}));
            when(strategy.getProtectingExtraCerts()).thenReturn(List.of());
            when(strategy.createProtection(any(PKIHeader.class), any(PKIBody.class)))
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

    private static Certificate leafCertificate(UUID uuid) {
        Certificate leaf = new Certificate();
        leaf.setUuid(uuid);
        leaf.setSerialNumber("01");
        return leaf;
    }

    private static CertificateChainResponseDto chainResponse(CertificateDetailDto... certificates) {
        CertificateChainResponseDto response = new CertificateChainResponseDto();
        response.setCompleteChain(true);
        response.setCertificates(List.of(certificates));
        return response;
    }

    private static CertificateDetailDto certificateDto(String uuid, CertificateValidationStatus status) {
        CertificateDetailDto dto = new CertificateDetailDto();
        dto.setUuid(uuid);
        dto.setFingerprint("aa:bb:cc");
        dto.setValidationStatus(status);
        dto.setCertificateContent(SELF_SIGNED_CERT_BASE64);
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
