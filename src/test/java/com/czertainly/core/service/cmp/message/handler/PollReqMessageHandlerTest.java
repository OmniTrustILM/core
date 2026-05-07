package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.service.cmp.message.protection.ProtectionStrategy;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PollReqMessageHandler}.
 *
 * <p>Pinned cases:</p>
 * <ul>
 *   <li>A pollReq for a transaction whose originating body was a revocation request must
 *       be cleanly rejected: wrapping the response in {@code CertRepMessage} regardless of
 *       original type would produce an invalid CMP body for revocation polls.</li>
 *   <li>A pollReq landing on a {@code PENDING_REVOKE} certificate must be rejected — RFC
 *       4210 §5.2.6 limits polling to ip/cp/kup contexts (issue/renew/rekey); CMP has no
 *       in-protocol way to represent a pending revocation.</li>
 * </ul>
 */
class PollReqMessageHandlerTest {

    private CmpTransactionService cmpTransactionService;
    private PollReqMessageHandler handler;
    private ConfigurationContext configuration;

    @BeforeEach
    void setUp() {
        cmpTransactionService = Mockito.mock(CmpTransactionService.class);
        handler = new PollReqMessageHandler();
        handler.setCmpTransactionService(cmpTransactionService);

        // Minimal configuration; the rejection paths exercised below short-circuit before
        // any message building, so no CmpProfile / shared secret / PkiMessageBuilder is
        // exercised — keep this trivial to avoid pulling in encryption setup.
        configuration = Mockito.mock(ConfigurationContext.class);
    }

    @Test
    void rejectsRevocationPoll_whenTransactionOriginatedFromRevocationRequest() {
        // The handler must not wrap a revocation-originated pollReq response in
        // CertRepMessage — that body type+content combination is invalid CMP. Reject
        // these polls explicitly instead.
        CmpTransaction trx = transactionWithCert(certificateInState(CertificateState.PENDING_REVOKE));
        trx.setOriginalRequestBodyType(PKIBody.TYPE_REVOCATION_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage pollReq = pollReqMessage();

        assertThatThrownBy(() -> handler.handle(pollReq, configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("not supported for revocation transactions");
    }

    @Test
    void rejectsPoll_whenCertificateInPendingRevoke_andNoOriginalBodyType() {
        // Defensive case: legacy transactions where originalRequestBodyType is NULL but
        // the certificate is somehow in PENDING_REVOKE — must not silently emit a CMP body
        // that doesn't correspond to the original operation.
        CmpTransaction trx = transactionWithCert(certificateInState(CertificateState.PENDING_REVOKE));
        trx.setOriginalRequestBodyType(null);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage pollReq = pollReqMessage();

        assertThatThrownBy(() -> handler.handle(pollReq, configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("PENDING_REVOKE");
    }

    @Test
    void rejectsPoll_whenNoTransactionForTransactionId() {
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of());

        PKIMessage pollReq = pollReqMessage();

        assertThatThrownBy(() -> handler.handle(pollReq, configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("no in-flight CMP transaction");
    }

    @Test
    void rejectsPoll_whenCertificateInTerminalState() {
        for (CertificateState terminal : List.of(CertificateState.REVOKED, CertificateState.REJECTED, CertificateState.FAILED)) {
            CmpTransaction trx = transactionWithCert(certificateInState(terminal));
            trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
            Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                    .thenReturn(List.of(trx));

            PKIMessage pollReq = pollReqMessage();

            assertThatThrownBy(() -> handler.handle(pollReq, configuration))
                    .isInstanceOf(CmpProcessingException.class)
                    .hasMessageContaining("client should not poll");
        }
    }

    @Test
    void rejectsPoll_withWrongBodyType() {
        // The handler must guard against being called with a non-pollReq body — protects
        // against accidental wiring elsewhere in the dispatch chain.
        PKIHeader header = pkiHeader();
        PKIMessage notAPollReq = new PKIMessage(header,
                new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent()));

        assertThatThrownBy(() -> handler.handle(notAPollReq, configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("pollReq handler invoked for wrong body type");
    }

    @Test
    void rejectsPoll_withEmptyCertReqIdValues() {
        PKIHeader header = pkiHeader();
        PKIMessage emptyPollReq = new PKIMessage(header,
                new PKIBody(PKIBody.TYPE_POLL_REQ, new PollReqContent(new ASN1Integer[0])));

        assertThatThrownBy(() -> handler.handle(emptyPollReq, configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("no certReqId");
    }

    private static Certificate certificateInState(CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(state);
        cert.setSerialNumber("01");
        cert.setSubjectDn("CN=test");
        // Cert content not exercised in the rejection paths above; left null on purpose.
        cert.setCertificateContent((CertificateContent) null);
        return cert;
    }

    private static CmpTransaction transactionWithCert(Certificate cert) {
        CmpTransaction trx = new CmpTransaction();
        trx.setUuid(UUID.randomUUID());
        trx.setCertificate(cert);
        trx.setCertificateUuid(cert.getUuid());
        trx.setTransactionId("test-tid");
        return trx;
    }

    private static PKIHeader pkiHeader() {
        return new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=test-sender")),
                new GeneralName(new X500Name("CN=test-recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .build();
    }

    private static PKIMessage pollReqMessage() {
        return new PKIMessage(pkiHeader(),
                new PKIBody(PKIBody.TYPE_POLL_REQ, new PollReqContent(new ASN1Integer(BigInteger.ZERO))));
    }

    // ==================== Happy paths ====================

    @Test
    void buildsPollRep_whenCertificateInPendingIssue() throws Exception {
        // Asynchronous-acceptance from the connector keeps the certificate in PENDING_ISSUE.
        // The handler must respond with a CMP pollRep so the client knows to retry later.
        configuration = configurationWithMockedProtection();
        CmpTransaction trx = transactionWithCert(certificateInState(CertificateState.PENDING_ISSUE));
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage response = handler.handle(pollReqMessage(), configuration);

        assertThat(response).isNotNull();
        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_POLL_REP);
        assertThat(response.getBody().getContent()).isInstanceOf(PollRepContent.class);
    }

    @Test
    void buildsPollRep_whenCertificateInRequestedOrPendingApprovalState() throws Exception {
        configuration = configurationWithMockedProtection();
        for (CertificateState inProgress : List.of(CertificateState.REQUESTED, CertificateState.PENDING_APPROVAL)) {
            CmpTransaction trx = transactionWithCert(certificateInState(inProgress));
            trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
            Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                    .thenReturn(List.of(trx));

            PKIMessage response = handler.handle(pollReqMessage(), configuration);

            assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_POLL_REP);
        }
    }

    @Test
    void buildsCertReadyResponse_whenCertificateNowIssued_forInitRequest() throws Exception {
        // After the asynchronous issuance completes, a subsequent pollReq should receive
        // an ip / cp / kup response (depending on original request body type) carrying the
        // issued certificate.
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(certificateContentWithRealPem());
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage response = handler.handle(pollReqMessage(), configuration);

        assertThat(response).isNotNull();
        // ir originated → ip response (TYPE_INIT_REQ + 1)
        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_INIT_REP);
    }

    @Test
    void buildsCertReadyResponse_withCpType_whenCertificateNowIssued_forCertRequest() throws Exception {
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(certificateContentWithRealPem());
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_CERT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage response = handler.handle(pollReqMessage(), configuration);

        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_CERT_REP);
    }

    @Test
    void buildsCertReadyResponse_withKupType_whenCertificateNowIssued_forKurRequest() throws Exception {
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(certificateContentWithRealPem());
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_KEY_UPDATE_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage response = handler.handle(pollReqMessage(), configuration);

        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_KEY_UPDATE_REP);
    }

    @Test
    void buildsCertReadyResponse_withCpType_whenLegacyTransactionWithoutOriginalBodyType() throws Exception {
        // Pre-existing transactions (created before the original_request_body_type column
        // existed) have NULL original body type; default to cp (TYPE_CERT_REP).
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(certificateContentWithRealPem());
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(null);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        PKIMessage response = handler.handle(pollReqMessage(), configuration);

        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_CERT_REP);
    }

    @Test
    void rejectsPoll_whenStoredCertificateContentIsMalformed() {
        // The cert has CertificateContent with non-empty (but malformed) base64 — passes the
        // null-content guard at lines 165-166 but fails X.509 parsing at line 170. Must
        // surface a clean CmpProcessingException, not propagate CertificateException.
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        CertificateContent malformed = new CertificateContent();
        // Valid base64 but the bytes are not a parseable X.509 — triggers CertificateException
        // inside CertificateUtil.parseCertificate (instead of an IllegalArgumentException
        // from base64 decoding, which would not be caught by the CertificateException handler).
        malformed.setContent(Base64.getEncoder().encodeToString("not-an-x509-certificate".getBytes()));
        cert.setCertificateContent(malformed);
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        assertThatThrownBy(() -> handler.handle(pollReqMessage(), configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasCauseInstanceOf(CertificateException.class);
    }

    @Test
    void rejectsPoll_whenCertificateContentMissing_forIssuedCert() {
        // Defensive: if the cert is reported as ISSUED but its content is missing in the DB,
        // the handler must not silently emit a malformed body — fail clean.
        configuration = configurationWithMockedProtection();
        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(null);
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        assertThatThrownBy(() -> handler.handle(pollReqMessage(), configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("certificate has no parseable content");
    }

    @Test
    void rejectsPoll_whenTransactionHasNoAssociatedCertificate() {
        // Defensive: a transaction row with a NULL certificate reference should not trip
        // a NullPointerException in the handler — must surface a clean systemFailure.
        CmpTransaction trx = new CmpTransaction();
        trx.setUuid(UUID.randomUUID());
        trx.setCertificate(null);
        trx.setTransactionId("test-tid");
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        assertThatThrownBy(() -> handler.handle(pollReqMessage(), configuration))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("CMP transaction has no associated certificate");
    }

    @Test
    void rejectsPoll_whenPollRepBuildingFails() throws Exception {
        // The pollRep builder catches generic Exception so a misbehaving ProtectionStrategy
        // (createProtection throws) must produce a CmpProcessingException, not an opaque
        // runtime error. The thrown exception is wrapped at the message-builder layer; we
        // verify both the resulting exception type and that the underlying RuntimeException
        // is preserved in the cause chain.
        ConfigurationContext cfg = configurationWithMockedProtection();
        Mockito.when(cfg.getProtectionStrategy().createProtection(Mockito.any(PKIHeader.class), Mockito.any(PKIBody.class)))
                .thenThrow(new RuntimeException("forced protection failure"));

        CmpTransaction trx = transactionWithCert(certificateInState(CertificateState.PENDING_ISSUE));
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        assertThatThrownBy(() -> handler.handle(pollReqMessage(), cfg))
                .isInstanceOf(CmpProcessingException.class)
                .hasRootCauseMessage("forced protection failure");
    }

    @Test
    void rejectsPoll_whenCertReadyResponseBuildingFails() throws Exception {
        // The cert-ready builder catches generic Exception so a misbehaving ProtectionStrategy
        // must produce a CmpProcessingException with the underlying failure preserved in the
        // cause chain.
        ConfigurationContext cfg = configurationWithMockedProtection();
        Mockito.when(cfg.getProtectionStrategy().createProtection(Mockito.any(PKIHeader.class), Mockito.any(PKIBody.class)))
                .thenThrow(new RuntimeException("forced protection failure"));

        Certificate cert = certificateInState(UUID.randomUUID(), CertificateState.ISSUED);
        cert.setCertificateContent(certificateContentWithRealPem());
        CmpTransaction trx = transactionWithCert(cert);
        trx.setOriginalRequestBodyType(PKIBody.TYPE_INIT_REQ);
        Mockito.when(cmpTransactionService.findByTransactionId(Mockito.anyString()))
                .thenReturn(List.of(trx));

        assertThatThrownBy(() -> handler.handle(pollReqMessage(), cfg))
                .isInstanceOf(CmpProcessingException.class)
                .hasRootCauseMessage("forced protection failure");
    }

    private static Certificate certificateInState(UUID uuid, CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(uuid);
        cert.setState(state);
        cert.setSerialNumber("01");
        cert.setSubjectDn("CN=test");
        return cert;
    }

    private static CertificateContent certificateContentWithRealPem() {
        // Generate a real self-signed X.509 cert at runtime so the handler's parse step
        // (CertificateUtil.parseCertificate) succeeds.
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            X500Name name = new X500Name("CN=test-poll");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    name, BigInteger.ONE, notBefore, notAfter, name, kp.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
            X509Certificate x509 = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            CertificateContent content = new CertificateContent();
            content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
            return content;
        } catch (Exception e) {
            throw new RuntimeException("test setup failed: cannot build self-signed cert", e);
        }
    }

    private ConfigurationContext configurationWithMockedProtection() {
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
}
