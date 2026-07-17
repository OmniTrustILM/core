package com.otilm.core.service.cmp.configurations.variants;

import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link Mobile3gppProfileContext#validateOnCrmfResponse}.
 *
 * <p>3GPP requires the extraCerts chain on an ip/cp/kup that carries an issued certificate.
 * A pending response (RFC 4210 §5.3.22 PKIStatus 'waiting', emitted while issuance completes
 * asynchronously) has no certifiedKeyPair and therefore no chain to advertise — it must be
 * exempt from the extraCerts requirement, otherwise the async-pending path returns a
 * systemFailure instead of the intended 'waiting' response.</p>
 */
class Mobile3gppProfileContextTest {

    private Mobile3gppProfileContext context() {
        // validateOnCrmfResponse reads only the response argument, not constructor state,
        // so the collaborators can be null for this unit test.
        return new Mobile3gppProfileContext(null, null, null, null, null, null);
    }

    @Test
    void acceptsWaitingResponse_withoutExtraCerts() {
        PKIMessage waiting = certRepMessage(PKIBody.TYPE_INIT_REP,
                new CertResponse(new org.bouncycastle.asn1.ASN1Integer(0), new PKIStatusInfo(PKIStatus.waiting)),
                null);

        assertThatCode(() -> context().validateOnCrmfResponse(waiting))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsIssuedResponse_withoutExtraCerts() throws Exception {
        CertResponse issued = new CertResponse(
                new org.bouncycastle.asn1.ASN1Integer(0),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(selfSignedCmpCertificate())),
                null);
        PKIMessage issuedResponse = certRepMessage(PKIBody.TYPE_INIT_REP, issued, null);

        assertThatThrownBy(() -> context().validateOnCrmfResponse(issuedResponse))
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining("extraCerts");
    }

    @Test
    void acceptsIssuedResponse_withExtraCerts() throws Exception {
        CMPCertificate cmpCert = selfSignedCmpCertificate();
        CertResponse issued = new CertResponse(
                new org.bouncycastle.asn1.ASN1Integer(0),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(cmpCert)),
                null);
        PKIMessage issuedResponse = certRepMessage(PKIBody.TYPE_INIT_REP, issued, new CMPCertificate[]{cmpCert});

        assertThatCode(() -> context().validateOnCrmfResponse(issuedResponse))
                .doesNotThrowAnyException();
    }

    private static PKIMessage certRepMessage(int bodyType, CertResponse response, CMPCertificate[] extraCerts) {
        PKIHeader header = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=sender")),
                new GeneralName(new X500Name("CN=recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .build();
        PKIBody body = new PKIBody(bodyType, new CertRepMessage(null, new CertResponse[]{response}));
        return new PKIMessage(header, body, null, extraCerts);
    }

    private static CMPCertificate selfSignedCmpCertificate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=test-3gpp");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        Certificate certificate = builder.build(signer).toASN1Structure();
        return new CMPCertificate(certificate);
    }
}
