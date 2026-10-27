package com.otilm.core.model.request;

import com.otilm.api.exception.CertificateRequestException;
import java.math.BigInteger;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CrmfCertificateRequestTest {

    @Test
    void getPublicKey_withoutKeyInTemplate_throwsCertificateRequestException() throws Exception {
        // given
        CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(BigInteger.ONE);
        builder.setSubject(new X500Name("CN=subject"));
        byte[] encoded = new CertReqMessages(builder.build().toASN1Structure()).getEncoded();
        CrmfCertificateRequest request = new CrmfCertificateRequest(encoded);

        // when / then
        assertThatThrownBy(request::getPublicKey)
                .isInstanceOf(CertificateRequestException.class)
                .hasMessage("Cannot get public key from certificate request.")
                .hasNoCause();
    }
}
