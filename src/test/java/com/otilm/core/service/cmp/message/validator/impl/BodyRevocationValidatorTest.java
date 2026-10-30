package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link BodyRevocationValidator#validateIn}.
 *
 * <p>
 * RFC 4210 &sect;5.3.9 marks {@code crlEntryDetails} OPTIONAL, so a reason-less {@code rr} is valid and only reason
 * codes the platform cannot represent are rejected: out of range, 7 (unused per RFC 5280) and 8 (removeFromCRL).
 * {@link com.otilm.api.model.core.authority.CertificateRevocationReason} defines the mappable set.
 * </p>
 */
class BodyRevocationValidatorTest {

    @Test
    void acceptsRr_withoutCrlEntryDetails() {
        PKIMessage msg = rrMessage(fullCertTemplate(), null);

        // RFC 4210 §5.3.9: crlEntryDetails is OPTIONAL — a reason-less rr is valid.
        assertThatCode(() -> new BodyRevocationValidator().validateIn(msg, null)).doesNotThrowAnyException();
    }

    @Test
    void acceptsRr_withCrlEntryDetails_butNoReasonCode() {
        PKIMessage msg = rrMessage(fullCertTemplate(), nonReasonExtensions());

        // crlEntryDetails may carry other crlEntryExtensions (e.g. invalidityDate) without a
        // reasonCode — that is still a valid, reason-less revocation request.
        assertThatCode(() -> new BodyRevocationValidator().validateIn(msg, null)).doesNotThrowAnyException();
    }

    @Test
    void acceptsRr_withSupportedReasonCode_superseded() {
        PKIMessage msg = rrMessage(fullCertTemplate(), reasonCodeExtensions(4));

        // superseded (4) is a mappable reason — preserved accept behaviour.
        assertThatCode(() -> new BodyRevocationValidator().validateIn(msg, null)).doesNotThrowAnyException();
    }

    // 7 (unused per RFC 5280), 8 (removeFromCRL — an un-revoke this path cannot perform) and
    // 11 (out of range): none maps to a CertificateRevocationReason, all must be rejected.
    @ParameterizedTest
    @ValueSource(ints = {7, 8, 11})
    void rejectsRr_withUnsupportedReasonCode(int reasonCode) {
        PKIMessage msg = rrMessage(fullCertTemplate(), reasonCodeExtensions(reasonCode));

        assertThatThrownBy(() -> new BodyRevocationValidator().validateIn(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("is not supported");
    }

    @Test
    void rejectsRr_withOversizedReasonCode() {
        // An ASN.1 ENUMERATED whose value is 2^64 + 4 truncates to 4 (superseded) through
        // BigInteger.longValue(); the validator must reject on the raw value, not the
        // truncated one, so a crafted oversized code cannot masquerade as an in-range reason.
        PKIMessage msg = rrMessage(fullCertTemplate(), reasonCodeExtensions(new BigInteger("18446744073709551620")));

        assertThatThrownBy(() -> new BodyRevocationValidator().validateIn(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("is not supported");
    }

    @Test
    void rejectsRr_withMalformedReasonCode() {
        // A reasonCode extension whose value is not an ENUMERATED (here an INTEGER) is
        // malformed wire input; the validator must surface a badDataFormat rejection rather
        // than letting the ASN.1 parse throw an unchecked exception.
        PKIMessage msg = rrMessage(fullCertTemplate(), malformedReasonExtensions());

        // Malformed wire input must surface as a badDataFormat CMP rejection, not an unchecked
        // exception leaking the raw ASN.1 parse error out of the validator.
        assertThatThrownBy(() -> new BodyRevocationValidator().validateIn(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .satisfies(ex -> assertThat(((CmpProcessingException) ex).getFailureInfo())
                        .isEqualTo(PKIFailureInfo.badDataFormat));
    }

    @Test
    void rejectsRr_withoutSerialNumber() {
        PKIMessage msg = rrMessage(certTemplateWithoutSerialNumber(), reasonCodeExtensions(4));

        // The serialNumber guard must still fire ahead of any crlEntryDetails handling.
        assertThatThrownBy(() -> new BodyRevocationValidator().validateIn(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("SerialNumber");
    }

    // ------------------------------------------------------------------------------------------
    // HELPERS
    // ------------------------------------------------------------------------------------------

    private static PKIMessage rrMessage(CertTemplate certTemplate, Extensions crlEntryDetails) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(certTemplate);
        if (crlEntryDetails != null) {
            v.add(crlEntryDetails);
        }
        RevReqContent content = new RevReqContent(RevDetails.getInstance(new DERSequence(v)));
        return pkiMessage(new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content));
    }

    private static CertTemplate fullCertTemplate() {
        return new CertTemplateBuilder()
                .setIssuer(new X500Name("CN=ManagementCA"))
                .setSubject(new X500Name("CN=user"))
                .setSerialNumber(new ASN1Integer(BigInteger.valueOf(123456)))
                .build();
    }

    private static CertTemplate certTemplateWithoutSerialNumber() {
        return new CertTemplateBuilder()
                .setIssuer(new X500Name("CN=ManagementCA"))
                .setSubject(new X500Name("CN=user"))
                .build();
    }

    private static Extensions reasonCodeExtensions(long code) {
        return reasonCodeExtensions(BigInteger.valueOf(code));
    }

    private static Extensions reasonCodeExtensions(BigInteger code) {
        try {
            ExtensionsGenerator g = new ExtensionsGenerator();
            g.addExtension(Extension.reasonCode, false, new ASN1Enumerated(code));
            return g.generate();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Extensions malformedReasonExtensions() {
        try {
            ExtensionsGenerator g = new ExtensionsGenerator();
            // Wrong ASN.1 type for reasonCode — INTEGER instead of ENUMERATED.
            g.addExtension(Extension.reasonCode, false, new ASN1Integer(4));
            return g.generate();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Extensions nonReasonExtensions() {
        try {
            ExtensionsGenerator g = new ExtensionsGenerator();
            g.addExtension(Extension.invalidityDate, false, new DERGeneralizedTime("20260101000000Z"));
            return g.generate();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static PKIMessage pkiMessage(PKIBody body) {
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=test-sender")),
                new GeneralName(new X500Name("CN=test-recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .build();
        return new PKIMessage(header, body);
    }
}
