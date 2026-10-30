package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the protection-type consistency check in {@link ProtectionValidator}.
 *
 * <p>
 * Regression coverage: a message whose actual protection type contradicts the profile's configured
 * {@code Requested Protection Method} must be rejected with a proper CMP {@code badMessageCheck} rejection (RFC 4210
 * §5.2.7) rather than being allowed through to a strategy that assumes a different type.
 * </p>
 */
class ProtectionValidatorTest {

    private static final ASN1OctetString TID = new DEROctetString(new byte[]{1, 2, 3, 4});
    private static final AlgorithmIdentifier SIGNATURE_ALG = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier("1.2.840.10045.4.3.3")); // ecdsa-with-SHA384
    private static final AlgorithmIdentifier PBM_ALG = new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac);
    private static final AlgorithmIdentifier PBMAC1_ALG = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1);

    @Test
    void rejectsSignatureMessage_whenProfileRequiresSharedSecret() {
        assertThatThrownBy(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, ProtectionMethod.SHARED_SECRET))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void rejectsPbmMessage_whenProfileRequiresSignature() {
        assertThatThrownBy(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBM_ALG, ProtectionMethod.SIGNATURE))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void acceptsPbmMessage_whenProfileRequiresSharedSecret() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBM_ALG, ProtectionMethod.SHARED_SECRET))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsPbmac1Message_whenProfileRequiresSharedSecret() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBMAC1_ALG, ProtectionMethod.SHARED_SECRET))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsSignatureMessage_whenProfileRequiresSignature() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, ProtectionMethod.SIGNATURE))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsAnyMessage_whenProfileDoesNotConstrainRequestMethod() {
        assertThatCode(() -> ProtectionValidator.assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, null))
                .doesNotThrowAnyException();
    }

    /** A message with neither protection bits nor a protectionAlg; the body is irrelevant to the check under test. */
    private static PKIMessage unprotectedMessage() {
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=user")),
                new GeneralName(new X500Name("CN=ca"))).setTransactionID(TID.getOctets()).build();
        return new PKIMessage(header, new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent()));
    }

    @Test
    void rejectsUnprotectedRequest_inRegistrationMode() {
        ConfigurationContext configuration = mock(ConfigurationContext.class);
        when(configuration.isRegistrationMode()).thenReturn(true);

        assertThatThrownBy(() -> new ProtectionValidator().validateIn(unprotectedMessage(), configuration))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.notAuthorized));
    }

    @Test
    void acceptsUnprotectedRequest_whenNotInRegistrationMode() {
        ConfigurationContext configuration = mock(ConfigurationContext.class);
        when(configuration.isRegistrationMode()).thenReturn(false);

        assertThatCode(() -> new ProtectionValidator().validateIn(unprotectedMessage(), configuration))
                .doesNotThrowAnyException();
    }
}
