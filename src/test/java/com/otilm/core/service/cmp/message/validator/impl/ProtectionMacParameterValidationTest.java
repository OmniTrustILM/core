package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Guards the client-supplied Password-Based MAC parameters that {@link ProtectionMacValidator} checks before computing
 * the MAC — and, in registration mode, before the challenge gate takes its row lock. The iteration count drives a
 * digest loop, so an unbounded value would burn CPU while holding the lock.
 */
class ProtectionMacParameterValidationTest {

    private static final byte[] TID = {1, 2, 3, 4};
    private static final AlgorithmIdentifier SHA1 = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
    private static final AlgorithmIdentifier HMAC_SHA1 = new AlgorithmIdentifier(IANAObjectIdentifiers.hmacSHA1);
    private static final AlgorithmIdentifier MD5 = new AlgorithmIdentifier(
            new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.2.5"));

    private static PKIMessage pbmMessage(BigInteger iterationCount, int saltLength, AlgorithmIdentifier owf,
            AlgorithmIdentifier mac) {
        PBMParameter pbm = new PBMParameter(new DEROctetString(new byte[saltLength]), owf,
                new ASN1Integer(iterationCount), mac);
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=user")),
                new GeneralName(new X500Name("CN=ca")))
                .setTransactionID(TID)
                .setProtectionAlg(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, pbm))
                .build();
        return new PKIMessage(header, new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent()),
                new DERBitString(new byte[]{0}));
    }

    @Test
    void acceptsParametersWithinTheBounds() {
        assertThatCode(() -> ProtectionMacValidator
                .validatePbmParameters(pbmMessage(BigInteger.valueOf(1000), 16, SHA1, HMAC_SHA1),
                        new DEROctetString(TID)))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsAnIterationCountAboveTheMaximum() {
        assertThatThrownBy(() -> ProtectionMacValidator
                .validatePbmParameters(
                        pbmMessage(BigInteger.valueOf(ProtectionMacValidator.MAX_PBM_ITERATION_COUNT + 1L), 16, SHA1,
                                HMAC_SHA1),
                        new DEROctetString(TID)))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void rejectsANonPositiveIterationCount() {
        assertThatThrownBy(() -> ProtectionMacValidator
                .validatePbmParameters(pbmMessage(BigInteger.ZERO, 16, SHA1, HMAC_SHA1), new DEROctetString(TID)))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void rejectsASaltAboveTheMaximum() {
        assertThatThrownBy(() -> ProtectionMacValidator
                .validatePbmParameters(pbmMessage(BigInteger.valueOf(1000),
                        ProtectionMacValidator.MAX_PBM_SALT_LENGTH + 1, SHA1, HMAC_SHA1), new DEROctetString(TID)))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void rejectsADisallowedOneWayFunction() {
        assertThatThrownBy(() -> ProtectionMacValidator
                .validatePbmParameters(pbmMessage(BigInteger.valueOf(1000), 16, MD5, HMAC_SHA1),
                        new DEROctetString(TID)))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badAlg));
    }

    @Test
    void rejectsADisallowedMacAlgorithm() {
        assertThatThrownBy(() -> ProtectionMacValidator
                .validatePbmParameters(pbmMessage(BigInteger.valueOf(1000), 16, SHA1, MD5), new DEROctetString(TID)))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badAlg));
    }
}
