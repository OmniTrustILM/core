package com.otilm.core.key.normalization;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9FieldID;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * The bound on an elliptic curve a key states by its parameters rather than by its name: no larger than the curves the
 * platform holds by name. Bouncy Castle builds a key over a larger curve at a cost that grows with its parameters and
 * that nothing charges: it tests the field, checks the generator against the order when the cofactor is not 1, and
 * derives a public key with a private value the order bounds.
 */
public final class ExplicitCurve {

    /**
     * The size in bits of the largest field a curve the platform holds by name lies over: that of sect571k1 and
     * sect571r1, larger than the prime field of P-521.
     */
    static final int MAXIMUM_FIELD_BITS = 571;

    /**
     * The size in bits of the largest order a curve over a field of {@link #MAXIMUM_FIELD_BITS} bits can have: by the
     * Hasse bound, the order of a curve exceeds its field by one bit at most.
     */
    static final int MAXIMUM_ORDER_BITS = MAXIMUM_FIELD_BITS + 1;

    private ExplicitCurve() {
    }

    /**
     * Whether the algorithm is that of an elliptic-curve key stating its curve by parameters larger than those of any
     * curve the platform holds by name: a field of more than {@link #MAXIMUM_FIELD_BITS} bits, or an order of more than
     * {@link #MAXIMUM_ORDER_BITS} bits. Parameters that cannot be read are left to whoever reads the key.
     *
     * @param algorithm the algorithm of a private key, or of the public key a certificate or a request carries
     * @return whether the key states such a curve
     */
    public static boolean largerThanAnyNamed(AlgorithmIdentifier algorithm) {
        ASN1Encodable parameters = algorithm.getParameters();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm.getAlgorithm()) || parameters == null
                || !(parameters.toASN1Primitive() instanceof ASN1Sequence explicit)) {
            return false;
        }
        try {
            // the version, the field, the curve, the generator, the order and the cofactor, in that order
            return fieldBits(X9FieldID.getInstance(explicit.getObjectAt(1)))
                    .compareTo(BigInteger.valueOf(MAXIMUM_FIELD_BITS)) > 0
                    || ASN1Integer.getInstance(explicit.getObjectAt(4)).getValue().bitLength() > MAXIMUM_ORDER_BITS;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The size of the field in bits: the length of its prime, or the degree of a characteristic-two field. */
    private static BigInteger fieldBits(X9FieldID field) {
        if (X9ObjectIdentifiers.prime_field.equals(field.getIdentifier())) {
            return BigInteger.valueOf(ASN1Integer.getInstance(field.getParameters()).getValue().bitLength());
        }
        return ASN1Integer.getInstance(ASN1Sequence.getInstance(field.getParameters()).getObjectAt(0)).getValue();
    }
}
