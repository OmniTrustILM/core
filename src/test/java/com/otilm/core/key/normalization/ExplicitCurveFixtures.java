package com.otilm.core.key.normalization;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;

/** Elliptic curves as a key states them by their parameters, made up for the tests. */
public final class ExplicitCurveFixtures {

    private ExplicitCurveFixtures() {
    }

    /**
     * A curve made up through a random point over a prime field of the size given, stating an order of the size given
     * and the cofactor given. Only a reader's own checks tie the order to the curve: with a cofactor of 1 it checks
     * none, and with another it multiplies the point by the order.
     *
     * @param fieldBits the size in bits of the field's prime
     * @param orderBits the size in bits of the order the curve states
     * @param cofactor the cofactor the curve states
     * @return the curve, with the point as its generator
     */
    public static X9ECParameters madeUp(int fieldBits, int orderBits, BigInteger cofactor) {
        SecureRandom random = new SecureRandom();
        BigInteger prime = BigInteger.probablePrime(fieldBits, random);
        BigInteger a = new BigInteger(fieldBits - 1, random);
        BigInteger x = new BigInteger(fieldBits - 1, random);
        BigInteger y = new BigInteger(fieldBits - 1, random);
        BigInteger b = y.pow(2).subtract(x.pow(3)).subtract(a.multiply(x)).mod(prime);
        BigInteger order = BigInteger.ONE.shiftLeft(orderBits - 1).add(BigInteger.ONE);
        ECCurve curve = new ECCurve.Fp(prime, a, b, order, cofactor);
        return new X9ECParameters(curve, new X9ECPoint(curve.createPoint(x, y), false), order, cofactor);
    }
}
