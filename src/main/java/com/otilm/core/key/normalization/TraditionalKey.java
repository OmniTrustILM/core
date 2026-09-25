package com.otilm.core.key.normalization;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/** The keys OpenSSL writes as traditional PEM, each carried into PKCS#8 as Bouncy Castle's PEM parser converts it. */
enum TraditionalKey {

    RSA {
        @Override
        PrivateKeyInfo wrap(ASN1Primitive key) throws IOException {
            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                    RSAPrivateKey.getInstance(key));
        }
    },

    EC {
        @Override
        PrivateKeyInfo wrap(ASN1Primitive key) throws IOException {
            ECPrivateKey ecKey = ECPrivateKey.getInstance(key);
            return new PrivateKeyInfo(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecKey.getParametersObject()), ecKey);
        }
    };

    /**
     * The key as PKCS#8. Content that is not this kind of key makes the file damaged.
     *
     * @param der the DER-encoded {@code RSAPrivateKey} or {@code ECPrivateKey}
     * @return the key as a {@code PrivateKeyInfo}
     */
    PrivateKeyInfo privateKeyInfo(byte[] der) {
        try {
            return wrap(ASN1Primitive.fromByteArray(der));
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    abstract PrivateKeyInfo wrap(ASN1Primitive key) throws IOException;
}
