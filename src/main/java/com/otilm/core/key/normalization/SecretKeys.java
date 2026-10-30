package com.otilm.core.key.normalization;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Secret keys in the PKCS#8 shape the JDK gives them: a {@code PrivateKeyInfo} whose algorithm is the secret key's and
 * whose key octets are the raw key itself rather than a DER structure. This is also the plaintext the contract's
 * envelope takes for a secret key.
 *
 * <p>
 * AES keys of 128, 192 and 256 bits are the secret keys the platform holds. AES keys of other lengths, and DESede and
 * HMAC keys, are secret keys it does not hold.
 * </p>
 */
final class SecretKeys {

    /** The name the JDK gives the AES algorithm. */
    static final String AES = "AES";

    /** DESede as PKCS#5 names it, and as the JDK's PKCS#12 store names it. */
    private static final Set<ASN1ObjectIdentifier> DESEDE = Set
            .of(PKCSObjectIdentifiers.des_EDE3_CBC, OIWObjectIdentifiers.desEDE);

    /** The arc of the HMAC algorithms, among RSA's digest algorithms. */
    private static final ASN1ObjectIdentifier HMAC = PKCSObjectIdentifiers.digestAlgorithm;

    private static final Set<Integer> AES_KEY_BYTES = Set.of(16, 24, 32);

    private SecretKeys() {
    }

    /**
     * Whether the key is a secret key: its algorithm AES, DESede or an HMAC.
     *
     * @param privateKeyInfo the key in its PKCS#8 form
     * @return whether it is a secret key
     */
    static boolean isSecret(PrivateKeyInfo privateKeyInfo) {
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        return NISTObjectIdentifiers.aes.equals(algorithm) || DESEDE.contains(algorithm) || algorithm.on(HMAC);
    }

    /**
     * What a secret key is: an AES key of 128, 192 or 256 bits, or a key the platform does not support, named by its
     * algorithm. An AES key of another length, which a JDK store can hold, is one the platform does not support.
     *
     * @param privateKeyInfo a secret key in its PKCS#8 form
     * @return the key's description
     */
    static KeyDescription described(PrivateKeyInfo privateKeyInfo) {
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        int keyBytes = privateKeyInfo.getPrivateKey().getOctets().length;
        if (!NISTObjectIdentifiers.aes.equals(algorithm) || !AES_KEY_BYTES.contains(keyBytes)) {
            return KeyDescription.unsupported(algorithm.getId());
        }
        return new KeyDescription(KeyRequestType.SECRET, KeyAlgorithm.AES, keyBytes * Byte.SIZE, null, null);
    }

    /**
     * An AES key in the PKCS#8 shape, as the JDK's PKCS#12 store writes it. The key's bytes are taken as they are, so
     * overwriting the octets of the result overwrites them.
     *
     * @param key the raw key
     * @return the key in its PKCS#8 form
     */
    static PrivateKeyInfo aesPrivateKeyInfo(byte[] key) {
        return PrivateKeyInfo
                .getInstance(new DERSequence(new ASN1Encodable[]{
                        new ASN1Integer(0),
                        new AlgorithmIdentifier(NISTObjectIdentifiers.aes),
                        new DEROctetString(key)}));
    }
}
