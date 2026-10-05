package com.otilm.core.key.normalization;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Supplier;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * Content protected under an empty passphrase, decrypted as the writers of a file protected with an empty password
 * derive its key.
 *
 * <p>
 * PBES2 under PBKDF2 derives it from no bytes; Bouncy Castle's JCA provider refuses to derive a key from an empty
 * passphrase, so the key is derived here with its lightweight PBKDF2. A PKCS#12 scheme derives it from the password's
 * BMPString terminator alone, as OpenSSL and the JDK write it, where Bouncy Castle derives it from no bytes at all.
 * </p>
 */
public final class EmptyPassphrase {

    private EmptyPassphrase() {
    }

    /**
     * Whether the protection is PBES2 under PBKDF2, which an empty passphrase opens only here.
     *
     * @param protection the encryption algorithm of a protected key or of a PKCS#12 safe
     * @return whether {@link #decrypt(AlgorithmIdentifier, byte[])} takes it
     */
    public static boolean decrypts(AlgorithmIdentifier protection) {
        return PKCSObjectIdentifiers.id_PBES2.equals(protection.getAlgorithm()) && PKCSObjectIdentifiers.id_PBKDF2
                .equals(PBES2Parameters.getInstance(protection.getParameters()).getKeyDerivationFunc().getAlgorithm());
    }

    /**
     * The content decrypted under an empty passphrase. The protection is one the key protections accept, its derivation
     * already charged to the budget of the file it comes from.
     *
     * @param protection PBES2 under PBKDF2
     * @param encrypted the encrypted content
     * @return the plaintext, which the caller overwrites once used
     * @throws GeneralSecurityException when the content does not decrypt under an empty passphrase, or the protection
     * names a PRF or cipher no accepted protection names
     */
    public static byte[] decrypt(AlgorithmIdentifier protection, byte[] encrypted) throws GeneralSecurityException {
        PBES2Parameters parameters = PBES2Parameters.getInstance(protection.getParameters());
        PBKDF2Params pbkdf2 = PBKDF2Params.getInstance(parameters.getKeyDerivationFunc().getParameters());
        EncryptionScheme scheme = parameters.getEncryptionScheme();
        Supplier<Digest> prf = KeyProtection.PBKDF2_PRFS.get(pbkdf2.getPrf().getAlgorithm());
        KeyProtection.Pbes2Cipher cipher = KeyProtection.PBES2_CIPHERS.get(scheme.getAlgorithm());
        if (prf == null || cipher == null) {
            throw new NoSuchAlgorithmException("The protection names a PRF or cipher no key protection accepts.");
        }
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(prf.get());
        generator.init(new byte[0], pbkdf2.getSalt(), pbkdf2.getIterationCount().intValueExact());
        byte[] key = ((KeyParameter) generator.generateDerivedParameters(cipher.keyBytes() * Byte.SIZE)).getKey();
        try {
            Cipher decryption = Cipher
                    .getInstance(cipher.algorithm() + "/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
            decryption
                    .init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, cipher.algorithm()),
                            new IvParameterSpec(ASN1OctetString.getInstance(scheme.getParameters()).getOctets()));
            return decryption.doFinal(encrypted);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * The content under a PKCS#12 scheme decrypted with the key OpenSSL and the JDK derive from an empty password: from
     * its BMPString terminator alone. The derivation is charged to the budget of the file the content comes from before
     * this is called.
     *
     * @param protection one of the PKCS#12 schemes
     * @param encrypted the encrypted content
     * @return the plaintext, which the caller overwrites once used
     * @throws IOException when the content does not decrypt under the key so derived
     * @throws OperatorCreationException when the protection is no scheme Bouncy Castle decrypts
     */
    static byte[] decryptTerminated(AlgorithmIdentifier protection, byte[] encrypted)
            throws IOException, OperatorCreationException {
        InputDecryptor decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setTryWrongPKCS12Zero(true)
                .build(new char[0])
                .get(protection);
        try (InputStream decrypted = decryptor.getInputStream(new ByteArrayInputStream(encrypted))) {
            return Streams.readAll(decrypted);
        }
    }
}
