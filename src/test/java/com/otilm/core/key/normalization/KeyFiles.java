package com.otilm.core.key.normalization;

import com.otilm.api.model.core.secret.Passphrase;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/** Key files made in the tests, in the forms the normalizer takes and the ones it refuses. */
final class KeyFiles {

    static final char[] PASSPHRASE = "correct horse battery".toCharArray();

    /** Few iterations, so that a test file opens fast; the ceilings are tested with parameters alone. */
    static final int ITERATIONS = 2048;

    private KeyFiles() {
    }

    /** The providers the normalizer names, which the application registers when it starts. */
    static void registerProviders() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    static KeyPair rsa() throws GeneralSecurityException {
        return keyPair("RSA", new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4),
                BouncyCastleProvider.PROVIDER_NAME);
    }

    static KeyPair ec() throws GeneralSecurityException {
        return keyPair("EC", new ECGenParameterSpec("secp256r1"), BouncyCastleProvider.PROVIDER_NAME);
    }

    static KeyPair keyPair(String algorithm, AlgorithmParameterSpec parameters, String provider)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, provider);
        if (parameters != null) {
            generator.initialize(parameters);
        }
        return generator.generateKeyPair();
    }

    static Passphrase passphrase() {
        return new Passphrase(PASSPHRASE);
    }

    /** The key as DER PKCS#8, without protection. */
    static byte[] pkcs8(KeyPair keyPair) {
        return keyPair.getPrivate().getEncoded();
    }

    static byte[] pem(String type, byte[] content) throws IOException {
        return pem(new PemObject(type, content));
    }

    static byte[] pem(String type, List<PemHeader> headers, byte[] content) throws IOException {
        return pem(new PemObject(type, headers, content));
    }

    /** The key under PBES2 or a PKCS#12 scheme, as Bouncy Castle writes it; {@code prf} null for a PKCS#12 scheme. */
    static byte[] encrypted(KeyPair keyPair, ASN1ObjectIdentifier scheme, AlgorithmIdentifier prf) throws Exception {
        return encrypted(keyPair, scheme, prf, PASSPHRASE);
    }

    static byte[] encrypted(KeyPair keyPair, ASN1ObjectIdentifier scheme, AlgorithmIdentifier prf, char[] passphrase)
            throws Exception {
        JceOpenSSLPKCS8EncryptorBuilder builder = new JceOpenSSLPKCS8EncryptorBuilder(scheme)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setIterationCount(ITERATIONS)
                .setPassword(passphrase);
        if (prf != null) {
            builder.setPRF(prf);
        }
        return envelope(keyPair, builder.build());
    }

    /** The key under PBES2 with scrypt as the key derivation. */
    static byte[] scrypt(KeyPair keyPair) throws Exception {
        return envelope(keyPair,
                new JcePKCSPBEOutputEncryptorBuilder(new ScryptConfig.Builder(16_384, 8, 1).withSaltLength(16).build(),
                        NISTObjectIdentifiers.id_aes256_CBC)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(PASSPHRASE));
    }

    /** The key under PKCS#5 v1.5 (PBES1), assembled by hand since Bouncy Castle writes no such envelope. */
    static byte[] pbes1(KeyPair keyPair, String cipher, ASN1ObjectIdentifier scheme) throws Exception {
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        Cipher encryption = Cipher.getInstance(cipher, BouncyCastleProvider.PROVIDER_NAME);
        encryption
                .init(Cipher.ENCRYPT_MODE,
                        SecretKeyFactory
                                .getInstance(cipher, BouncyCastleProvider.PROVIDER_NAME)
                                .generateSecret(new PBEKeySpec(PASSPHRASE)),
                        new PBEParameterSpec(salt, ITERATIONS));
        return envelope(new AlgorithmIdentifier(scheme, new PBEParameter(salt, ITERATIONS)),
                encryption.doFinal(pkcs8(keyPair)));
    }

    /**
     * The key under PBES1 with MD5 and DES as OpenSSL writes it, derived here without Bouncy Castle: PBKDF1 over the
     * passphrase's UTF-8 bytes, the first half of the result the DES key and the second half the initialization vector.
     */
    static byte[] opensslPbes1(KeyPair keyPair, char[] passphrase) throws Exception {
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(new String(passphrase).getBytes(StandardCharsets.UTF_8));
        md5.update(salt);
        byte[] derived = md5.digest();
        for (int round = 1; round < ITERATIONS; round++) {
            derived = md5.digest(derived);
        }
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
        des
                .init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOfRange(derived, 0, 8), "DES"),
                        new IvParameterSpec(Arrays.copyOfRange(derived, 8, 16)));
        return envelope(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, new PBEParameter(salt, ITERATIONS)),
                des.doFinal(pkcs8(keyPair)));
    }

    /** The key as OpenSSL traditional PEM under the cipher, or without protection when {@code cipher} is null. */
    static byte[] traditional(KeyPair keyPair, String cipher) throws Exception {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer
                    .writeObject(cipher == null
                            ? new JcaMiscPEMGenerator(keyPair.getPrivate())
                            : new JcaMiscPEMGenerator(keyPair.getPrivate(),
                                    new JcePEMEncryptorBuilder(cipher)
                                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                            .build(PASSPHRASE)));
        }
        return pem.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** An envelope stating the protection over the ciphertext, for protection nothing is meant to decrypt. */
    static byte[] envelope(AlgorithmIdentifier protection, byte[] cipherText) throws IOException {
        return new EncryptedPrivateKeyInfo(protection, cipherText).getEncoded(ASN1Encoding.DER);
    }

    /** Content encrypted under PBES2 as though it were a key. */
    static byte[] encryptedContent(byte[] content) throws Exception {
        OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setPRF(PKCS8Generator.PRF_HMACSHA256)
                .setIterationCount(ITERATIONS)
                .setPassword(PASSPHRASE)
                .build();
        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
        try (OutputStream out = encryptor.getOutputStream(cipherText)) {
            out.write(content);
        }
        return envelope(encryptor.getAlgorithmIdentifier(), cipherText.toByteArray());
    }

    /** A PKCS#8 structure stating the algorithm over any private-key payload. */
    static PrivateKeyInfo privateKeyInfo(AlgorithmIdentifier algorithm, byte[] payload) {
        return PrivateKeyInfo
                .getInstance(new DERSequence(
                        new ASN1Encodable[]{new ASN1Integer(0), algorithm, new DEROctetString(payload)}));
    }

    /** Constructed values nested {@code depth} deep. */
    static byte[] nested(int depth) throws IOException {
        ASN1Encodable value = DERNull.INSTANCE;
        for (int level = 0; level < depth; level++) {
            value = new DERSequence(value);
        }
        return value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    /** The key a normalized envelope holds, opened with its transport passphrase. */
    static byte[] opened(NormalizedKey key) throws Exception {
        return new PKCS8EncryptedPrivateKeyInfo(key.encryptedPrivateKeyInfo())
                .decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(key.transportPassphrase().characters()))
                .getEncoded();
    }

    private static byte[] envelope(KeyPair keyPair, OutputEncryptor encryptor) throws IOException {
        return new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(pkcs8(keyPair)))
                .build(encryptor)
                .getEncoded();
    }

    private static byte[] pem(PemObject block) throws IOException {
        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(block);
        }
        return pem.toString().getBytes(StandardCharsets.US_ASCII);
    }
}
