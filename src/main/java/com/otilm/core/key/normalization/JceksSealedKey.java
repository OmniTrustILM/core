package com.otilm.core.key.normalization;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.JavaSerialization.Field;
import com.otilm.core.key.normalization.JavaSerialization.Span;
import com.otilm.core.key.normalization.JavaSerialization.StreamClass;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PBEParameter;

/**
 * A JCEKS secret key as the store seals it: parsed strictly, never deserialized.
 *
 * <p>
 * A JCEKS store keeps a secret key as a serialized {@code SealedObjectForKeyProtector}: the key object, serialized in
 * turn and encrypted with PBE-MD5-3DES under the store's passphrase. Both streams are read against exactly the classes
 * and fields the JDK writes. The sealed key is a {@code SecretKeySpec}, or a {@code KeyRep} of a secret key in raw
 * form.
 * </p>
 */
public final class JceksSealedKey {

    private static final String SEAL_ALGORITHM = "PBEWithMD5AndTripleDES";

    /** The length of the salt the JDK seals a key with. */
    private static final int SALT_BYTES = 8;

    private static final String STRING = "Ljava/lang/String;";

    private static final String BYTES = "[B";

    private static final StreamClass SEALED_OBJECT = new StreamClass("javax.crypto.SealedObject", 4482838265551344752L,
            JavaSerialization.SC_SERIALIZABLE,
            List
                    .of(new Field("encodedParams", BYTES), new Field("encryptedContent", BYTES),
                            new Field("paramsAlg", STRING), new Field("sealAlg", STRING)),
            null);

    private static final StreamClass SEALED_KEY = new StreamClass("com.sun.crypto.provider.SealedObjectForKeyProtector",
            -3650226485480866989L, JavaSerialization.SC_SERIALIZABLE, List.of(), SEALED_OBJECT);

    private static final StreamClass SECRET_KEY_SPEC = new StreamClass("javax.crypto.spec.SecretKeySpec",
            6577238317307289933L, JavaSerialization.SC_SERIALIZABLE,
            List.of(new Field("algorithm", STRING), new Field("key", BYTES)), null);

    private static final StreamClass ENUM = new StreamClass("java.lang.Enum", 0L,
            JavaSerialization.SC_SERIALIZABLE_ENUM, List.of(), null);

    private static final StreamClass KEY_REP_TYPE = new StreamClass("java.security.KeyRep$Type", 0L,
            JavaSerialization.SC_SERIALIZABLE_ENUM, List.of(), ENUM);

    private static final StreamClass KEY_REP = new StreamClass("java.security.KeyRep", -4757683898830641853L,
            JavaSerialization.SC_SERIALIZABLE,
            List
                    .of(new Field("algorithm", STRING), new Field("encoded", BYTES), new Field("format", STRING),
                            new Field("type", "Ljava/security/KeyRep$Type;")),
            null);

    private static final String RAW = "RAW";

    private static final String SECRET = "SECRET";

    private final byte[] salt;

    private final BigInteger iterations;

    private final byte[] encryptedContent;

    private final int encodedLength;

    private JceksSealedKey(byte[] salt, BigInteger iterations, byte[] encryptedContent, int encodedLength) {
        this.salt = salt;
        this.iterations = iterations;
        this.encryptedContent = encryptedContent;
        this.encodedLength = encodedLength;
    }

    /**
     * Reads the sealed key that starts at offset; refuses anything but the stream the JDK writes for it.
     *
     * @param data the bytes that hold the sealed key, such as a JCEKS store
     * @param offset where the sealed key starts
     * @return the sealed key
     */
    public static JceksSealedKey read(byte[] data, int offset) {
        JavaSerialization stream = JavaSerialization.at(data, offset);
        stream.object(SEALED_KEY);
        Span parameters = stream.byteArray();
        Span content = stream.byteArray();
        // the algorithm of the parameters, then the algorithm that sealed the key: the same scheme
        stream.string(SEAL_ALGORITHM);
        stream.string(SEAL_ALGORITHM);
        PBEParameter sealing = sealing(parameters.copyFrom(data));
        return new JceksSealedKey(sealing.getSalt(), sealing.getIterationCount(), content.copyFrom(data),
                stream.position() - offset);
    }

    /**
     * How many bytes of data the sealed key takes, so a store reader can continue after it.
     *
     * @return the length of the sealed key's stream
     */
    public int encodedLength() {
        return encodedLength;
    }

    /**
     * The iterations of the key derivation that opens the key, as the stream states them.
     *
     * @return the iterations
     */
    BigInteger iterations() {
        return iterations;
    }

    /**
     * The key the store sealed, opened with the passphrase: an AES key in its PKCS#8 form, or for another algorithm
     * only the name the store gives it. A missing or wrong passphrase and a damaged key read the same.
     *
     * @param passphrase the passphrase the store seals its keys under, which stays the caller's to clear
     * @return the key
     */
    OpenedKey open(Passphrase passphrase) {
        byte[] content = decrypted(passphrase);
        try {
            return opened(content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /** The key the decrypted stream holds, a {@code SecretKeySpec} or a {@code KeyRep} of a raw secret key. */
    private static OpenedKey opened(byte[] content) {
        JavaSerialization stream = JavaSerialization.at(content, 0);
        StreamClass form = stream.object(SECRET_KEY_SPEC, KEY_REP);
        String algorithm = stream.string();
        Span key = stream.byteArray();
        if (form.equals(KEY_REP)) {
            stream.string(RAW);
            if (!SECRET.equals(stream.enumConstant(KEY_REP_TYPE))) {
                throw KeyFileRefusal.unreadableKey();
            }
        }
        stream.requireEnd();
        if (!SecretKeys.AES.equalsIgnoreCase(algorithm)) {
            return new OpenedKey.UnsupportedSecret(algorithm);
        }
        return new OpenedKey.Pkcs8(SecretKeys.aesPrivateKeyInfo(key.copyFrom(content)));
    }

    /**
     * The sealing parameters, as the DER {@code PBEParameter} the JDK writes: an 8-byte salt and the iteration count.
     */
    private static PBEParameter sealing(byte[] encoded) {
        KeyFileReader.withinDepth(encoded);
        PBEParameter parameters;
        boolean asTheJdkWritesThem;
        try {
            parameters = PBEParameter.getInstance(ASN1Primitive.fromByteArray(encoded));
            asTheJdkWritesThem = parameters.getSalt().length == SALT_BYTES
                    && Arrays.equals(parameters.getEncoded(ASN1Encoding.DER), encoded);
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
        if (!asTheJdkWritesThem) {
            throw KeyFileRefusal.unreadableKey();
        }
        return parameters;
    }

    /**
     * The sealed content, decrypted with the JCEKS protection. A passphrase SunJCE refuses, such as one that is not
     * ASCII, makes the key unreadable.
     */
    private byte[] decrypted(Passphrase passphrase) {
        if (passphrase == null) {
            throw KeyFileRefusal.unreadableKey();
        }
        char[] characters = passphrase.characters();
        try {
            return JavaKeyStoreProtection
                    .decryptJceks(new PBEParameter(salt, iterations.intValueExact()), encryptedContent, characters);
        } catch (ArithmeticException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            Arrays.fill(characters, '\0');
        }
    }
}
