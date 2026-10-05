package com.otilm.core.container;

import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.key.normalization.NestingDepth;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.pkcs.Pfx;

/** Tells a keystore from any other file by its content, never its name. */
public final class KeystoreDetection {

    private static final byte[] JKS_MAGIC = {(byte) 0xFE, (byte) 0xED, (byte) 0xFE, (byte) 0xED};

    private static final byte[] JCEKS_MAGIC = {(byte) 0xCE, (byte) 0xCE, (byte) 0xCE, (byte) 0xCE};

    private static final int PFX_VERSION = 3;

    private KeystoreDetection() {
    }

    /**
     * Whether the file is a JKS or JCEKS store.
     *
     * @param file the uploaded file
     * @return whether the file starts with the magic number of either store
     */
    public static boolean isJavaKeyStore(byte[] file) {
        return startsWith(file, JKS_MAGIC) || startsWith(file, JCEKS_MAGIC);
    }

    /**
     * Whether the file is a PKCS#12 store.
     *
     * @param file the uploaded file
     * @return whether the file parses as a PFX of version 3 within the nesting limit
     */
    public static boolean isPkcs12(byte[] file) {
        if (!statesPfxVersion(file) || !NestingDepth.within(file, KeyNormalizer.MAXIMUM_NESTING_DEPTH)) {
            return false;
        }
        try {
            return Pfx.getInstance(ASN1Primitive.fromByteArray(file)) != null;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Whether the file is a PKCS#12, JKS or JCEKS store.
     *
     * @param file the uploaded file
     * @return whether the file is any of the keystores
     */
    public static boolean isKeystore(byte[] file) {
        return isJavaKeyStore(file) || isPkcs12(file);
    }

    private static boolean startsWith(byte[] file, byte[] magic) {
        return file.length >= magic.length && Arrays.equals(file, 0, magic.length, magic, 0, magic.length);
    }

    /**
     * Whether the file opens with a structure whose first value is the PFX version, read without parsing the rest, so
     * that no other file, such as a key, is parsed whole only to be told apart.
     */
    private static boolean statesPfxVersion(byte[] file) {
        try {
            return new ASN1StreamParser(file).readObject() instanceof ASN1SequenceParser sequence
                    && sequence.readObject() instanceof ASN1Integer version && version.hasValue(PFX_VERSION);
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }
}
