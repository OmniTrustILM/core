package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.JceksSealedKey;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * A JKS or JCEKS store, read by its layout as the JDK writes it, never by the JDK's {@code KeyStore} or by Java
 * deserialization.
 *
 * <p>
 * The layout is big-endian: the magic number, the version, the number of entries, the entries, and a SHA-1 digest of
 * the passphrase, a fixed phrase and everything before the digest. A private-key entry holds its alias, its date, its
 * protected key and its certificate chain; a trusted-certificate entry its alias, its date and its certificate; and a
 * secret-key entry, which only a JCEKS store holds, its alias, its date and its sealed key. A version 2 store states
 * the type of each certificate, which must be X.509. Every length is checked against what is left before the digest,
 * and each key and certificate is counted against the limits before it is read.
 * </p>
 *
 * <p>
 * A store's entries are handed on only once its digest shows the passphrase is the store's, so a store is always read
 * as verified: a key the passphrase then does not open has a passphrase of its own, which tells such a store apart from
 * a wrong passphrase. The keys are handed on as the store holds them, a private key as its protected
 * {@code EncryptedPrivateKeyInfo} and a secret key as its sealed key; only the key normalizer opens them.
 * </p>
 */
@Component
@Order(20)
class JavaKeyStoreFormat implements ContainerFormat {

    private static final int JCEKS_MAGIC = 0xCECECECE;

    private static final int FIRST_VERSION = 1;

    /** The version the JDK writes, which states the type of each certificate. */
    private static final int TYPED_VERSION = 2;

    private static final int PRIVATE_KEY_TAG = 1;

    private static final int TRUSTED_CERTIFICATE_TAG = 2;

    private static final int SECRET_KEY_TAG = 3;

    private static final String X509 = "X.509";

    private static final int DIGEST_LENGTH = 20;

    /** What the JDK digests between the passphrase and the store. */
    private static final byte[] DIGEST_PHRASE = "Mighty Aphrodite".getBytes(StandardCharsets.UTF_8);

    @Override
    public boolean recognizes(byte[] file) {
        return KeystoreDetection.isJavaKeyStore(file);
    }

    @Override
    public Contents read(byte[] file, Passphrase passphrase, DerivationBudget budget) {
        List<RawItem> items = new ArrayList<>();
        try {
            int digest = new Layout(file).entries(items);
            if (!digestMatches(file, digest, passphrase)) {
                throw ContainerRefusal.integrityFailed();
            }
            return new Contents(items, true);
        } catch (RuntimeException refusal) {
            RawItem.overwriteKeys(items);
            throw refusal;
        }
    }

    /**
     * Whether the digest the store ends with is the one the passphrase gives: SHA-1 over the passphrase, each character
     * as two bytes with the high byte first, the phrase the JDK adds, and everything before the digest.
     */
    private static boolean digestMatches(byte[] file, int digest, Passphrase passphrase) {
        MessageDigest sha1 = sha1();
        char[] characters = passphrase.characters();
        try {
            for (char character : characters) {
                sha1.update((byte) (character >> Byte.SIZE));
                sha1.update((byte) character);
            }
        } finally {
            Arrays.fill(characters, '\0');
        }
        sha1.update(DIGEST_PHRASE);
        sha1.update(file, 0, digest);
        return MessageDigest.isEqual(sha1.digest(), Arrays.copyOfRange(file, digest, file.length));
    }

    // S4790: the JKS and JCEKS formats define their integrity digest over SHA-1.
    @SuppressWarnings("java:S4790")
    private static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is not available.", e);
        }
    }

    /**
     * The entries of one store, read in turn from its start up to the digest that ends it, with the keys and
     * certificates counted as they come.
     */
    private static final class Layout {

        private final byte[] file;

        private final ByteBuffer numbers;

        /** Where the entries end and the digest starts. */
        private final int end;

        private int position;

        private int keys;

        private int certificates;

        Layout(byte[] file) {
            this.file = file;
            this.numbers = ByteBuffer.wrap(file);
            this.end = file.length - DIGEST_LENGTH;
        }

        /**
         * Reads the store's entries into the items, in file order. They must fill the store up to its digest.
         *
         * @return where the digest starts
         */
        int entries(List<RawItem> items) {
            boolean jceks = integer() == JCEKS_MAGIC;
            boolean typed = version() == TYPED_VERSION;
            int count = count();
            for (int index = 0; index < count; index++) {
                entry(items, jceks, typed);
            }
            if (position != end) {
                throw ContainerRefusal.notSupportedFormat();
            }
            return end;
        }

        /** The version, which must be one the JDK writes. */
        private int version() {
            int version = integer();
            if (version != FIRST_VERSION && version != TYPED_VERSION) {
                throw ContainerRefusal.notSupportedFormat();
            }
            return version;
        }

        /** One entry, of the kind its tag tells; a secret key only in a JCEKS store. */
        private void entry(List<RawItem> items, boolean jceks, boolean typed) {
            int tag = integer();
            if (tag == PRIVATE_KEY_TAG) {
                privateKey(items, typed);
            } else if (tag == TRUSTED_CERTIFICATE_TAG) {
                countCertificate();
                String alias = aliasAndDate();
                items.add(certificate(alias, typed));
            } else if (tag == SECRET_KEY_TAG && jceks) {
                secretKey(items);
            } else {
                throw ContainerRefusal.entryUnsupported(Integer.toString(tag));
            }
        }

        /** A private key, as the protected {@code EncryptedPrivateKeyInfo} the store holds, and then its chain. */
        private void privateKey(List<RawItem> items, boolean typed) {
            countKey();
            String alias = aliasAndDate();
            items.add(new RawItem.Key(bytes(), alias, null, false));
            int chain = count();
            for (int index = 0; index < chain; index++) {
                countCertificate();
                items.add(certificate(null, typed));
            }
        }

        /** A secret key, as the sealed key the store holds. */
        private void secretKey(List<RawItem> items) {
            countKey();
            String alias = aliasAndDate();
            int length = sealedKeyLength();
            items.add(new RawItem.Key(Arrays.copyOfRange(file, position, position + length), alias, null, true));
            position += length;
        }

        /**
         * How long the sealed key that starts here is: a serialization stream, whose end its strict reader finds. A
         * stream the reader refuses, such as one cut short, is a layout the JDK does not write.
         */
        private int sealedKeyLength() {
            try {
                return JceksSealedKey.read(file, position).encodedLength();
            } catch (ValidationException refusal) {
                throw ContainerRefusal.notSupportedFormat();
            }
        }

        /** A certificate, after the type a version 2 store states for it. */
        private RawItem certificate(String alias, boolean typed) {
            if (typed) {
                String type = utf();
                if (!X509.equals(type)) {
                    throw ContainerRefusal.entryUnsupported(type);
                }
            }
            return new RawItem.Certificate(bytes(), alias, null);
        }

        /** The entry's alias, after which its date is passed over. */
        private String aliasAndDate() {
            String alias = utf();
            skip(Long.BYTES);
            return alias;
        }

        private void countKey() {
            keys++;
            ContainerLimits.requireOtherEntriesWithin(keys);
        }

        private void countCertificate() {
            certificates++;
            ContainerLimits.requireCertificatesWithin(certificates);
        }

        /** The bytes a length states, after the length. */
        private byte[] bytes() {
            int length = count();
            require(length);
            byte[] bytes = Arrays.copyOfRange(file, position, position + length);
            position += length;
            return bytes;
        }

        /** A string in modified UTF-8 after its length, as {@code DataOutputStream.writeUTF} writes it. */
        private String utf() {
            require(Short.BYTES);
            int length = Short.BYTES + Short.toUnsignedInt(numbers.getShort(position));
            require(length);
            try (DataInputStream string = new DataInputStream(new ByteArrayInputStream(file, position, length))) {
                String value = string.readUTF();
                position += length;
                return value;
            } catch (IOException e) {
                throw ContainerRefusal.notSupportedFormat();
            }
        }

        /** A count or a length, which is never below zero. */
        private int count() {
            int count = integer();
            if (count < 0) {
                throw ContainerRefusal.notSupportedFormat();
            }
            return count;
        }

        private int integer() {
            require(Integer.BYTES);
            int value = numbers.getInt(position);
            position += Integer.BYTES;
            return value;
        }

        private void skip(int length) {
            require(length);
            position += length;
        }

        /** Refuses the store when fewer bytes are left before the digest than the next value takes. */
        private void require(int length) {
            if (length > end - position) {
                throw ContainerRefusal.notSupportedFormat();
            }
        }
    }
}
