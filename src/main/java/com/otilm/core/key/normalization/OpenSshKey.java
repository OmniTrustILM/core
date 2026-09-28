package com.otilm.core.key.normalization;

import com.otilm.api.model.core.secret.Passphrase;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;

/**
 * Reads an {@code openssh-key-v1} private key. Core reads its header itself before any derivation, since Bouncy
 * Castle's decryption only checks that the bcrypt round count is positive, not that it stays within the platform's
 * ceiling. Bcrypt's own cost is bounded by that round count alone; it is never charged to the file's derivation budget.
 */
final class OpenSshKey {

    static final int MAXIMUM_BCRYPT_ROUNDS = 256;

    private static final byte[] MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    private static final String NONE = "none";

    private static final String BCRYPT = "bcrypt";

    private static final String BCRYPT_ROUNDS_LIMIT = "bcrypt rounds";

    /** The ciphers Bouncy Castle's {@code OpenSSHPrivateKeyUtil} decrypts. */
    private static final Set<String> ACCEPTED_CIPHERS = Set
            .of("aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "3des-cbc");

    private OpenSshKey() {
    }

    /**
     * The header of an {@code openssh-key-v1} blob: its cipher, KDF, bcrypt round count and key count, read before any
     * derivation. Refuses a cipher or KDF outside the accepted set, naming it, and a round count over the platform's
     * ceiling, compared as the unsigned value the wire format states; a round count of zero is damaged, not a limit. A
     * key count other than one is not a single key file.
     *
     * @param blob the decoded content of an {@code OPENSSH PRIVATE KEY} block
     * @return the header
     */
    static Header header(byte[] blob) {
        Cursor cursor = new Cursor(blob);
        cursor.magic();
        String cipher = cursor.string();
        String kdf = cursor.string();
        Cursor options = new Cursor(cursor.block());
        int keys = cursor.u32();
        int rounds = 0;
        if (NONE.equals(kdf)) {
            if (!NONE.equals(cipher)) {
                throw KeyFileRefusal.unsupportedProtection(cipher);
            }
        } else if (BCRYPT.equals(kdf)) {
            if (!ACCEPTED_CIPHERS.contains(cipher)) {
                throw KeyFileRefusal.unsupportedProtection(cipher);
            }
            options.block(); // salt, not needed to check the header
            long roundsUnsigned = Integer.toUnsignedLong(options.u32());
            if (roundsUnsigned > MAXIMUM_BCRYPT_ROUNDS) {
                throw KeyFileRefusal.limitExceeded(BCRYPT_ROUNDS_LIMIT, MAXIMUM_BCRYPT_ROUNDS);
            }
            if (roundsUnsigned == 0) {
                throw KeyFileRefusal.unreadableKey();
            }
            rounds = (int) roundsUnsigned;
        } else {
            throw KeyFileRefusal.unsupportedProtection(kdf);
        }
        if (keys != 1) {
            throw KeyFileRefusal.notAKeyFile();
        }
        return new Header(cipher, kdf, rounds, keys);
    }

    /**
     * Opens the key: Bouncy Castle decrypts the blob under the passphrase and Core turns the result into PKCS#8. A
     * failure here reads the same whatever its cause, so it never tells a right passphrase from a wrong one. The blob
     * is overwritten once used, since an unprotected key holds its plaintext directly.
     *
     * @param blob the decoded content of an {@code OPENSSH PRIVATE KEY} block, already checked by {@link #header}
     * @param passphrase the passphrase that opens the key, or {@code null} for a key without protection
     * @return the key as PKCS#8
     */
    static PrivateKeyInfo open(byte[] blob, Passphrase passphrase) {
        char[] characters = passphrase == null ? null : passphrase.characters();
        byte[] passphraseUtf8 = characters == null ? null : utf8(characters);
        try {
            AsymmetricKeyParameter parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob, passphraseUtf8);
            return PrivateKeyInfoFactory.createPrivateKeyInfo(parameters);
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            if (characters != null) {
                Arrays.fill(characters, '\0');
            }
            if (passphraseUtf8 != null) {
                Arrays.fill(passphraseUtf8, (byte) 0);
            }
            Arrays.fill(blob, (byte) 0);
        }
    }

    /** The UTF-8 bytes of the characters; the encoder's own buffer is overwritten once copied. */
    private static byte[] utf8(char[] characters) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(characters));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        Arrays.fill(encoded.array(), (byte) 0);
        return bytes;
    }

    /**
     * An {@code openssh-key-v1} blob's cipher, KDF, bcrypt round count and key count.
     *
     * @param cipher the cipher name
     * @param kdf the KDF name
     * @param rounds the bcrypt round count, 0 without bcrypt
     * @param keys the number of keys the blob states
     */
    record Header(String cipher, String kdf, int rounds, int keys) {

        /**
         * Whether the key has no protection at all, so opening it involves no derivation and no passphrase.
         *
         * @return {@code true} for kdf {@code none}
         */
        boolean unprotected() {
            return NONE.equals(kdf);
        }
    }

    /** A cursor over SSH wire-encoded fields: {@code string} is a {@code uint32} length followed by its bytes. */
    static final class Cursor {

        private final byte[] buffer;

        private int position;

        Cursor(byte[] buffer) {
            this.buffer = buffer;
        }

        void magic() {
            if (buffer.length < MAGIC.length || !Arrays.equals(buffer, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
                throw KeyFileRefusal.unreadableKey();
            }
            position = MAGIC.length;
        }

        int u32() {
            if (position > buffer.length - 4) {
                throw KeyFileRefusal.unreadableKey();
            }
            int value = ((buffer[position] & 0xFF) << 24) | ((buffer[position + 1] & 0xFF) << 16)
                    | ((buffer[position + 2] & 0xFF) << 8) | (buffer[position + 3] & 0xFF);
            position += 4;
            return value;
        }

        byte[] block() {
            int length = u32();
            if (length < 0 || length > buffer.length - position) {
                throw KeyFileRefusal.unreadableKey();
            }
            byte[] value = Arrays.copyOfRange(buffer, position, position + length);
            position += length;
            return value;
        }

        String string() {
            return new String(block(), StandardCharsets.US_ASCII);
        }
    }
}
