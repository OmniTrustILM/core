package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Reads what an uploaded key file holds from its structure alone, before any passphrase is used. A JCEKS sealed key is
 * read as the store seals it, a file holding PEM blocks as PEM, and any other file as DER; either way it must hold
 * exactly one key, and nothing besides the curve OpenSSL writes before an EC key. A secret key must be protected.
 */
final class KeyFileReader {

    private static final String NESTING_LIMIT = "nesting depth";

    private static final String PROC_TYPE = "Proc-Type";

    private static final String ENCRYPTED = "4,ENCRYPTED";

    private static final String DEK_INFO = "DEK-Info";

    /** The curve {@code openssl ecparam -genkey} writes before the key; the key states its curve itself. */
    private static final String EC_PARAMETERS = "EC PARAMETERS";

    private static final byte[] BYTE_ORDER_MARK = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private KeyFileReader() {
    }

    /**
     * What the file holds. A protected key is returned only when its protection is one the platform accepts. The key
     * derivation of a PKCS#8 protection or a JCEKS sealed key is charged to the file's budget first; a traditional PEM
     * key and a JKS key are derived at a fixed cost, and an OpenSSH key's bcrypt derivation is bounded by its rounds,
     * none of which is charged.
     *
     * @param file the uploaded file
     * @param budget the budget of the file, charged the derivation of a PKCS#8 protection or a JCEKS sealed key
     * @return the key the file holds, with or without protection
     */
    static KeyFile read(byte[] file, DerivationBudget budget) {
        if (JavaSerialization.startsStream(file)) {
            return sealed(file, budget);
        }
        List<PemObject> blocks = pemBlocks(file);
        blocks.removeIf(block -> EC_PARAMETERS.equals(block.getType()));
        if (blocks.isEmpty()) {
            return fromDer(file, budget);
        }
        if (blocks.size() > 1) {
            throw KeyFileRefusal.notAKeyFile();
        }
        return fromPem(blocks.getFirst(), budget);
    }

    /**
     * The structure DER bytes hold, read as the given type, after which the bytes are overwritten, since they may hold
     * a key. Bytes Bouncy Castle cannot read that way make the file damaged; it signals that with a range of unchecked
     * exceptions, each meaning the same here.
     *
     * @param der the DER bytes
     * @param reader reads the structure as the expected type
     * @return the structure
     */
    static <T> T parse(byte[] der, Function<Object, T> reader) {
        T parsed;
        try {
            parsed = reader.apply(ASN1Primitive.fromByteArray(der));
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            Arrays.fill(der, (byte) 0);
        }
        if (parsed == null) {
            throw KeyFileRefusal.unreadableKey();
        }
        return parsed;
    }

    /**
     * The PEM blocks in the file, none for a binary one; a block that is not base64 makes the file damaged. A byte
     * order mark, which editors on Windows put at the start of a text file, is not part of the PEM.
     */
    private static List<PemObject> pemBlocks(byte[] file) {
        int start = startsWithByteOrderMark(file) ? BYTE_ORDER_MARK.length : 0;
        List<PemObject> blocks = new ArrayList<>();
        try (PemReader reader = new PemReader(new InputStreamReader(
                new ByteArrayInputStream(file, start, file.length - start), StandardCharsets.US_ASCII))) {
            for (PemObject block = reader.readPemObject(); block != null; block = reader.readPemObject()) {
                blocks.add(block);
            }
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
        return blocks;
    }

    private static boolean startsWithByteOrderMark(byte[] file) {
        return file.length >= BYTE_ORDER_MARK.length
                && Arrays.equals(file, 0, BYTE_ORDER_MARK.length, BYTE_ORDER_MARK, 0, BYTE_ORDER_MARK.length);
    }

    private static KeyFile fromPem(PemObject block, DerivationBudget budget) {
        return switch (block.getType()) {
            case "PRIVATE KEY" -> plain(parse(withinDepth(block.getContent()), PrivateKeyInfo::getInstance));
            case "ENCRYPTED PRIVATE KEY" ->
                protectedPkcs8(parse(withinDepth(block.getContent()), EncryptedPrivateKeyInfo::getInstance), budget);
            case "RSA PRIVATE KEY" -> traditional(TraditionalKey.RSA, block);
            case "EC PRIVATE KEY" -> traditional(TraditionalKey.EC, block);
            case "OPENSSH PRIVATE KEY" -> openSsh(block.getContent());
            default -> throw KeyFileRefusal.notAKeyFile();
        };
    }

    /**
     * A DER file is a PKCS#8 key, with or without protection; the two are told apart by their structure, since a
     * {@code PrivateKeyInfo} starts with its version and an {@code EncryptedPrivateKeyInfo} with its algorithm.
     */
    private static KeyFile fromDer(byte[] file, DerivationBudget budget) {
        byte[] der = withinDepth(file);
        ASN1Primitive structure;
        try {
            structure = ASN1Primitive.fromByteArray(der);
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.notAKeyFile();
        }
        PrivateKeyInfo privateKeyInfo = attempt(structure, PrivateKeyInfo::getInstance);
        if (privateKeyInfo != null) {
            return plain(privateKeyInfo);
        }
        EncryptedPrivateKeyInfo envelope = attempt(structure, EncryptedPrivateKeyInfo::getInstance);
        if (envelope != null) {
            return protectedPkcs8(envelope, budget);
        }
        throw KeyFileRefusal.notAKeyFile();
    }

    /**
     * A PKCS#8 key without protection. A secret key without protection is refused, since a digest of the file would be
     * an unkeyed digest of the secret; the copy of the key the structure holds is overwritten first.
     */
    private static KeyFile plain(PrivateKeyInfo privateKeyInfo) {
        if (SecretKeys.isSecret(privateKeyInfo)) {
            Arrays.fill(privateKeyInfo.getPrivateKey().getOctets(), (byte) 0);
            throw KeyFileRefusal.unprotectedSecret();
        }
        return new KeyFile.Plain(privateKeyInfo);
    }

    /** A JCEKS sealed key that makes up the whole file, once its key derivation is charged to the file's budget. */
    private static KeyFile sealed(byte[] file, DerivationBudget budget) {
        JceksSealedKey sealed = JceksSealedKey.read(file, 0);
        if (sealed.encodedLength() != file.length) {
            throw KeyFileRefusal.unreadableKey();
        }
        budget.charge(sealed.iterations());
        return new KeyFile.JceksSealed(sealed);
    }

    private static KeyFile protectedPkcs8(EncryptedPrivateKeyInfo envelope, DerivationBudget budget) {
        KeyProtection.requireAccepted(envelope.getEncryptionAlgorithm(), budget);
        return new KeyFile.Pkcs8Protected(envelope);
    }

    /**
     * A traditional block is protected when its {@code Proc-Type} header says so, with the cipher and initialization
     * vector in its {@code DEK-Info} header.
     */
    private static KeyFile traditional(TraditionalKey kind, PemObject block) {
        Map<String, String> headers = headers(block);
        String procType = headers.get(PROC_TYPE);
        if (procType == null) {
            return new KeyFile.Plain(kind.privateKeyInfo(withinDepth(block.getContent())));
        }
        String dekInfo = headers.getOrDefault(DEK_INFO, "");
        int comma = dekInfo.indexOf(',');
        if (!ENCRYPTED.equals(procType) || comma < 0) {
            throw KeyFileRefusal.unreadableKey();
        }
        String cipher = dekInfo.substring(0, comma).trim();
        KeyProtection.requireAcceptedCipher(cipher);
        return new KeyFile.TraditionalProtected(kind, cipher, iv(dekInfo.substring(comma + 1).trim()),
                block.getContent());
    }

    /**
     * An OpenSSH key, its header checked for an accepted cipher, KDF and key count first; a refusal overwrites the
     * blob, since it may hold the plaintext key directly. A key without protection is opened right away, since no
     * passphrase is involved, so its own refusals read as themselves rather than as the passphrase refusal every
     * protected key shares.
     */
    private static KeyFile openSsh(byte[] blob) {
        OpenSshKey.Header header;
        try {
            header = OpenSshKey.header(blob);
        } catch (ValidationException refusal) {
            Arrays.fill(blob, (byte) 0);
            throw refusal;
        }
        return header.unprotected() ? new KeyFile.Plain(OpenSshKey.open(blob, null)) : new KeyFile.OpenSsh(blob);
    }

    private static Map<String, String> headers(PemObject block) {
        Map<String, String> headers = new HashMap<>();
        for (Object header : block.getHeaders()) {
            PemHeader pemHeader = (PemHeader) header;
            headers.put(pemHeader.getName(), pemHeader.getValue());
        }
        return headers;
    }

    private static byte[] iv(String hex) {
        try {
            return Hex.decode(hex);
        } catch (RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * The bytes, refused when they nest deeper than a key file may.
     *
     * @param der DER bytes from the file
     * @return the same bytes
     */
    static byte[] withinDepth(byte[] der) {
        if (!NestingDepth.within(der, KeyNormalizer.MAXIMUM_NESTING_DEPTH)) {
            throw KeyFileRefusal.limitExceeded(NESTING_LIMIT, KeyNormalizer.MAXIMUM_NESTING_DEPTH);
        }
        return der;
    }

    /** The structure read as the given type, or {@code null} when it is not one. */
    private static <T> T attempt(ASN1Primitive structure, Function<Object, T> reader) {
        try {
            return reader.apply(structure);
        } catch (RuntimeException e) {
            return null;
        }
    }
}
