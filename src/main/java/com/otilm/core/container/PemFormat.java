package com.otilm.core.container;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * PEM text: the certificates, PKCS#7 bundles and certificate requests its blocks hold, and at most one private key.
 * Text around the blocks, such as the attributes OpenSSL writes before each, is left aside.
 *
 * <p>
 * A key block is kept whole, headers included, so that the normalizer reads it as a file of its own.
 * </p>
 */
@Component
@Order(30)
class PemFormat implements ContainerFormat {

    private static final byte[] BYTE_ORDER_MARK = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private static final byte[] BEGIN = "-----BEGIN ".getBytes(StandardCharsets.US_ASCII);

    private static final Set<String> KEYS = Set
            .of("PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY");

    /** The curve {@code openssl ecparam -genkey} writes before the key; the key states its curve itself. */
    private static final String EC_PARAMETERS = "EC PARAMETERS";

    @Override
    public boolean recognizes(byte[] file) {
        return armored(file);
    }

    /** PEM text has no integrity check, so the passphrase never verifies it. */
    @Override
    public Contents read(byte[] file, Passphrase passphrase, DerivationBudget budget) {
        List<PemObject> blocks = blocks(file);
        List<RawItem> items = new ArrayList<>();
        try {
            if (blocks.stream().filter(block -> KEYS.contains(block.getType())).count() > 1) {
                throw ContainerRefusal.pemTooManyKeys();
            }
            for (PemObject block : blocks) {
                items.addAll(items(block));
            }
            return new Contents(items, false);
        } catch (RuntimeException refusal) {
            RawItem.overwriteKeys(items);
            throw refusal;
        } finally {
            overwrite(blocks);
        }
    }

    /**
     * The content of the PEM block a key is kept as, which references a key that has no public key to take.
     *
     * @param keyFile a key kept as PEM, which {@link #armored(byte[])} tells
     * @return the decoded block, a copy the caller overwrites
     */
    static byte[] blockContent(byte[] keyFile) {
        return blocks(keyFile).getFirst().getContent();
    }

    /**
     * Whether a line of the text, after any byte order mark, starts a PEM block.
     *
     * @param file an uploaded file, or a key as a format keeps it
     * @return whether the file is PEM
     */
    static boolean armored(byte[] file) {
        return beginLines(file) > 0;
    }

    /** How many lines of the text, after any byte order mark, start a PEM block. */
    private static int beginLines(byte[] file) {
        int start = textStart(file);
        int count = 0;
        for (int position = start; position <= file.length - BEGIN.length; position++) {
            boolean lineStart = position == start || file[position - 1] == '\n' || file[position - 1] == '\r';
            if (lineStart && Arrays.equals(file, position, position + BEGIN.length, BEGIN, 0, BEGIN.length)) {
                count++;
            }
        }
        return count;
    }

    /**
     * The PEM blocks of the file, at least one. A byte order mark, which editors on Windows put at the start of a text
     * file, is not part of the PEM. Blocks that cannot be read make the file one of no supported format, and so does a
     * line starting a block that the reader stopped at, since the blocks after it would go unread.
     */
    private static List<PemObject> blocks(byte[] file) {
        int start = textStart(file);
        List<PemObject> blocks = new ArrayList<>();
        try (PemReader reader = new PemReader(new InputStreamReader(
                new ByteArrayInputStream(file, start, file.length - start), StandardCharsets.US_ASCII))) {
            for (PemObject block = reader.readPemObject(); block != null; block = reader.readPemObject()) {
                blocks.add(block);
            }
        } catch (IOException | RuntimeException e) {
            overwrite(blocks);
            throw ContainerRefusal.notSupportedFormat();
        }
        if (blocks.isEmpty() || blocks.size() < beginLines(file)) {
            overwrite(blocks);
            throw ContainerRefusal.notSupportedFormat();
        }
        return blocks;
    }

    private static int textStart(byte[] file) {
        boolean marked = file.length >= BYTE_ORDER_MARK.length
                && Arrays.equals(file, 0, BYTE_ORDER_MARK.length, BYTE_ORDER_MARK, 0, BYTE_ORDER_MARK.length);
        return marked ? BYTE_ORDER_MARK.length : 0;
    }

    private static List<RawItem> items(PemObject block) {
        if (KEYS.contains(block.getType())) {
            return List.of(new RawItem.Key(standalone(block), null, null, false));
        }
        byte[] content = block.getContent();
        return switch (block.getType()) {
            case "CERTIFICATE", "X509 CERTIFICATE" -> List.of(new RawItem.Certificate(content.clone(), null, null));
            case "TRUSTED CERTIFICATE" -> List.of(new RawItem.Certificate(trustedCertificate(content), null, null));
            case "PKCS7", "CMS" -> DerFormat.signedDataCertificates(content);
            case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST" ->
                List.of(new RawItem.SigningRequest(content.clone()));
            case EC_PARAMETERS -> List.of();
            default -> throw ContainerRefusal.pemBlockUnsupported(block.getType());
        };
    }

    /** The key block as a PEM file of its own, headers included. */
    private static byte[] standalone(PemObject block) {
        StringWriter text = new StringWriter();
        try (PemWriter writer = new PemWriter(text)) {
            writer.writeObject(block);
        } catch (IOException e) {
            throw new IllegalStateException("A key block could not be written.", e);
        }
        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** The certificate of an OpenSSL trusted certificate, without the trust settings that follow it. */
    private static byte[] trustedCertificate(byte[] content) {
        ContainerLimits.requireNestingWithin(content);
        ASN1Primitive certificate;
        try (ASN1InputStream input = new ASN1InputStream(content)) {
            certificate = input.readObject();
        } catch (IOException | RuntimeException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
        if (certificate == null) {
            throw ContainerRefusal.notSupportedFormat();
        }
        return DerFormat.encoded(certificate);
    }

    /** Overwrites the decoded content of every block, which for a key block is the key; the items keep copies. */
    private static void overwrite(List<PemObject> blocks) {
        for (PemObject block : blocks) {
            Arrays.fill(block.getContent(), (byte) 0);
        }
    }
}
