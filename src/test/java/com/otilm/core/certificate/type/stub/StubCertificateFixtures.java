package com.otilm.core.certificate.type.stub;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * Content in the format of {@link StubCertificateTypeHandler}: certificates are {@code STUB-CERT|id|holder|notBefore|
 * notAfter|key} with dates as {@code yyyy-MM-dd}, requests are {@code STUB-REQ|holder|key|signed|countersignedId}.
 */
public final class StubCertificateFixtures {

    public static final String STUB_NOT_BEFORE = "2026-01-01";
    public static final String STUB_NOT_AFTER = "2026-12-31";

    private static final KeyPair KEY_PAIR = generateKeyPair();

    private StubCertificateFixtures() {
    }

    public static KeyPair keyPair() {
        return KEY_PAIR;
    }

    public static byte[] certificate(String id, String holder) {
        return certificate(id, holder, STUB_NOT_BEFORE, STUB_NOT_AFTER);
    }

    public static byte[] certificate(String id, String holder, String notBefore, String notAfter) {
        return utf8("STUB-CERT|" + id + "|" + holder + "|" + notBefore + "|" + notAfter + "|" + encodedKey());
    }

    public static byte[] request(String holder, boolean signed, String countersignedId) {
        return utf8("STUB-REQ|" + holder + "|" + encodedKey() + "|" + signed + "|" + countersignedId);
    }

    private static String encodedKey() {
        return Base64.getEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded());
    }

    private static byte[] utf8(String content) {
        return content.getBytes(StandardCharsets.UTF_8);
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
