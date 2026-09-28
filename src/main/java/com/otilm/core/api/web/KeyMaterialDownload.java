package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.CertificateController;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** Renders protected key material as a download that neither a browser nor a proxy may cache or sniff. */
final class KeyMaterialDownload {

    private static final int MAX_FILE_NAME_LENGTH = 100;
    private static final String FALLBACK_FILE_NAME = "key";
    private static final Base64.Encoder PEM_BASE64 = Base64
            .getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));

    private KeyMaterialDownload() {
    }

    /**
     * The material as a PEM {@code ENCRYPTED PRIVATE KEY} file, as RFC 7468 describes, named after the key item.
     *
     * @param name name of the key item, sanitized into the file name
     * @param encryptedPrivateKeyInfo the DER-encoded PKCS#8 EncryptedPrivateKeyInfo
     * @return the download
     */
    static ResponseEntity<Resource> encryptedPrivateKeyPem(String name, byte[] encryptedPrivateKeyInfo) {
        String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + PEM_BASE64.encodeToString(encryptedPrivateKeyInfo)
                + "\n-----END ENCRYPTED PRIVATE KEY-----\n";
        return download(MediaType.APPLICATION_OCTET_STREAM, sanitizedFileName(name, "pem"),
                pem.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * A PKCS#12 keystore, named after the certificate.
     *
     * @param name the certificate's common name, sanitized into the file name
     * @param content the DER-encoded PKCS#12 file
     * @return the download
     */
    static ResponseEntity<Resource> pkcs12(String name, byte[] content) {
        return download(MediaType.parseMediaType(CertificateController.KEYSTORE_MEDIA_TYPE),
                sanitizedFileName(name, "p12"), content);
    }

    private static ResponseEntity<Resource> download(MediaType type, String fileName, byte[] content) {
        return ResponseEntity
                .ok()
                .contentType(type)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(fileName).build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .header("X-Content-Type-Options", "nosniff")
                .body(new ByteArrayResource(content));
    }

    /**
     * A file name that is safe on every system and in the header that carries it: ASCII letters, digits, {@code .},
     * {@code -} and {@code _} only, not starting with a dot, and at most 100 characters before the extension.
     *
     * @param name the name to derive the file name from; {@code key} when nothing usable is left of it
     * @param extension the file extension, without its dot
     * @return the file name
     */
    static String sanitizedFileName(String name, String extension) {
        StringBuilder safe = new StringBuilder();
        if (name != null) {
            name.codePoints().forEach(codePoint -> safe.append(isSafe(codePoint) ? (char) codePoint : '_'));
        }
        while (!safe.isEmpty() && safe.charAt(0) == '.') {
            safe.deleteCharAt(0);
        }
        safe.setLength(Math.min(safe.length(), MAX_FILE_NAME_LENGTH));
        return (safe.isEmpty() ? FALLBACK_FILE_NAME : safe) + "." + extension;
    }

    private static boolean isSafe(int codePoint) {
        return (codePoint >= 'a' && codePoint <= 'z') || (codePoint >= 'A' && codePoint <= 'Z')
                || (codePoint >= '0' && codePoint <= '9') || codePoint == '.' || codePoint == '-' || codePoint == '_';
    }
}
