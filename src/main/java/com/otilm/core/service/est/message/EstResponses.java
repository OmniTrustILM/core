package com.otilm.core.service.est.message;

import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.core.key.normalization.Pkcs8Envelopes;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * Renders the responses of an EST server. A success body is the base64 text of a DER structure (RFC 7030 section 4), in
 * lines of 64 characters that each end with CRLF; a refusal is the fixed plain text of its {@link EstError}.
 */
public final class EstResponses {

    /**
     * The realm of the Basic challenge of a request that names no label.
     */
    public static final String DEFAULT_REALM = "est";

    private static final String CRLF = "\r\n";
    private static final Base64.Encoder BASE64_LINES = Base64
            .getMimeEncoder(64, CRLF.getBytes(StandardCharsets.US_ASCII));
    private static final byte[] EMPTY_SEQUENCE = {0x30, 0x00};
    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BOUNDARY_RANDOM_BYTES = 24;
    private static final String ERROR_CONTENT_TYPE = "text/plain; charset=UTF-8";

    private EstResponses() {
    }

    /**
     * The response to {@code /cacerts} (RFC 7030 section 4.1.3): the certificates in a certs-only CMS
     * {@code SignedData}, which has no signer and no content.
     *
     * @param chain the CA certificates
     * @return the response
     * @throws IllegalStateException when a certificate cannot be encoded
     */
    public static ResponseEntity<byte[]> caCertificates(List<X509Certificate> chain) {
        return base64Body(EstMediaTypes.PKCS7_MIME, certsOnly(chain));
    }

    /**
     * The response to {@code /simpleenroll} (RFC 7030 section 4.2.3): the issued certificate in a certs-only CMS
     * {@code SignedData}.
     *
     * @param certificate the issued certificate
     * @return the response
     * @throws IllegalStateException when the certificate cannot be encoded
     */
    public static ResponseEntity<byte[]> enrolled(X509Certificate certificate) {
        return base64Body(EstMediaTypes.PKCS7_CERTS_ONLY, certsOnly(List.of(certificate)));
    }

    /**
     * Consumes and zeroes the key on every path, and builds the response to {@code /serverkeygen} (RFC 7030 section
     * 4.4.2): a {@code multipart/mixed} body whose first part is the private key as {@code application/pkcs8} and whose
     * second part is the issued certificate in a certs-only CMS {@code SignedData}, each as base64 text. The response
     * must not be cached. The key and every copy this method makes of it are overwritten once the body is built; the
     * body is the caller's to clear after it is sent.
     *
     * @param consumedKey the generated private key, which this method overwrites
     * @param certificate the issued certificate
     * @return the response
     * @throws IllegalStateException when the key or the certificate cannot be encoded
     */
    public static ResponseEntity<byte[]> serverKeyGenerated(PrivateKeyInfo consumedKey, X509Certificate certificate) {
        Objects.requireNonNull(consumedKey, "consumedKey");
        Objects.requireNonNull(certificate, "certificate");
        String boundary = "est-" + HexFormat.of().formatHex(randomBytes());
        byte[] keyDer = null;
        byte[] keyBase64 = null;
        try {
            keyDer = consumedKey.getEncoded(ASN1Encoding.DER);
            keyBase64 = BASE64_LINES.encode(keyDer);
            byte[] certificateBase64 = BASE64_LINES.encode(certsOnly(List.of(certificate)));
            byte[] body = multipart(boundary, keyBase64, certificateBase64);
            return ResponseEntity
                    .ok()
                    .header(HttpHeaders.CONTENT_TYPE, EstMediaTypes.MULTIPART_MIXED + "; boundary=" + boundary)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(body);
        } catch (IOException e) {
            throw new IllegalStateException("The private key cannot be encoded.");
        } finally {
            Pkcs8Envelopes.overwrite(consumedKey);
            zero(keyDer);
            zero(keyBase64);
        }
    }

    /**
     * The response to a request that is still being processed (RFC 7030 section 4.2.3): no content, and the delay after
     * which the client repeats the request.
     *
     * @param retryAfter the delay, sent in whole seconds
     * @return the response
     */
    public static ResponseEntity<byte[]> pending(Duration retryAfter) {
        return ResponseEntity.accepted().header(HttpHeaders.RETRY_AFTER, Long.toString(retryAfter.toSeconds())).build();
    }

    /**
     * The response to {@code /csrattrs} (RFC 7030 section 4.5.2).
     *
     * @param csrAttrsDer the DER {@code CsrAttrs}
     * @return the response, which has no content when the sequence is empty
     */
    public static ResponseEntity<byte[]> csrAttributes(byte[] csrAttrsDer) {
        if (Arrays.equals(csrAttrsDer, EMPTY_SEQUENCE)) {
            return ResponseEntity.noContent().build();
        }
        return base64Body(EstMediaTypes.CSR_ATTRS, csrAttrsDer);
    }

    /**
     * @param error what the client is told
     * @param realm the realm of the Basic challenge that an {@link EstError#challenges() challenging} error carries
     * @return the response
     */
    public static ResponseEntity<byte[]> error(EstError error, String realm) {
        return error(error, realm, null);
    }

    /**
     * @param error what the client is told
     * @param realm the realm of the Basic challenge that an {@link EstError#challenges() challenging} error carries
     * @param detail platform-written text sent after the fixed sentence; {@code null} for none
     * @return the response
     */
    public static ResponseEntity<byte[]> error(EstError error, String realm, String detail) {
        ResponseEntity.BodyBuilder response = ResponseEntity
                .status(error.status())
                .header(HttpHeaders.CONTENT_TYPE, ERROR_CONTENT_TYPE);
        if (error.challenges()) {
            response.header(HttpHeaders.WWW_AUTHENTICATE, basicChallenge(realm));
        }
        return response.body(textOf(error, detail));
    }

    /**
     * Writes the response of {@link #error} to a servlet response, for a refusal made before the request is dispatched.
     * The challenge, should the error carry one, names the realm of a request without a label.
     *
     * @param response where to write
     * @param error what the client is told
     * @param allowedMethod the method the operation accepts, which {@link EstError#METHOD_NOT_ALLOWED} sends as
     * {@code Allow}; other errors ignore it
     * @throws IOException when the response cannot be written
     */
    public static void write(HttpServletResponse response, EstError error, String allowedMethod) throws IOException {
        byte[] text = textOf(error);
        response.setStatus(error.status().value());
        response.setContentType(ERROR_CONTENT_TYPE);
        response.setContentLength(text.length);
        if (error.challenges()) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, basicChallenge(DEFAULT_REALM));
        }
        if (error == EstError.METHOD_NOT_ALLOWED && allowedMethod != null) {
            response.setHeader(HttpHeaders.ALLOW, allowedMethod);
        }
        response.getOutputStream().write(text);
    }

    private static byte[] certsOnly(List<X509Certificate> chain) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new JcaCertStore(chain));
            return generator.generate(new CMSAbsentContent()).getEncoded(ASN1Encoding.DER);
        } catch (CertificateEncodingException | CMSException | IOException e) {
            throw new IllegalStateException("The CA certificates cannot be encoded as a certs-only CMS message.", e);
        }
    }

    private static ResponseEntity<byte[]> base64Body(String contentType, byte[] der) {
        String lines = BASE64_LINES.encodeToString(der) + CRLF;
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .header(CONTENT_TRANSFER_ENCODING, "base64")
                .body(lines.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] randomBytes() {
        byte[] bytes = new byte[BOUNDARY_RANDOM_BYTES];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** Joins the two parts with the delimiters of RFC 2046; the base64 text has no hyphen, so it cannot hold one. */
    private static byte[] multipart(String boundary, byte[] keyBase64, byte[] certificateBase64) {
        byte[] keyPart = part(boundary, EstMediaTypes.PKCS8);
        byte[] certificatePart = part(boundary, EstMediaTypes.PKCS7_CERTS_ONLY);
        byte[] lineEnd = CRLF.getBytes(StandardCharsets.US_ASCII);
        byte[] closing = (CRLF + "--" + boundary + "--" + CRLF).getBytes(StandardCharsets.US_ASCII);
        byte[][] pieces = {keyPart, keyBase64, lineEnd, certificatePart, certificateBase64, closing};
        byte[] body = new byte[Arrays.stream(pieces).mapToInt(piece -> piece.length).sum()];
        int offset = 0;
        for (byte[] piece : pieces) {
            System.arraycopy(piece, 0, body, offset, piece.length);
            offset += piece.length;
        }
        return body;
    }

    private static byte[] part(String boundary, String contentType) {
        String headers = "--" + boundary + CRLF + "Content-Type: " + contentType + CRLF + CONTENT_TRANSFER_ENCODING
                + ": base64" + CRLF + CRLF;
        return headers.getBytes(StandardCharsets.US_ASCII);
    }

    private static void zero(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Names UTF-8 (RFC 7617), the charset the credentials are decoded with. */
    private static String basicChallenge(String realm) {
        return "Basic realm=\"" + realm + "\", charset=\"UTF-8\"";
    }

    private static byte[] textOf(EstError error) {
        return textOf(error, null);
    }

    private static byte[] textOf(EstError error, String detail) {
        String text = detail == null ? error.text() : error.text() + " " + detail;
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
