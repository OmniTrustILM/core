package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.security.authn.ForwardedClientCertificateParser;
import com.otilm.core.security.authn.ForwardedClientCertificateParser.ParsedCertificate;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;

/**
 * What an EST client presented to prove who it is: HTTP Basic credentials and a client certificate forwarded by the
 * TLS-terminating proxy. Each is read without judging it, so that the authentication policy of the profile decides
 * which of them counts. A credential the client sent but that cannot be read is reported as malformed, never as absent.
 * <p>
 * The password never leaves this object by itself: {@link #toString()} reports only whether each credential is present,
 * and the password field is {@link Sensitive}.
 */
@Slf4j
public final class EstClientCredentials {

    private static final String BASIC_SCHEME = "Basic";

    private final BasicCredentials basic;
    private final boolean basicMalformed;
    private final ParsedCertificate certificate;
    private final boolean certificateMalformed;

    private EstClientCredentials(BasicCredentials basic, boolean basicMalformed, ParsedCertificate certificate,
            boolean certificateMalformed) {
        this.basic = basic;
        this.basicMalformed = basicMalformed;
        this.certificate = certificate;
        this.certificateMalformed = certificateMalformed;
    }

    /**
     * Reads the credentials of a request. The {@code Authorization} header counts as Basic credentials when its scheme
     * is {@code Basic}, in any letter case; one with another scheme is not for EST and is ignored. The certificate is
     * read only when the header is there, with the parser that validates every certificate the proxy asserted.
     *
     * @param request the request of the client
     * @param certificateHeaderName the header in which the proxy forwards the client certificate
     * @return the credentials, always: what cannot be read is marked malformed
     */
    public static EstClientCredentials from(HttpServletRequest request, String certificateHeaderName) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        String value = authorization == null ? "" : authorization.strip();
        boolean basicPresented = isBasicScheme(value);
        BasicCredentials basic = basicPresented ? decodeBasic(value.substring(BASIC_SCHEME.length()).strip()) : null;

        boolean certificatePresented = request.getHeader(certificateHeaderName) != null;
        ParsedCertificate certificate = certificatePresented ? parseCertificate(request, certificateHeaderName) : null;

        return new EstClientCredentials(basic, basicPresented && basic == null, certificate,
                certificatePresented && certificate == null);
    }

    public Optional<BasicCredentials> basic() {
        return Optional.ofNullable(basic);
    }

    /**
     * @return whether the client sent Basic credentials that cannot be decoded
     */
    public boolean basicMalformed() {
        return basicMalformed;
    }

    public Optional<ParsedCertificate> certificate() {
        return Optional.ofNullable(certificate);
    }

    /**
     * @return whether the client sent a certificate header that cannot be parsed
     */
    public boolean certificateMalformed() {
        return certificateMalformed;
    }

    @Override
    public String toString() {
        return "EstClientCredentials[basic=" + state(basic != null, basicMalformed) + ", certificate="
                + state(certificate != null, certificateMalformed) + "]";
    }

    /**
     * Reads the scheme without a regular expression, so that no value of the header can make the reading slow.
     *
     * @param value the header value, stripped
     * @return whether the scheme is {@code Basic}, in any letter case, followed by whitespace or by nothing
     */
    private static boolean isBasicScheme(String value) {
        int length = BASIC_SCHEME.length();
        return value.regionMatches(true, 0, BASIC_SCHEME, 0, length)
                && (value.length() == length || Character.isWhitespace(value.charAt(length)));
    }

    /**
     * @param encoded the text after the scheme, stripped; empty when there is none
     * @return the credentials, {@code null} when the text is not strict base64 of {@code user:password}
     */
    private static BasicCredentials decodeBasic(String encoded) {
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        int separator = decoded.indexOf(':');
        if (separator < 0) {
            return null;
        }
        return new BasicCredentials(decoded.substring(0, separator), decoded.substring(separator + 1));
    }

    private static ParsedCertificate parseCertificate(HttpServletRequest request, String certificateHeaderName) {
        try {
            return ForwardedClientCertificateParser.parse(request, certificateHeaderName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The SHA-256 algorithm is not available.", e);
        } catch (IllegalArgumentException e) {
            log
                    .debug("The client certificate header was refused: {}",
                            PlatformAuthenticationClient.certificateFailureReason(e));
            return null;
        }
    }

    private static String state(boolean present, boolean malformed) {
        if (malformed) {
            return "malformed";
        }
        return present ? "present" : "absent";
    }

    /**
     * The user name and password of an {@code Authorization: Basic} header. The user name may be empty, which RFC 7030
     * section 3.2.3 allows a client to send.
     */
    public static final class BasicCredentials {

        private final String username;

        @Sensitive
        private final String password;

        private BasicCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() {
            return username;
        }

        public String password() {
            return password;
        }
    }
}
