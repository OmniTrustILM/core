package com.otilm.core.util;

import com.otilm.core.service.est.authentication.EstClientCredentials;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

/** What an EST client presented, as the controller reads it from the request. */
public final class EstClientCredentialsFixtures {

    private static final String CERTIFICATE_HEADER = "ssl-client-cert";

    private EstClientCredentialsFixtures() {
    }

    /** A client that presented no credential. */
    public static EstClientCredentials noCredentials() {
        return EstClientCredentials.from(new MockHttpServletRequest(), CERTIFICATE_HEADER);
    }

    /** A client that presented HTTP Basic credentials. */
    public static EstClientCredentials basicCredentials(String username, String password) {
        return withAuthorization(basicAuthorization(username, password));
    }

    /** The {@code Authorization} header value of HTTP Basic credentials. */
    public static String basicAuthorization(String username, String password) {
        byte[] userAndPassword = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(userAndPassword);
    }

    /** A client whose Basic credentials are not base64 text. */
    public static EstClientCredentials malformedBasicCredentials() {
        return withAuthorization(malformedBasicAuthorization());
    }

    /** The {@code Authorization} header value of Basic credentials that are not base64 text. */
    public static String malformedBasicAuthorization() {
        return "Basic !!!not-base64!!!";
    }

    /**
     * A client that presented a certificate, which the proxy forwarded with the chain the client sent, each certificate
     * as the base64 text of its DER.
     */
    public static EstClientCredentials certificateCredentials(X509Certificate certificate, X509Certificate... chain) {
        return withCertificateHeader(certificateHeader(certificate, chain));
    }

    /**
     * A client that presented a certificate, which the proxy forwarded as {@link #certificateCredentials} does, and
     * HTTP Basic credentials.
     */
    public static EstClientCredentials certificateAndBasicCredentials(X509Certificate certificate, String username,
            String password) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CERTIFICATE_HEADER, certificateHeader(certificate));
        request.addHeader(HttpHeaders.AUTHORIZATION, basicAuthorization(username, password));
        return EstClientCredentials.from(request, CERTIFICATE_HEADER);
    }

    /** The value that the proxy forwards in the certificate header: the certificate followed by the chain. */
    public static String certificateHeader(X509Certificate certificate, X509Certificate... chain) {
        return Stream
                .concat(Stream.of(certificate), Arrays.stream(chain))
                .map(EstClientCredentialsFixtures::base64Der)
                .collect(Collectors.joining(","));
    }

    /** A client whose certificate header holds no certificate. */
    public static EstClientCredentials malformedCertificateCredentials() {
        return withCertificateHeader(malformedCertificateHeader());
    }

    /** The value of a certificate header that holds no certificate. */
    public static String malformedCertificateHeader() {
        return "not a certificate";
    }

    private static EstClientCredentials withAuthorization(String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        return EstClientCredentials.from(request, CERTIFICATE_HEADER);
    }

    private static EstClientCredentials withCertificateHeader(String header) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CERTIFICATE_HEADER, header);
        return EstClientCredentials.from(request, CERTIFICATE_HEADER);
    }

    private static String base64Der(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("The certificate cannot be encoded", e);
        }
    }
}
