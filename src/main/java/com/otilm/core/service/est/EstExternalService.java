package com.otilm.core.service.est;

import com.otilm.core.service.est.authentication.EstClientCredentials;
import org.springframework.http.ResponseEntity;

/**
 * The EST operations (RFC 7030) for the controller. Each answers with the complete HTTP response, and refuses with an
 * {@link com.otilm.core.service.est.message.EstException} that the error advice renders. The label is the one of the
 * request path, {@code null} for a request without one.
 */
public interface EstExternalService {

    /**
     * Distributes the CA certificates of the authority that serves the label (RFC 7030 section 4.1). It asks for no
     * client authentication.
     */
    ResponseEntity<byte[]> getCaCertificates(String label);

    /**
     * Tells the client which attributes the CA expects in a certification request (RFC 7030 section 4.5). It asks for
     * no client authentication.
     */
    ResponseEntity<byte[]> getCsrAttributes(String label);

    /**
     * Enrolls a client (RFC 7030 section 4.2.1).
     *
     * @param request the body of the request, base64 text of a DER PKCS#10 certification request
     * @param credentials what the client presented to authenticate
     */
    ResponseEntity<byte[]> simpleEnroll(String label, byte[] request, EstClientCredentials credentials);

    /**
     * Renews or rekeys the certificate of a client (RFC 7030 section 4.2.2).
     *
     * @param request the body of the request, base64 text of a DER PKCS#10 certification request
     * @param credentials what the client presented to authenticate
     */
    ResponseEntity<byte[]> simpleReenroll(String label, byte[] request, EstClientCredentials credentials);

    /**
     * Enrolls a client with a key that the server generates (RFC 7030 section 4.4).
     *
     * @param request the body of the request, base64 text of a DER PKCS#10 certification request
     * @param credentials what the client presented to authenticate
     */
    ResponseEntity<byte[]> serverKeyGeneration(String label, byte[] request, EstClientCredentials credentials);
}
