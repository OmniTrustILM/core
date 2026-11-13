package com.otilm.core.util.mocks;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * The answers of a v2 authority provider connector that issues and renews at once. They are stubbed on a WireMock
 * server that the test owns, rather than on one of their own as a {@link BaseConnectorMock} starts: the test seeds its
 * RA Profile with that server as the connector of the authority, and an HTTP test shares one server between its tests.
 * A test chains only the stubs that its scenario needs, and each stub answers whatever the request asks for.
 */
public final class AuthorityV2ConnectorStubs {

    /** The path that an issue is sent to, for a test that counts the issues. */
    public static final String ISSUE_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/issue";

    /** The path that a renewal or a rekey is sent to, for a test that counts them. */
    public static final String RENEW_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";

    private final WireMockServer server;

    private AuthorityV2ConnectorStubs(WireMockServer server) {
        this.server = server;
    }

    /** The stubs of the authority whose connector is the server. */
    public static AuthorityV2ConnectorStubs on(WireMockServer server) {
        return new AuthorityV2ConnectorStubs(server);
    }

    /**
     * Answers the issue that {@code AuthorityProviderV2Adapter.issue} sends for an issue action with the certificate.
     */
    public AuthorityV2ConnectorStubs stubIssue(X509Certificate issued) {
        server.stubFor(WireMock.post(WireMock.urlPathMatching(ISSUE_PATH)).willReturn(certificateData(issued)));
        return this;
    }

    /**
     * Answers the issue that {@code AuthorityProviderV2Adapter.issue} sends for an issue action with a certificate for
     * the request it carries, which the server's {@link CertifyingIssueTransformer} issues.
     */
    public AuthorityV2ConnectorStubs stubIssueCertifyingTheRequest() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH))
                        .willReturn(WireMock.okJson("{}").withTransformers(CertifyingIssueTransformer.NAME)));
        return this;
    }

    /**
     * Answers the issue that {@code AuthorityProviderV2Adapter.issue} sends with a server error, as an authority that
     * cannot issue a certificate does.
     */
    public AuthorityV2ConnectorStubs stubIssueFailure() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH))
                        .willReturn(WireMock.jsonResponse("{\"message\": \"the authority cannot issue\"}", 500)));
        return this;
    }

    /**
     * Answers the renewal that {@code AuthorityProviderV2Adapter.renew} sends with the certificate. A renew action
     * sends it, and so does a rekey action, as the v2 contract has no rekey operation of its own.
     */
    public AuthorityV2ConnectorStubs stubRenew(X509Certificate renewed) {
        server.stubFor(WireMock.post(WireMock.urlPathMatching(RENEW_PATH)).willReturn(certificateData(renewed)));
        return this;
    }

    /**
     * Answers the renewal that {@code AuthorityProviderV2Adapter.renew} sends with a server error, as an authority that
     * cannot renew a certificate does. A renew action sends it, and so does a rekey action. A later {@link #stubRenew}
     * answers the renewals after it.
     */
    public AuthorityV2ConnectorStubs stubRenewFailure() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(RENEW_PATH))
                        .willReturn(WireMock.jsonResponse("{\"message\": \"the authority cannot renew\"}", 500)));
        return this;
    }

    /**
     * Answers what {@code ExtendedAttributeServiceImpl.mergeAndValidateIssueAttributes} asks the authority before Core
     * stores a request, a renewal, a rekey or the completion of a registration: the authority accepts a request without
     * issue attributes, and defines none.
     */
    public AuthorityV2ConnectorStubs stubIssueAttributeValidation() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(ISSUE_PATH + "/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        return this;
    }

    /**
     * Answers the validation that {@code ExtendedAttributeServiceImpl.mergeAndValidateIssueAttributes} asks the
     * authority for first with a server error, as an authority that cannot validate a request does.
     */
    public AuthorityV2ConnectorStubs stubIssueAttributeValidationFailure() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.jsonResponse("{\"message\": \"the authority is unavailable\"}", 500)));
        return this;
    }

    private static ResponseDefinitionBuilder certificateData(X509Certificate certificate) {
        try {
            String der = Base64.getEncoder().encodeToString(certificate.getEncoded());
            return WireMock.okJson("{\"certificateData\": \"%s\"}".formatted(der));
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("The certificate cannot be encoded", e);
        }
    }
}
