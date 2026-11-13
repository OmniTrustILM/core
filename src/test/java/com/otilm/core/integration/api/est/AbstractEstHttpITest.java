package com.otilm.core.integration.api.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * What the EST operations over HTTP need: the real filter chain through MockMvc, the Auth service that admits every
 * request as the {@code est} system user, and the connector of the authority on WireMock. The requests carry the
 * context path because the protocol filter matches on it.
 */
@AutoConfigureMockMvc
abstract class AbstractEstHttpITest extends BaseSpringBootTest {

    protected static final String CONTEXT_PATH = "/api";
    protected static final String EST_BASE = CONTEXT_PATH + "/v1/protocols/.well-known/est/";
    protected static final String CA_CERTIFICATES = "/v1/authorityProvider/authorities/[^/]+/caCertificates";

    private static final MediaType PLAIN_TEXT_UTF8 = MediaType.parseMediaType("text/plain; charset=UTF-8");

    protected static WireMockServer connectorServer;

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected EstRouteSeeder seeder;

    @Autowired
    private AuthenticationCache authenticationCache;

    private WireMockServer authService;

    @BeforeAll
    static void startConnector() {
        connectorServer = LoopbackWireMock.start();
    }

    @AfterAll
    static void stopConnector() {
        connectorServer.stop();
    }

    @BeforeEach
    void resetConnectorAndStartAuthService() {
        connectorServer.resetAll();
        authenticationCache.evictAll();
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), AuthHelper.EST_USERNAME);
    }

    @AfterEach
    void stopAuthService() {
        authService.stop();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    protected MockHttpServletResponse getFromEst(String operationPath) throws Exception {
        return mockMvc.perform(estGet(operationPath)).andReturn().getResponse();
    }

    protected MockHttpServletResponse postToEst(String operationPath, byte[] body) throws Exception {
        return mockMvc.perform(estPost(operationPath, body)).andReturn().getResponse();
    }

    protected MockHttpServletResponse postToEst(String operationPath, byte[] body, String authorization)
            throws Exception {
        return mockMvc
                .perform(estPost(operationPath, body).header(HttpHeaders.AUTHORIZATION, authorization))
                .andReturn()
                .getResponse();
    }

    protected static MockHttpServletRequestBuilder estGet(String operationPath) {
        return get(EST_BASE + operationPath).contextPath(CONTEXT_PATH);
    }

    /** A request that carries a certification request as the media type of EST says. */
    protected static MockHttpServletRequestBuilder estPost(String operationPath, byte[] body) {
        return post(EST_BASE + operationPath).contextPath(CONTEXT_PATH).contentType(EstMediaTypes.PKCS10).content(body);
    }

    protected static void assertPlainTextError(MockHttpServletResponse response, EstError error) throws Exception {
        assertThat(response.getStatus()).isEqualTo(error.status().value());
        assertThat(MediaType.parseMediaType(response.getContentType())).isEqualTo(PLAIN_TEXT_UTF8);
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo(error.text());
    }

    /**
     * Reads the only certificate of the certificates-only CMS that answers an enrolment or a re-enrolment, after it
     * checks that the answer says it is one.
     */
    protected static X509Certificate readCertificate(MockHttpServletResponse response) throws Exception {
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(MediaType.parseMediaType(EstMediaTypes.PKCS7_CERTS_ONLY));
        CMSSignedData signedData = new CMSSignedData(Base64.getMimeDecoder().decode(response.getContentAsByteArray()));
        Collection<X509CertificateHolder> held = signedData.getCertificates().getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate(held.iterator().next());
    }

    /**
     * An RA Profile whose authority has the WireMock server as its connector. A test can create one, as a connector URL
     * is unique.
     */
    protected RaProfile saveRaProfile(String name) {
        return seeder.seedRaProfile(connectorServer, name);
    }

    protected static List<X509Certificate> generateChain() throws Exception {
        return List
                .of(CertificateGeneratorHelper.generateCACertificate(null, "CN=Root CA"),
                        CertificateGeneratorHelper.generateCACertificate(null, "CN=Issuing CA"));
    }

    /** The connector's answer to the request for the CA certificates of the authority. */
    protected static void stubCaCertificates(List<X509Certificate> chain) throws CertificateEncodingException {
        stubCaCertificates(chain, 0);
    }

    protected static void stubCaCertificates(List<X509Certificate> chain, int delayMillis)
            throws CertificateEncodingException {
        List<String> entries = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            String certificateData = Base64.getEncoder().encodeToString(certificate.getEncoded());
            entries.add("{\"certificateData\": \"%s\", \"certificateType\": \"X.509\"}".formatted(certificateData));
        }
        String body = "{\"certificates\": [" + String.join(",", entries) + "]}";
        connectorServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(CA_CERTIFICATES))
                        .willReturn(WireMock.okJson(body).withFixedDelay(delayMillis)));
    }
}
