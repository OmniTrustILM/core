package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateRequestDto;
import com.czertainly.core.provisioning.ProvisioningException;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Base64;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.*;

class TrustedCertificateServiceTest extends BaseSpringBootTest {

    private static final String TEST_UUID = "abfbc322-29e1-11ed-a261-0242ac120002";
    private static final String TEST_CERTIFICATE_CONTENT = Base64.getEncoder().encodeToString("test-certificate-content".getBytes());
    private static final String TRUSTED_CERTIFICATE_JSON = """
        {
            "uuid": "%s",
            "certificateContent": "%s",
            "issuer": "CN=Test CA",
            "san": "DNS:example.com",
            "serialNumber": "1234567890",
            "subject": "CN=example.com",
            "thumbprint": "AB:CD:EF:12:34:56",
            "notBefore": "2024-01-01T00:00:00",
            "notAfter": "2025-12-31T23:59:59"
        }
        """.formatted(TEST_UUID, TEST_CERTIFICATE_CONTENT);

    private static final String TRUSTED_CERTIFICATE_LIST_JSON = "[" + TRUSTED_CERTIFICATE_JSON + "]";

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension.newInstance()
        .options(wireMockConfig().dynamicPort())
        .build();

    @DynamicPropertySource
    static void provisioningTestProperties(@NonNull DynamicPropertyRegistry registry) {
        registry.add("provisioning.api.url", wireMockServer::baseUrl);
    }

    @Autowired
    private TrustedCertificateService trustedCertificateService;

    @Test
    void testListTrustedCertificates_success() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(TRUSTED_CERTIFICATE_LIST_JSON)));

        List<TrustedCertificateDto> certificates = trustedCertificateService.listTrustedCertificates();

        assertNotNull(certificates);
        assertEquals(1, certificates.size());
        TrustedCertificateDto dto = certificates.getFirst();
        assertEquals(TEST_UUID, dto.getUuid());
        assertEquals("CN=Test CA", dto.getIssuer());
        assertEquals("CN=example.com", dto.getSubject());
    }

    @Test
    void testListTrustedCertificates_emptyList() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("[]")));

        List<TrustedCertificateDto> certificates = trustedCertificateService.listTrustedCertificates();

        assertNotNull(certificates);
        assertTrue(certificates.isEmpty());
    }

    @Test
    void testListTrustedCertificates_apiFails() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates"))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> trustedCertificateService.listTrustedCertificates());

        assertTrue(exception.getMessage().contains("Failed to list trusted certificates"));
    }

    @Test
    void testGetTrustedCertificate_success() throws NotFoundException {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(TRUSTED_CERTIFICATE_JSON)));

        TrustedCertificateDto dto = trustedCertificateService.getTrustedCertificate(SecuredUUID.fromString(TEST_UUID));

        assertNotNull(dto);
        assertEquals(TEST_UUID, dto.getUuid());
        assertEquals("CN=Test CA", dto.getIssuer());
        assertEquals("CN=example.com", dto.getSubject());
        assertEquals("DNS:example.com", dto.getSan());
        assertEquals("1234567890", dto.getSerialNumber());
        assertEquals("AB:CD:EF:12:34:56", dto.getThumbprint());
    }

    @Test
    void testGetTrustedCertificate_notFound() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(404)
                .withBody("Not Found")));

        assertThrows(NotFoundException.class,
            () -> trustedCertificateService.getTrustedCertificate(SecuredUUID.fromString(TEST_UUID)));
    }

    @Test
    void testGetTrustedCertificate_apiFails() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> trustedCertificateService.getTrustedCertificate(SecuredUUID.fromString(TEST_UUID)));

        assertTrue(exception.getMessage().contains("Failed to get trusted certificate"));
    }

    @Test
    void testCreateTrustedCertificate_success() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/v1/trusted-certificates"))
            .willReturn(aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(TRUSTED_CERTIFICATE_JSON)));

        TrustedCertificateRequestDto request = new TrustedCertificateRequestDto();
        request.setCertificateContent(Base64.getDecoder().decode(TEST_CERTIFICATE_CONTENT));

        TrustedCertificateDto dto = trustedCertificateService.createTrustedCertificate(request);

        assertNotNull(dto);
        assertEquals(TEST_UUID, dto.getUuid());
        assertEquals("CN=Test CA", dto.getIssuer());
        assertEquals("CN=example.com", dto.getSubject());

        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/v1/trusted-certificates"))
            .withHeader("Content-Type", containing("application/json")));
    }

    @Test
    void testCreateTrustedCertificate_apiFails() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/v1/trusted-certificates"))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        TrustedCertificateRequestDto request = new TrustedCertificateRequestDto();
        request.setCertificateContent(Base64.getDecoder().decode(TEST_CERTIFICATE_CONTENT));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> trustedCertificateService.createTrustedCertificate(request));

        assertTrue(exception.getMessage().contains("Failed to create trusted certificate"));
    }

    @Test
    void testDeleteTrustedCertificate_success() {
        wireMockServer.stubFor(delete(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(204)));

        assertDoesNotThrow(() -> trustedCertificateService.deleteTrustedCertificate(SecuredUUID.fromString(TEST_UUID)));

        wireMockServer.verify(deleteRequestedFor(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID)));
    }

    @Test
    void testDeleteTrustedCertificate_notFound() {
        wireMockServer.stubFor(delete(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(404)
                .withBody("Not Found")));

        assertThrows(NotFoundException.class,
            () -> trustedCertificateService.deleteTrustedCertificate(SecuredUUID.fromString(TEST_UUID)));
    }

    @Test
    void testDeleteTrustedCertificate_apiFails() {
        wireMockServer.stubFor(delete(urlPathEqualTo("/api/v1/trusted-certificates/" + TEST_UUID))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> trustedCertificateService.deleteTrustedCertificate(SecuredUUID.fromString(TEST_UUID)));

        assertTrue(exception.getMessage().contains("Failed to delete trusted certificate"));
    }
}