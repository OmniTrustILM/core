package com.czertainly.core.cbom.client;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.czertainly.core.model.cbom.*;
import com.czertainly.core.settings.SettingsCache;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.*;

class CbomRepositoryClientTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    private CbomRepositoryClient client;
    private ObjectMapper objectMapper;
    private String baseUrl;
    private PlatformSettingsDto originalPlatformSettings;

    @BeforeEach
    void setUp() {
        baseUrl = wireMock.baseUrl();
        originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);

        PlatformSettingsDto platformSettings = new PlatformSettingsDto();
        UtilsSettingsDto utilsSettings = new UtilsSettingsDto();
        utilsSettings.setCbomRepositoryUrl(baseUrl);
        platformSettings.setUtils(utilsSettings);
        SettingsCache cache = new SettingsCache();
        cache.cacheSettings(SettingsSection.PLATFORM, platformSettings);

        WebClient wclient = WebClient.builder().build();
        client = new CbomRepositoryClient(wclient, 262144);
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
    }

    @AfterEach
    void tearDown() {
        PlatformSettingsDto toRestore = originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto();
        new SettingsCache().cacheSettings(SettingsSection.PLATFORM, toRestore);
    }

    @Test
    void testCreate_Success() throws Exception {
        // Arrange
        CbomUploadRequestDto request = new CbomUploadRequestDto();
        LinkedHashMap<String, Object> content = new LinkedHashMap<String, Object>();
        content.put("version", "1");
        content.put("serialNumber", "urn:uuid:test-serial");
        request.setContent(content);

        BomCreateResponseDto response = new BomCreateResponseDto();
        response.setSerialNumber("urn:uuid:test-serial");
        response.setVersion(1);

        wireMock.stubFor(post(urlEqualTo("/api/v1/bom"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(response))));

        // Act
        client.create(request);

        // Assert
        wireMock.verify(postRequestedFor(urlEqualTo("/api/v1/bom"))
                .withHeader("Content-Type", equalTo("application/vnd.cyclonedx+json")));
    }

    @Test
    void testCreate_WithException() {
        // Arrange
        CbomUploadRequestDto request = new CbomUploadRequestDto();
        LinkedHashMap<String, Object> content = new LinkedHashMap<String, Object>();
        content.put("serialNumber", "urn:uuid:test-serial");
        request.setContent(content);

        wireMock.stubFor(post(urlEqualTo("/api/v1/bom"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"message\":\"Internal Server Error\"}")));

        // Act & Assert
        assertThrows(CbomRepositoryException.class, () -> client.create(request));
    }

    @Test
    void testSearch_Success() throws Exception {
        // Arrange
        BomSearchRequestDto searchRequest = new BomSearchRequestDto();
        Long after = OffsetDateTime.parse("2026-01-19T21:35:05Z").toEpochSecond();
        searchRequest.setAfter(after);

        BomEntryDto entry1 = new BomEntryDto();
        entry1.setSerialNumber("urn:uuid:test-1");
        entry1.setVersion("1");

        BomEntryDto entry2 = new BomEntryDto();
        entry2.setSerialNumber("urn:uuid:test-2");
        entry2.setVersion("1");

        List<BomEntryDto> responseList = List.of(entry1, entry2);

        wireMock.stubFor(get(urlPathEqualTo("/api/v1/bom"))
                .withQueryParam("after", equalTo(String.valueOf(after)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(responseList))));

        // Act
        List<BomEntryDto> result = client.search(searchRequest);

        // Assert
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("urn:uuid:test-1", result.get(0).getSerialNumber());
        assertEquals("urn:uuid:test-2", result.get(1).getSerialNumber());

        wireMock.verify(getRequestedFor(urlPathEqualTo("/api/v1/bom"))
                .withQueryParam("after", equalTo(String.valueOf(after))));
    }

    @Test
    void testSearch_WithNullAfter() throws Exception {
        // Arrange
        BomSearchRequestDto searchRequest = new BomSearchRequestDto();
        searchRequest.setAfter(null);

        List<BomEntryDto> responseList = List.of();

        wireMock.stubFor(get(urlPathEqualTo("/api/v1/bom"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(responseList))));

        // Act
        List<BomEntryDto> result = client.search(searchRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testRead_WithoutVersion() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";
        
        BomResponseDto response = new BomResponseDto();
        response.put("specVersion", "1.0");
        response.put("serialNumber", urn);
        response.put("version", "1");

        wireMock.stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(response))));

        // Act
        BomResponseDto result = client.read(urn, null);

        // Assert
        assertNotNull(result);
        assertEquals(urn, result.get("serialNumber"));
        assertEquals("1", result.get("version"));
        assertEquals("1.0", result.get("specVersion"));

        wireMock.verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*"))
                .withoutQueryParam("version"));
    }

    @Test
    void testRead_WithVersion() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";

        BomResponseDto response = new BomResponseDto();
        response.put("specVersion", "1.0");
        response.put("serialNumber", urn);
        response.put("version", "2");

        wireMock.stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
                .withQueryParam("version", equalTo("2"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(response))));

        // Act
        BomResponseDto result = client.read(urn, 2);

        // Assert
        assertNotNull(result);
        assertEquals(urn, result.get("serialNumber"));
        assertEquals("2", result.get("version"));
        assertEquals("1.0", result.get("specVersion"));

        wireMock.verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*"))
                .withQueryParam("version", equalTo("2")));
    }

    @Test
    void testVersions_Success() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";
        String encodedUrn = "urn%3Auuid%3Atest-serial";  // Manually encode

        BomVersionDto version1 = new BomVersionDto();
        version1.setVersion("1");
        version1.setTimestamp(OffsetDateTime.parse("2026-01-19T21:35:05Z").toString());

        BomVersionDto version2 = new BomVersionDto();
        version2.setVersion("2");
        version2.setTimestamp(OffsetDateTime.parse("2026-01-20T10:00:00Z").toString());

        List<BomVersionDto> responseList = List.of(version1, version2);

        wireMock.stubFor(get(urlPathEqualTo("/api/v1/bom/" + encodedUrn + "/versions"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(responseList))));

        // Act
        List<BomVersionDto> result = client.versions(urn);

        // Assert
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("1", result.get(0).getVersion());
        assertEquals("2", result.get(1).getVersion());

        wireMock.verify(getRequestedFor(urlPathEqualTo("/api/v1/bom/" + encodedUrn + "/versions")));
    }

    @Test
    void testVersions_WithEncodedUrn() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial-with-special-chars";
        List<BomVersionDto> responseList = List.of();

        wireMock.stubFor(get(urlPathMatching("/api/v1/bom/.*/versions"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(responseList))));

        // Act
        List<BomVersionDto> result = client.versions(urn);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testRead_LargeResponse_FailsWithBufferSizeLimit() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";
        int smallBufferSize = 100;
        WebClient wclient = WebClient.builder().build();
        client = new CbomRepositoryClient(wclient, smallBufferSize);

        StringBuilder largeContent = new StringBuilder();
        largeContent.append("A".repeat(smallBufferSize + 1));

        BomResponseDto response = new BomResponseDto();
        response.put("serialNumber", urn);
        response.put("largeData", largeContent.toString());

        wireMock.stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(response))));

        // Act & Assert
        assertThrows(CbomRepositoryException.class, () -> client.read(urn, null));
    }

    @Test
    void testRead_WhenWebClientResponseException_ShouldThrowCbomRepositoryException() {
        // Arrange
        String urn = "urn:uuid:test-serial";

        wireMock.stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
            .willReturn(aResponse()
                .withStatus(400)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                    "type": "about:blank",
                    "title": "Bad Request",
                    "status": 400,
                    "detail": "Invalid request parameters"
                    }
                    """)));

        // Act & Assert
        CbomRepositoryException exception = assertThrows(
            CbomRepositoryException.class,
        () -> client.read(urn, null)
        );

        assertNotNull(exception.getProblemDetail());
        assertEquals(400, exception.getProblemDetail().getStatus());

        wireMock.verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*"))
            .withoutQueryParam("version"));
    }
}
