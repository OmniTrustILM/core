package com.otilm.core.cbom.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.model.cbom.BomCreateResponseDto;
import com.otilm.core.model.cbom.BomEntryDto;
import com.otilm.core.model.cbom.BomResponseDto;
import com.otilm.core.model.cbom.BomSearchRequestDto;
import com.otilm.core.model.cbom.BomVersionDto;
import com.otilm.core.settings.SettingsCache;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.web.reactive.function.client.WebClient;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CbomRepositoryClientTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

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
        PlatformSettingsDto toRestore = originalPlatformSettings != null
                ? originalPlatformSettings
                : new PlatformSettingsDto();
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

        wireMock
                .stubFor(post(urlEqualTo("/api/v1/bom"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(objectMapper.writeValueAsString(response))));

        // Act
        client.create(request);

        // Assert
        wireMock
                .verify(postRequestedFor(urlEqualTo("/api/v1/bom"))
                        .withHeader("Content-Type", equalTo("application/vnd.cyclonedx+json")));
    }

    @Test
    void testCreate_WithException() {
        // Arrange
        CbomUploadRequestDto request = new CbomUploadRequestDto();
        LinkedHashMap<String, Object> content = new LinkedHashMap<String, Object>();
        content.put("serialNumber", "urn:uuid:test-serial");
        request.setContent(content);

        wireMock
                .stubFor(post(urlEqualTo("/api/v1/bom"))
                        .willReturn(aResponse()
                                .withStatus(500)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"message\":\"Internal Server Error\"}")));

        // Act & Assert
        assertThrows(CbomRepositoryException.class, () -> client.create(request));
    }

    private static final String ENTRY_1 = """
            {"serialNumber":"urn:uuid:test-1","version":"1","created_at":"2026-01-19T21:35:05Z",
             "cryptoStats":{"cryptoAssets":{"total":4,"algorithms":{"total":1},"certificates":{"total":1},
             "protocols":{"total":1},"relatedCryptoMaterials":{"total":1}}}}""";
    private static final String ENTRY_2 = """
            {"serialNumber":"urn:uuid:test-2","version":"original","created_at":"2026-01-19T21:35:06Z",
             "cryptoStats":null,"warnings":["crypto-stats-missing"]}""";
    private static final String ENTRY_3 = """
            {"serialNumber":"urn:uuid:test-3","version":"2","created_at":"2026-01-19T21:35:07Z",
             "cryptoStats":{"cryptoAssets":{"total":0,"algorithms":{"total":0},"certificates":{"total":0},
             "protocols":{"total":0},"relatedCryptoMaterials":{"total":0}}},
             "warnings":["crypto-stats-shallow","crypto-stats-truncated"],"unknownFutureField":true}""";

    private static BomSearchRequestDto pagedQuery(long after, int limit) {
        BomSearchRequestDto query = new BomSearchRequestDto();
        query.setAfter(after);
        query.setLimit(limit);
        return query;
    }

    private void stubPage(String queryParam, String value, String body, String linkHeader) {
        var response = aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody(body);
        if (linkHeader != null) {
            response = response.withHeader("Link", linkHeader);
        }
        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam(queryParam, equalTo(value))
                        .willReturn(response));
    }

    @Test
    void search_opensARunWithAfterAndLimitAndMapsTheContract() throws Exception {
        stubPage("after", "1768858505", "[" + ENTRY_1 + "," + ENTRY_2 + "," + ENTRY_3 + "]", null);

        BomSearchPage page = client.search(pagedQuery(1768858505L, 1000));

        assertEquals(3, page.entries().size());
        assertFalse(page.hasNext());
        BomEntryDto first = page.entries().get(0);
        assertEquals("urn:uuid:test-1", first.getSerialNumber());
        assertEquals(OffsetDateTime.parse("2026-01-19T21:35:05Z"), first.getCreatedAt());
        assertEquals(4, first.getCryptoStats().getCryptoAssets().getTotal());
        assertFalse(first.hasWarnings());
        BomEntryDto second = page.entries().get(1);
        assertEquals("original", second.getVersion());
        assertNull(second.getCryptoStats());
        assertEquals(List.of("crypto-stats-missing"), second.getWarnings());
        BomEntryDto third = page.entries().get(2);
        assertEquals(List.of("crypto-stats-shallow", "crypto-stats-truncated"), third.getWarnings());
        wireMock
                .verify(getRequestedFor(urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("after", equalTo("1768858505"))
                        .withQueryParam("limit", equalTo("1000"))
                        .withQueryParam("cursor", absent()));
    }

    @Test
    void search_followsLinkNextByAppendingItsQueryToTheOwnSearchUrl() throws Exception {
        stubPage("after", "0", "[" + ENTRY_1 + "]", "<bom?cursor=c1&limit=1>; rel=\"next\"");
        stubPage("cursor", "c1", "[" + ENTRY_2 + "]",
                "<bom?cursor=c2&limit=1>; rel=\"next\", <bom?after=0&limit=1>; rel=\"first\"");
        stubPage("cursor", "c2", "[]", null);

        BomSearchPage first = client.search(pagedQuery(0, 1));
        assertTrue(first.hasNext());
        assertEquals(URI.create(baseUrl + "/api/v1/bom?cursor=c1&limit=1"), first.nextPage());

        BomSearchPage second = client.nextPage(first);
        assertEquals("urn:uuid:test-2", second.entries().get(0).getSerialNumber());
        assertTrue(second.hasNext());

        BomSearchPage third = client.nextPage(second);
        assertTrue(third.entries().isEmpty());
        assertFalse(third.hasNext());

        wireMock
                .verify(getRequestedFor(urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("cursor", equalTo("c1"))
                        .withQueryParam("limit", equalTo("1"))
                        .withQueryParam("after", absent()));
    }

    @Test
    void search_followsALinkCursorThatContainsBase64PaddingVerbatim() {
        String rawQuery = "cursor=djF8MTc4ODQ1MTIwMDAwMHx1cm46dXVpZA%3D%3D==&limit=1";
        stubPage("after", "0", "[" + ENTRY_1 + "]", "<bom?" + rawQuery + ">; rel=\"next\"");
        wireMock
                .stubFor(get(urlEqualTo("/api/v1/bom?" + rawQuery))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("[]")));

        BomSearchPage first = assertDoesNotThrow(() -> client.search(pagedQuery(0, 1)));
        assertTrue(first.hasNext());
        assertEquals(rawQuery, first.nextPage().getRawQuery());

        BomSearchPage second = assertDoesNotThrow(() -> client.nextPage(first));
        assertTrue(second.entries().isEmpty());
    }

    @Test
    void search_withoutLimitIsTheUnpagedLegacyCall() throws Exception {
        stubPage("after", "0", "[" + ENTRY_1 + "]", null);
        BomSearchRequestDto query = new BomSearchRequestDto();
        query.setAfter(null);

        BomSearchPage page = client.search(query);

        assertEquals(1, page.entries().size());
        assertFalse(page.hasNext());
        wireMock
                .verify(getRequestedFor(urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("after", equalTo("0"))
                        .withQueryParam("limit", absent()));
    }

    @Test
    void search_rejectsALimitOutsideTheContractBeforeCalling() {
        BomSearchRequestDto belowTheContract = pagedQuery(0, 0);
        BomSearchRequestDto aboveTheContract = pagedQuery(0, 1001);
        assertThrows(IllegalArgumentException.class, () -> client.search(belowTheContract));
        assertThrows(IllegalArgumentException.class, () -> client.search(aboveTheContract));
        wireMock.verify(0, getRequestedFor(urlPathEqualTo("/api/v1/bom")));
    }

    @Test
    void search_refusesAnAbsoluteOrPathAbsoluteOrForeignLinkTarget() {
        for (String target : List
                .of("https://evil.example/api/v1/bom?cursor=c1&limit=1", "/api/v1/bom?cursor=c1&limit=1",
                        "boms?cursor=c1&limit=1", "bom", "bom?", "bom?cursor=c1&after=0&limit=1",
                        // The server decodes the name before it reads it, so an encoded 'after' is 'after' and must
                        // not pass a guard that compares the raw text.
                        "bom?cursor=c1&%61fter=0&limit=1", "bom?cursor=c1&%61%66%74%65%72=0&limit=1",
                        // A network-path reference with an empty authority is not a relative-path reference either.
                        "//?cursor=c1&limit=1")) {
            wireMock.resetAll();
            stubPage("after", "0", "[]", "<" + target + ">; rel=\"next\"");
            CbomRepositoryException ex = assertThrows(CbomRepositoryException.class,
                    () -> client.search(pagedQuery(0, 1)), target);
            assertEquals(502, ex.getProblemDetail().getStatus(), target);
            // The target itself is not echoed: an absolute one names the repository's host, and the detail reaches
            // the sync endpoint's REST caller as well as the scheduler result. It goes to the log instead.
            assertEquals("CBOM Repository returned an unusable Link header for the next page",
                    ex.getProblemDetail().getDetail(), target);
        }
    }

    @Test
    void read_classifiesAFailedDocumentReadByTheResponseStatusNotByTheBody() {
        // An ingress or a repository build that answers with plain JSON rather than a problem detail: the body decodes
        // to a ProblemDetail with status 0, and the sync's 503-or-charge decision must not read that.
        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom/urn:uuid:down"))
                        .willReturn(aResponse()
                                .withStatus(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"service unavailable\"}")));

        CbomRepositoryException ex = assertThrows(CbomRepositoryException.class, () -> client.read("urn:uuid:down", 1));

        assertNotNull(ex.getProblemDetail());
        assertEquals(503, ex.getProblemDetail().getStatus());
    }

    @Test
    void search_classifiesAFailedPageByTheResponseStatusNotByTheBody() {
        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom"))
                        .willReturn(aResponse()
                                .withStatus(500)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody("{\"type\":\"about:blank\",\"title\":\"stub\",\"status\":503,"
                                        + "\"detail\":\"a body that claims another status\"}")));

        BomSearchRequestDto query = pagedQuery(0, 1);
        CbomRepositoryException ex = assertThrows(CbomRepositoryException.class, () -> client.search(query));

        assertEquals(500, ex.getProblemDetail().getStatus());
        assertEquals("CBOM Repository failed a page request (HTTP 500)", ex.getProblemDetail().getDetail());
    }

    @Test
    void nextPage_refusesACursorThatRepeatsTheRequestedPage() throws Exception {
        stubPage("after", "0", "[]", "<bom?cursor=c1&limit=1>; rel=\"next\"");
        stubPage("cursor", "c1", "[]", "<bom?cursor=c1&limit=1>; rel=\"next\"");

        BomSearchPage first = client.search(pagedQuery(0, 1));
        CbomRepositoryException ex = assertThrows(CbomRepositoryException.class, () -> client.nextPage(first));
        assertEquals(502, ex.getProblemDetail().getStatus());
        assertEquals("CBOM Repository repeated the page cursor", ex.getProblemDetail().getDetail());
    }

    @Test
    void nextPage_requiresAPageWithANextLink() throws Exception {
        stubPage("after", "0", "[]", null);
        BomSearchPage last = client.search(pagedQuery(0, 1));
        assertThrows(IllegalArgumentException.class, () -> client.nextPage(last));
    }

    @Test
    void search_keepsTheStatusOfAFailedPageButNotTheRepositoryDetail() {
        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom"))
                        .willReturn(aResponse()
                                .withStatus(500)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody(
                                        "{\"type\":\"about:blank\",\"title\":\"Internal Server Error\",\"status\":500,"
                                                + "\"detail\":\"ERROR: relation \\\"bom\\\" does not exist\"}")));

        BomSearchRequestDto query = pagedQuery(0, 1);
        CbomRepositoryException ex = assertThrows(CbomRepositoryException.class, () -> client.search(query));

        // The status is what the sync classifies by, so it is kept. The sentence is not: a failed page fails the run,
        // and the run's message reaches an operator through the scheduler result.
        assertEquals(500, ex.getProblemDetail().getStatus());
        assertEquals("CBOM Repository failed a page request (HTTP 500)", ex.getProblemDetail().getDetail());
    }

    @Test
    void nextPage_propagatesA400FromAReplicaThatDoesNotKnowTheCursor() throws Exception {
        stubPage("after", "0", "[]", "<bom?cursor=c1&limit=1>; rel=\"next\"");
        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("cursor", equalTo("c1"))
                        .willReturn(aResponse()
                                .withStatus(400)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody(
                                        "{\"type\":\"about:blank\",\"title\":\"Bad Request\",\"status\":400,\"detail\":\"unknown parameter cursor\"}")));

        BomSearchPage first = client.search(pagedQuery(0, 1));
        CbomRepositoryException ex = assertThrows(CbomRepositoryException.class, () -> client.nextPage(first));
        assertEquals(400, ex.getProblemDetail().getStatus());
        assertEquals("CBOM Repository failed a page request (HTTP 400)", ex.getProblemDetail().getDetail());
    }

    @Test
    void testRead_WithoutVersion() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";

        BomResponseDto response = new BomResponseDto();
        response.put("specVersion", "1.0");
        response.put("serialNumber", urn);
        response.put("version", "1");

        wireMock
                .stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
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

        wireMock.verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*")).withoutQueryParam("version"));
    }

    @Test
    void testRead_WithVersion() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";

        BomResponseDto response = new BomResponseDto();
        response.put("specVersion", "1.0");
        response.put("serialNumber", urn);
        response.put("version", "2");

        wireMock
                .stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
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

        wireMock
                .verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", equalTo("2")));
    }

    @Test
    void testVersions_Success() throws Exception {
        // Arrange
        String urn = "urn:uuid:test-serial";
        String encodedUrn = "urn%3Auuid%3Atest-serial"; // Manually encode

        BomVersionDto version1 = new BomVersionDto();
        version1.setVersion("1");
        version1.setTimestamp(OffsetDateTime.parse("2026-01-19T21:35:05Z").toString());

        BomVersionDto version2 = new BomVersionDto();
        version2.setVersion("2");
        version2.setTimestamp(OffsetDateTime.parse("2026-01-20T10:00:00Z").toString());

        List<BomVersionDto> responseList = List.of(version1, version2);

        wireMock
                .stubFor(get(urlPathEqualTo("/api/v1/bom/" + encodedUrn + "/versions"))
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

        wireMock
                .stubFor(get(urlPathMatching("/api/v1/bom/.*/versions"))
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

        wireMock
                .stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
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

        wireMock
                .stubFor(get(WireMock.urlMatching("/api/v1/bom/.*"))
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
        CbomRepositoryException exception = assertThrows(CbomRepositoryException.class, () -> client.read(urn, null));

        assertNotNull(exception.getProblemDetail());
        assertEquals(400, exception.getProblemDetail().getStatus());

        wireMock.verify(getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*")).withoutQueryParam("version"));
    }
}
