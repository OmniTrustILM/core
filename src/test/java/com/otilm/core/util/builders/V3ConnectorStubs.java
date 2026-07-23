package com.otilm.core.util.builders;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;

/**
 * WireMock stub helpers for the v3 authority provider wire contract. Each static method registers stubs for a
 * specific v3 connector endpoint using paths from the {@code CertificateApiClient} v3 constants.
 */
public final class V3ConnectorStubs {

    // ---- endpoint paths (from CertificateApiClient v3 constants) ----

    private static final String REGISTER_PATH   = "/v3/authorityProvider/certificates/register";
    private static final String REGISTER_ATTRIBUTES_PATH = REGISTER_PATH + "/attributes";
    public static final String REGISTER_STATUS = "/v3/authorityProvider/certificates/register/status";
    private static final String ISSUE_PATH      = "/v3/authorityProvider/certificates/issue";

    // State names for the stateful register-status scenario.
    private static final String STATUS_SCENARIO_IN_PROGRESS = Scenario.STARTED;
    private static final String STATUS_SCENARIO_COMPLETED   = "COMPLETED";

    private V3ConnectorStubs() {}

    // ---- Register -------------------------------------------------------

    /**
     * Stubs a synchronous register response (HTTP 200).
     *
     * @param metaJson JSON array of MetadataAttribute objects; pass {@code null} or {@code "[]"} for a meta-free response
     */
    public static void stubRegisterSync(WireMockServer wm, String metaJson) {
        String safeMetaJson = (metaJson == null || metaJson.isBlank()) ? "[]" : metaJson;
        stubRegisterAttributesEmpty(wm);
        wm.stubFor(post(urlEqualTo(REGISTER_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": null, "meta": %s}
                                """.formatted(safeMetaJson))));
    }

    /**
     * Stubs an asynchronous register response (HTTP 202).
     *
     * @param trackingMeta JSON array of MetadataAttribute tracking objects; pass {@code null} or {@code "[]"} for empty meta
     */
    public static void stubRegisterAsync(WireMockServer wm, String trackingMeta) {
        String safeMeta = (trackingMeta == null || trackingMeta.isBlank()) ? "[]" : trackingMeta;
        stubRegisterAttributesEmpty(wm);
        wm.stubFor(post(urlEqualTo(REGISTER_PATH))
                .willReturn(aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": null, "meta": %s}
                                """.formatted(safeMeta))));
    }

    /**
     * Stubs the connector's register-operation attribute-list endpoint to return an empty schema, so the
     * unconditional {@code mergeAndValidateRegisterAttributes} on the register-capable path succeeds without real
     * register-attribute data. Every register-capable stub needs this — a real register-capable connector exposes
     * {@code /register/attributes} alongside {@code /register}.
     */
    private static void stubRegisterAttributesEmpty(WireMockServer wm) {
        wm.stubFor(post(urlEqualTo(REGISTER_ATTRIBUTES_PATH)).willReturn(WireMock.okJson("[]")));
        wm.stubFor(get(urlEqualTo(REGISTER_ATTRIBUTES_PATH)).willReturn(WireMock.okJson("[]")));
    }

    // ---- Register status (stateful scenario) ----------------------------

    /**
     * Registers a two-state stateful stub for the register-status endpoint: first call returns IN_PROGRESS and
     * transitions to COMPLETED, subsequent calls return COMPLETED.
     *
     * @param scenarioName unique name for this scenario; use a per-test name to avoid cross-test state
     */
    public static void stubRegisterStatus(WireMockServer wm, String scenarioName) {
        wm.stubFor(post(urlEqualTo(REGISTER_STATUS))
                .inScenario(scenarioName)
                .whenScenarioStateIs(STATUS_SCENARIO_IN_PROGRESS)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"status": "inProgress", "certificateData": null, "meta": []}
                                """))
                .willSetStateTo(STATUS_SCENARIO_COMPLETED));

        wm.stubFor(post(urlEqualTo(REGISTER_STATUS))
                .inScenario(scenarioName)
                .whenScenarioStateIs(STATUS_SCENARIO_COMPLETED)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"status": "completed", "certificateData": null, "meta": []}
                                """)));
    }

    /**
     * Registers a stateless stub for the register-status endpoint that always returns IN_PROGRESS, for
     * timeout/max-attempts scenarios where the connector never completes.
     */
    public static void stubRegisterStatusAlwaysInProgress(WireMockServer wm) {
        wm.stubFor(post(urlEqualTo(REGISTER_STATUS))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"status": "inProgress", "certificateData": null, "meta": []}
                                """)));
    }

    // ---- v3 issue (register-bound issuance) ------------------------------

    /**
     * Stubs a synchronous v3 issue response (HTTP 200) returning the given base64 certificate data and empty meta.
     *
     * @param certData base64-encoded certificate DER bytes to include in the response
     */
    public static void stubV3IssueSync(WireMockServer wm, String certData) {
        wm.stubFor(post(urlEqualTo(ISSUE_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": "%s", "meta": []}
                                """.formatted(certData))));
    }

    /**
     * Stubs an asynchronous v3 issue response (HTTP 202) with empty meta.
     */
    public static void stubV3IssueAsync(WireMockServer wm) {
        wm.stubFor(post(urlEqualTo(ISSUE_PATH))
                .willReturn(aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": null, "meta": []}
                                """)));
    }

    // ---- Attribute list + validate (required by mergeAndValidateAttributes) ----

    /**
     * Stubs the v3 attribute-list and validate endpoints (certificate, authority, and RA-profile attributes) to return
     * empty lists / {@code true}, so {@code mergeAndValidateAttributes} succeeds without real attribute data.
     */
    public static void stubAttributesAndValidate(WireMockServer wm) {
        // v3 certificate attribute list endpoints
        wm.stubFor(post(urlMatching("/v3/authorityProvider/certificates/.*/attributes"))
                .willReturn(WireMock.okJson("[]")));
        wm.stubFor(get(urlMatching("/v3/authorityProvider/certificates/.*/attributes"))
                .willReturn(WireMock.okJson("[]")));
        // v3 authority attributes
        wm.stubFor(get(urlMatching("/v3/authorityProvider/attributes"))
                .willReturn(WireMock.okJson("[]")));
        wm.stubFor(post(urlMatching("/v3/authorityProvider/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        // v3 RA profile attributes
        wm.stubFor(get(urlMatching("/v3/authorityProvider/raProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        wm.stubFor(post(urlMatching("/v3/authorityProvider/raProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
    }
}
