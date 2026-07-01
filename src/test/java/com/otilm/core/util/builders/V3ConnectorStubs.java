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
 * WireMock stub helpers for the v3 authority provider wire contract.
 *
 * <p>Each static method registers one or more stubs on the supplied {@link WireMockServer} for a
 * specific v3 connector endpoint. All paths are taken directly from the S6 wire-contract reference
 * and the {@code CertificateApiClient} v3 constants:
 *
 * <ul>
 *   <li>REGISTER  — POST /v3/authorityProvider/certificates/register</li>
 *   <li>REGISTER STATUS — POST /v3/authorityProvider/certificates/register/status</li>
 *   <li>REGISTER CANCEL — POST /v3/authorityProvider/certificates/register/cancel</li>
 *   <li>V2 ISSUE (tail call) — POST /v2/authorityProvider/authorities/{uuid}/certificates/issue</li>
 *   <li>ATTRIBUTES/VALIDATE — GET/POST for list and validate endpoints (returns empty / true)</li>
 * </ul>
 *
 * <p>The status stub uses WireMock scenario state so a test can simulate a multi-poll sequence
 * (first call returns IN_PROGRESS, second returns COMPLETED). The scenario name is a parameter
 * so multiple independent tests do not share state.
 */
public final class V3ConnectorStubs {

    // ---- endpoint paths (from CertificateApiClient v3 constants) ----

    private static final String REGISTER_PATH   = "/v3/authorityProvider/certificates/register";
    public static final String REGISTER_STATUS = "/v3/authorityProvider/certificates/register/status";

    // State names for the stateful register-status scenario.
    public static final String STATUS_SCENARIO_IN_PROGRESS = Scenario.STARTED;
    public static final String STATUS_SCENARIO_COMPLETED   = "COMPLETED";

    private V3ConnectorStubs() {}

    // ---- Register -------------------------------------------------------

    /**
     * Stubs a synchronous register response (HTTP 200).
     *
     * @param wm       the WireMock server to register the stub on
     * @param metaJson JSON array of MetadataAttribute objects, or {@code "[]"} if none.
     *                 Use {@code null} or {@code "[]"} for a meta-free response.
     */
    public static void stubRegisterSync(WireMockServer wm, String metaJson) {
        String safeMetaJson = (metaJson == null || metaJson.isBlank()) ? "[]" : metaJson;
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
     * @param wm            the WireMock server to register the stub on
     * @param trackingMeta  JSON array of MetadataAttribute tracking objects returned by the connector.
     *                      Pass {@code null} or {@code "[]"} for an empty-meta async response.
     */
    public static void stubRegisterAsync(WireMockServer wm, String trackingMeta) {
        String safeMeta = (trackingMeta == null || trackingMeta.isBlank()) ? "[]" : trackingMeta;
        wm.stubFor(post(urlEqualTo(REGISTER_PATH))
                .willReturn(aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": null, "meta": %s}
                                """.formatted(safeMeta))));
    }

    // ---- Register status (stateful scenario) ----------------------------

    /**
     * Registers a two-state stateful stub for the register-status endpoint.
     *
     * <ul>
     *   <li>State {@code STARTED} → returns {@code IN_PROGRESS}; transitions to {@code COMPLETED}.</li>
     *   <li>State {@code COMPLETED} → returns {@code COMPLETED} with {@code certificateData: null}
     *       (this stub carries no certificate content).</li>
     * </ul>
     *
     * @param wm           the WireMock server to register the stub on
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
     * Registers a stateless stub for the register-status endpoint that always returns
     * {@code IN_PROGRESS}. Use for timeout/max-attempts scenarios where the connector
     * never completes the operation.
     *
     * @param wm the WireMock server to register the stub on
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

    // ---- v2 issue (tail call from issueCertificateAction) ---------------

    /**
     * Stubs the v2 issue endpoint used by {@code issueCertificateAction} (HTTP 200).
     *
     * <p>The URL pattern covers any authority UUID segment:
     * {@code /v2/authorityProvider/authorities/{uuid}/certificates/issue}.</p>
     *
     * @param wm       the WireMock server to register the stub on
     * @param certData base64-encoded certificate DER bytes to include in the response
     */
    public static void stubV2Issue(WireMockServer wm, String certData) {
        wm.stubFor(post(urlMatching(
                "/v2/authorityProvider/authorities/[^/]+/certificates/issue"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"certificateData": "%s"}
                                """.formatted(certData))));
    }

    // ---- Attribute list + validate (required by mergeAndValidateAttributes) ----

    /**
     * Stubs the v3 attribute-list and validate endpoints (issue/revoke/register attributes, authority
     * attributes, and RA-profile attributes) to return empty lists / {@code true}, so service-layer
     * calls to {@code mergeAndValidateAttributes} succeed without any real attribute data.
     *
     * @param wm the WireMock server to register the stubs on
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
