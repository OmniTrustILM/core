package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The CBOM ingest report over HTTP: the detail gate refuses with the platform's 403, an unknown CBOM is a 404, and the
 * permitted response names the member a secret was inlined under without carrying the value anywhere in the body.
 */
@AutoConfigureMockMvc
class CbomIngestFindingsHttpITest extends BaseSpringBootTest {

    private static final String SECRET_MARKER = "AKIA-SECRET-MARKER";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomAssetIngestService ingestService;

    private UUID cbomUuid;

    @BeforeEach
    void seedOneReport() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:http-report");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        cbomUuid = cbomRepository.save(cbom).getUuid();
        assertThat(ingestService
                .ingest(cbomUuid,
                        CbomIngestTestFixtures
                                .read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a-signing-key\","
                                        + "\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                                        + "\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"value\":\""
                                        + SECRET_MARKER + "\"}}}]}"),
                        OffsetDateTime.parse("2026-10-15T10:00:00Z"), CbomSyncPolicy.DEFAULTS))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
    }

    private static String endpoint(UUID uuid) {
        return "/v1/cboms/" + uuid + "/ingestFindings";
    }

    @Test
    void refusesWhenDetailAccessToTheCbomIsDenied() throws Exception {
        denyResourceAccess(Resource.CBOM, ResourceAction.DETAIL);

        mockMvc
                .perform(get(endpoint(cbomUuid)))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'CBOM'")));
    }

    @Test
    void anUnknownCbomIsNotFound() throws Exception {
        UUID unknown = UUID.randomUUID();

        mockMvc
                .perform(get(endpoint(unknown)))
                .andExpectAll(status().isNotFound(), jsonPath("$.message")
                        .value(allOf(containsString("'Cbom'"), containsString(unknown.toString()))));
    }

    @Test
    void servesTheReportNamingTheMemberAndNeverTheValue() throws Exception {
        String body = mockMvc
                .perform(get(endpoint(cbomUuid)))
                .andExpectAll(status().isOk(), jsonPath("$.length()").value(1), jsonPath("$[0].kind").value("finding"),
                        jsonPath("$[0].componentName").value("a-signing-key"),
                        jsonPath("$[0].detail").value(containsString("under member value")),
                        jsonPath("$[0].occurrences").value(1), jsonPath("$[0].recordedAt").isString())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(body).doesNotContain(SECRET_MARKER);
    }
}
