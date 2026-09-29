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
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The CBOM-scoped asset listing over HTTP: both gates refuse with the platform's 403, an unknown CBOM is a 404, and the
 * permitted response carries the refs without any of the fenced vocabulary.
 */
@AutoConfigureMockMvc
class CbomContributedAssetsHttpITest extends BaseSpringBootTest {

    private static final Pattern IDENTITY_KEY = Pattern
            .compile("identity[_\\-\\s]?key|absorbed[_\\-\\s]?key|canonical[_\\-\\s]?key", Pattern.CASE_INSENSITIVE);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomAssetIngestService ingestService;

    private UUID cbomUuid;

    @BeforeEach
    void seedOneContribution() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:http");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        cbomUuid = cbomRepository.save(cbom).getUuid();
        assertThat(ingestService
                .ingest(cbomUuid,
                        CbomIngestTestFixtures
                                .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "aes-ref")),
                        OffsetDateTime.parse("2026-09-29T10:00:00Z"), CbomSyncPolicy.DEFAULTS))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
    }

    private static String endpoint(UUID uuid) {
        return "/v1/cboms/" + uuid + "/assets";
    }

    @Test
    void refusesWhenDetailAccessToTheCbomIsDenied() throws Exception {
        denyResourceAccess(Resource.CBOM, ResourceAction.DETAIL);

        mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'CBOM'")));
    }

    @Test
    void refusesWhenListingCryptographicAssetsIsDenied() throws Exception {
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.LIST);

        mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'Cryptographic Asset'")));
    }

    /** The CBOM lookup's own 404, told apart by its message from the one a request to no mapped route gets. */
    @Test
    void anUnknownCbomIsNotFound() throws Exception {
        UUID unknown = UUID.randomUUID();

        mockMvc
                .perform(post(endpoint(unknown)).contentType("application/json").content("{}"))
                .andExpectAll(status().isNotFound(), jsonPath("$.message")
                        .value(allOf(containsString("'Cbom'"), containsString(unknown.toString()))));
    }

    @Test
    void servesTheRowsWithTheirRefsWithoutMentioningTheKey() throws Exception {
        String body = mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isOk(), jsonPath("$.totalItems").value(1),
                        jsonPath("$.items[0].name").value("aes-256"), jsonPath("$.items[0].sourceCbomCount").value(1),
                        jsonPath("$.items[0].bomRefs[0]").value("aes-ref"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(body).doesNotContainPattern(IDENTITY_KEY);
    }
}
