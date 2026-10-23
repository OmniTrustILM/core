package com.otilm.core.integration.api.web;

import com.otilm.api.model.connector.cryptography.v2.key.ListKeysRequestV2Dto;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class TokenKeyListingPageHttpITest extends BaseSpringBootTest {

    private static final UUID TOKEN_PROFILE_UUID = UUID.randomUUID();

    @Autowired
    private MockMvc mockMvc;

    private static String endpoint() {
        return "/v1/tokens/" + UUID.randomUUID() + "/tokenProfiles/" + TOKEN_PROFILE_UUID + "/tokenKeys";
    }

    @Test
    void aPageNumberBelowOneIsRefusedNamingTheBound() throws Exception {
        mockMvc
                .perform(get(endpoint()).param("pageNumber", "0"))
                .andExpectAll(status().isBadRequest(),
                        jsonPath("$.message").value("Validation error: pageNumber must be at least 1"));
    }

    @Test
    void aPageSizeBelowOneIsRefusedNamingTheBound() throws Exception {
        mockMvc
                .perform(get(endpoint()).param("itemsPerPage", "0"))
                .andExpectAll(status().isBadRequest(),
                        jsonPath("$.message").value("Validation error: itemsPerPage must be at least 1"));
    }

    @Test
    void aPageSizeAboveOneListingPageIsRefusedNamingTheLimit() throws Exception {
        mockMvc
                .perform(get(endpoint()).param("itemsPerPage", String.valueOf(ListKeysRequestV2Dto.MAX_LIMIT + 1)))
                .andExpectAll(status().isBadRequest(), jsonPath("$.message")
                        .value("Validation error: itemsPerPage must be at most " + ListKeysRequestV2Dto.MAX_LIMIT));
    }

    /** The token profile lookup's 404 shows the request passed validation. */
    @Test
    void aPageSizeOfOneListingPageReachesTheTokenProfileLookup() throws Exception {
        mockMvc
                .perform(get(endpoint()).param("itemsPerPage", String.valueOf(ListKeysRequestV2Dto.MAX_LIMIT)))
                .andExpectAll(status().isNotFound(),
                        jsonPath("$.message").value(containsString(TOKEN_PROFILE_UUID.toString())));
    }
}
