package com.otilm.core.integration.api.web;

import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CertificateListingPageSizeHttpITest extends BaseSpringBootTest {

    private static final String ENDPOINT = "/v1/certificates";

    @Autowired
    private MockMvc mockMvc;

    private static String body(int itemsPerPage) {
        return "{\"itemsPerPage\": " + itemsPerPage + ", \"pageNumber\": 1, \"filters\": []}";
    }

    @Test
    void aPageSizeAboveTheDocumentedMaximumIsRefusedNamingTheLimit() throws Exception {
        mockMvc
                .perform(post(ENDPOINT).contentType("application/json").content(body(1001)))
                .andExpectAll(status().isUnprocessableEntity(),
                        jsonPath("$[0]").value("Items per page must be at most 1000, but was 1001"));
    }

    @Test
    void thePageSizeAtTheDocumentedMaximumIsServed() throws Exception {
        mockMvc
                .perform(post(ENDPOINT).contentType("application/json").content(body(1000)))
                .andExpectAll(status().isOk(), jsonPath("$.itemsPerPage").value(1000));
    }

    @Test
    void aPageSizeBelowOneIsRefusedWithAReadableMessage() throws Exception {
        mockMvc
                .perform(post(ENDPOINT).contentType("application/json").content(body(0)))
                .andExpectAll(status().isUnprocessableEntity(),
                        jsonPath("$[0]").value("Items per page must be at least 1, but was 0"));
    }
}
