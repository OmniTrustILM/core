package com.otilm.core.integration.api.web;

import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class SettingControllerBrandingITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * The documented status, asserted over HTTP rather than read off the annotation: {@code @ApiResponse} only shapes
     * the OpenAPI document, so a void handler without {@code @ResponseStatus} would answer 200 and the contract and the
     * runtime would disagree.
     */
    @Test
    void updateBranding_answersNoContent() throws Exception {
        mockMvc
                .perform(put("/v1/settings/platform/branding")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"primaryColor\":\"#0073CF\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void updateBranding_rejectsAnInvalidColor() throws Exception {
        mockMvc
                .perform(put("/v1/settings/platform/branding")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"primaryColor\":\"chartreuse\"}"))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void getBranding_answersTheStoredBranding() throws Exception {
        mockMvc
                .perform(put("/v1/settings/platform/branding")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"primaryColor\":\"#0073CF\",\"defaultTheme\":\"dark\"}"))
                .andExpect(status().isNoContent());

        mockMvc
                .perform(get("/v1/settings/platform/branding"))
                .andExpectAll(status().isOk(), jsonPath("$.primaryColor").value("#0073CF"),
                        jsonPath("$.defaultTheme").value("dark"));
    }
}
