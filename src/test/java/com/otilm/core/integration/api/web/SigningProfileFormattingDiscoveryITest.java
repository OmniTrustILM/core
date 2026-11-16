package com.otilm.core.integration.api.web;

import com.otilm.api.model.common.validation.SignatureFamilyFormat;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Covers the wire form of the content-signing formatting discovery route. A service-level test cannot observe it. */
@AutoConfigureMockMvc
class SigningProfileFormattingDiscoveryITest extends BaseSpringBootTest {

    private static final String PATH = "/v1/signingProfiles/signatureFormattingConnectors/%s/contentSigningFormattingAttributes";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void contentSigningFormattingAttributes_bindsTheFamilyAndLevelWireCodes() throws Exception {
        mockMvc
                .perform(get(PATH.formatted(UUID.randomUUID())).param("family", "pades").param("maxLevel", "signed"))
                .andExpect(status().isNotFound());
    }

    @Test
    void returnsBadRequest_whenTheFamilyCodeIsMalformed() throws Exception {
        // given
        var uppercaseFamily = "PAdES";

        // when
        ResultActions response = mockMvc
                .perform(get(PATH.formatted(UUID.randomUUID()))
                        .param("family", uppercaseFamily)
                        .param("maxLevel", "signed"));

        // then
        response
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString(SignatureFamilyFormat.MESSAGE)));
    }
}
