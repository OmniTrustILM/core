package com.otilm.core.integration.api.web;

import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers the wire form of the content-signing formatting discovery route. The published contract lists the lowercase
 * enum codes, so binding them is contract, and a service-level test cannot observe it.
 */
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
    void contentSigningFormattingAttributes_rejectsAFamilyOutsideThePublishedVocabulary() throws Exception {
        mockMvc
                .perform(get(PATH.formatted(UUID.randomUUID()))
                        .param("family", "not-a-family")
                        .param("maxLevel", "signed"))
                .andExpect(status().is4xxClientError());
    }
}
