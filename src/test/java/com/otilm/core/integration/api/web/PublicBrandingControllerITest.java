package com.otilm.core.integration.api.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.BrandingTheme;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTestNoAuth;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Drives {@code GET /v1/branding} through the real filter chain with no credentials attached, which is the only way to
 * show that the permit-all entry and the controller agree.
 */
@AutoConfigureMockMvc
@TestPropertySource(properties = "server.servlet.context-path=")
class PublicBrandingControllerITest extends BaseSpringBootTestNoAuth {

    private static final String PATH = "/v1/branding";

    /** Everything the anonymous response is allowed to carry. A key outside this set is a leak, not a feature. */
    private static final Set<String> EXPECTED_KEYS = Set
            .of("configured", "primaryColor", "secondaryColor", "tertiaryColor", "backgroundColor", "textColor",
                    "lightLogo", "darkLogo", "defaultTheme");

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private SettingsCache settingsCache;

    @MockitoSpyBean
    private SettingRepository settingRepository;

    @BeforeEach
    void clearBranding() {
        settingsCache.cacheSettings(SettingsSection.PLATFORM, new PlatformSettingsDto());
        // The repository is exercised while the context starts; only what this test triggers is of interest.
        clearInvocations(settingRepository);
    }

    private void cacheBranding(BrandingSettingsDto branding) {
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setBranding(branding);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, platform);
    }

    private JsonNode fetchBranding() throws Exception {
        String body = mvc.perform(get(PATH)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(body);
    }

    @Test
    void brandingIsServedWithoutAuthentication() throws Exception {
        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setPrimaryColor("#0073CF");
        branding.setDefaultTheme(BrandingTheme.DARK);
        cacheBranding(branding);

        JsonNode response = fetchBranding();

        Assertions.assertTrue(response.get("configured").asBoolean());
        Assertions.assertEquals("#0073CF", response.get("primaryColor").asText());
        Assertions.assertEquals("dark", response.get("defaultTheme").asText());
    }

    /** An unbranded instance is a normal state, not an error: the client applies the platform's own look. */
    @Test
    void anUnbrandedInstanceReportsUnconfiguredBrandingRatherThanFailing() throws Exception {
        JsonNode response = fetchBranding();

        Assertions.assertFalse(response.get("configured").asBoolean());
        Assertions.assertTrue(response.get("primaryColor").isNull());
        Assertions.assertTrue(response.get("lightLogo").isNull());
    }

    /**
     * The whole point of a purpose-built response type. Asserted as an exact key set rather than by spot-checking, so a
     * settings field that finds its way into this DTO fails the build instead of reaching anonymous callers.
     */
    @Test
    void theResponseCarriesExactlyTheBrandingKeysAndNothingElse() throws Exception {
        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setPrimaryColor("#0073CF");
        cacheBranding(branding);

        Set<String> keys = keysOf(fetchBranding());

        Assertions.assertEquals(EXPECTED_KEYS, keys);
    }

    /** Unset fields stay in the response as explicit nulls, so the shape does not depend on what is configured. */
    @Test
    void theResponseKeepsTheSameShapeWhetherOrNotBrandingIsConfigured() throws Exception {
        Set<String> unbranded = keysOf(fetchBranding());

        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setTextColor("#171717");
        cacheBranding(branding);

        Assertions.assertEquals(unbranded, keysOf(fetchBranding()));
    }

    /** Every page load hits this, so it must be answered from the settings cache and not from the database. */
    @Test
    void theEndpointIssuesNoDatabaseQuery() throws Exception {
        fetchBranding();

        verifyNoInteractions(settingRepository);
    }

    /**
     * 400 rather than 405 because {@code ExceptionHandlingAdvice} maps an unsupported method that way for the whole
     * API; what matters here is that no write ever reaches a handler, since the controller declares only a GET.
     */
    @Test
    void theEndpointIsReadOnly() throws Exception {
        mvc.perform(post(PATH)).andExpect(status().isBadRequest());
        mvc.perform(put(PATH)).andExpect(status().isBadRequest());
        mvc.perform(delete(PATH)).andExpect(status().isBadRequest());
    }

    private Set<String> keysOf(JsonNode node) {
        Set<String> keys = new HashSet<>();
        node.fieldNames().forEachRemaining(keys::add);
        return keys;
    }
}
