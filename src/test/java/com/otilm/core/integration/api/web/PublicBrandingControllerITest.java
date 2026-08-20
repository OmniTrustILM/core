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
import java.util.stream.Collectors;
import java.util.stream.Stream;
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

    private static final String DEFAULT_THEME = "defaultTheme";

    /**
     * The keys the response carries whatever is configured. {@code defaultTheme} is deliberately not among them: it
     * resolves to a {@code $ref} on the shared {@code BrandingTheme} schema, which cannot be declared nullable, so
     * {@code PublicBrandingDto} omits it when unset rather than sending it as null.
     */
    private static final Set<String> ALWAYS_PRESENT_KEYS = Set
            .of("configured", "primaryColor", "secondaryColor", "tertiaryColor", "backgroundColor", "textColor",
                    "lightLogo", "darkLogo");

    /** Everything the anonymous response is allowed to carry. A key outside this set is a leak, not a feature. */
    private static final Set<String> PERMITTED_KEYS = Stream
            .concat(ALWAYS_PRESENT_KEYS.stream(), Stream.of(DEFAULT_THEME))
            .collect(Collectors.toUnmodifiableSet());

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

    /**
     * An unbranded instance is a normal state, not an error: the client applies the platform's own look. {@code
     * configured} is asserted to be a present boolean rather than merely falsy, because a primitive field behind
     * {@code @JsonInclude(ALWAYS)} is the only reason the key cannot go missing on the path where there is no branding
     * to map at all.
     */
    @Test
    void anUnbrandedInstanceReportsUnconfiguredBrandingRatherThanFailing() throws Exception {
        JsonNode response = fetchBranding();

        Assertions.assertTrue(response.path("configured").isBoolean(), response.toString());
        Assertions.assertFalse(response.get("configured").asBoolean());
        Assertions.assertTrue(response.get("primaryColor").isNull());
        Assertions.assertTrue(response.get("lightLogo").isNull());
    }

    /**
     * The whole point of a purpose-built response type. Asserted as an exact key set rather than by spot-checking, so a
     * settings field that finds its way into this DTO fails the build instead of reaching anonymous callers. A theme is
     * configured here so that the fullest response the endpoint can produce is the one held to the set.
     */
    @Test
    void theResponseCarriesExactlyTheBrandingKeysAndNothingElse() throws Exception {
        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setPrimaryColor("#0073CF");
        branding.setDefaultTheme(BrandingTheme.LIGHT);
        cacheBranding(branding);

        Set<String> keys = keysOf(fetchBranding());

        Assertions.assertEquals(PERMITTED_KEYS, keys);
    }

    /**
     * The one key that comes and goes, pinned so that the omission is a decision on record rather than something a
     * client discovers. Absence is representable in every generated client; null on a required {@code $ref} is
     * representable in none, which is why it is spelled this way round.
     */
    @Test
    void defaultThemeIsAbsentRatherThanNullWhenNoThemeIsConfigured() throws Exception {
        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setPrimaryColor("#0073CF");
        cacheBranding(branding);

        JsonNode response = fetchBranding();

        Assertions.assertFalse(response.has(DEFAULT_THEME), response.toString());
        Assertions.assertEquals(ALWAYS_PRESENT_KEYS, keysOf(response));
    }

    /**
     * Unset colours and logos stay in the response as explicit nulls, so a client can read any of them without testing
     * for the key first. {@code defaultTheme} is the documented exception and is taken out before the comparison —
     * without that, this passed only because neither side of it configured a theme.
     */
    @Test
    void theResponseKeepsTheSameShapeWhetherOrNotBrandingIsConfigured() throws Exception {
        Set<String> unbranded = keysOf(fetchBranding());

        BrandingSettingsDto branding = new BrandingSettingsDto();
        branding.setTextColor("#171717");
        branding.setDefaultTheme(BrandingTheme.DARK);
        cacheBranding(branding);

        Set<String> branded = keysOf(fetchBranding());
        branded.remove(DEFAULT_THEME);

        Assertions.assertEquals(ALWAYS_PRESENT_KEYS, unbranded);
        Assertions.assertEquals(ALWAYS_PRESENT_KEYS, branded);
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
