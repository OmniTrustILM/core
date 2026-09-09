package com.otilm.core.service.impl;

import com.otilm.api.model.core.branding.PublicBrandingDto;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.BrandingTheme;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.settings.SettingsCache;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.mockito.Mockito.mockStatic;

/**
 * Covers the mapping without a Spring context, which also states the property the endpoint depends on: the settings
 * cache is the service's only source, so answering a page load costs no database query. There is no repository to reach
 * for here — the service has no collaborator at all.
 */
class BrandingServiceImplTest {

    private final BrandingServiceImpl service = new BrandingServiceImpl();

    /** Before the first cache load there is no platform section at all, and the endpoint still has to answer. */
    @Test
    void anEmptyCacheReportsUnconfiguredBranding() {
        PublicBrandingDto branding = withCachedPlatformSettings(null);

        Assertions.assertFalse(branding.isConfigured());
        Assertions.assertNull(branding.getPrimaryColor());
    }

    /** Platform settings exist but carry no branding section — the state of every instance that has never branded. */
    @Test
    void platformSettingsWithoutABrandingSectionReportUnconfiguredBranding() {
        PublicBrandingDto branding = withCachedPlatformSettings(new PlatformSettingsDto());

        Assertions.assertFalse(branding.isConfigured());
    }

    /** A branding section every field of which is unset is not "configured": the client applies the platform's look. */
    @Test
    void aBrandingSectionWithNoValuesSetReportsUnconfiguredBranding() {
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setBranding(new BrandingSettingsDto());

        Assertions.assertFalse(withCachedPlatformSettings(platform).isConfigured());
    }

    /** One field is enough. A theme on its own carries no colour, so it has to count as much as a colour does. */
    @Test
    void aThemeOnItsOwnIsEnoughToCountAsConfigured() {
        BrandingSettingsDto settings = new BrandingSettingsDto();
        settings.setDefaultTheme(BrandingTheme.DARK);

        PublicBrandingDto branding = withCachedBranding(settings);

        Assertions.assertTrue(branding.isConfigured());
        Assertions.assertEquals(BrandingTheme.DARK, branding.getDefaultTheme());
    }

    /** Every field is carried across verbatim; a field silently dropped here reaches the login page as a default. */
    @Test
    void everyBrandingFieldIsCarriedIntoTheResponse() {
        BrandingSettingsDto settings = new BrandingSettingsDto();
        settings.setPrimaryColor("#0073CF");
        settings.setSecondaryColor("#00B0F0");
        settings.setBackgroundColor("#FFFFFF");
        settings.setTextColor("#171717");
        settings.setLightLogo("data:image/png;base64,light");
        settings.setDarkLogo("data:image/png;base64,dark");
        settings.setDefaultTheme(BrandingTheme.LIGHT);

        PublicBrandingDto branding = withCachedBranding(settings);

        Assertions.assertTrue(branding.isConfigured());
        Assertions.assertEquals("#0073CF", branding.getPrimaryColor());
        Assertions.assertEquals("#00B0F0", branding.getSecondaryColor());
        Assertions.assertEquals("#FFFFFF", branding.getBackgroundColor());
        Assertions.assertEquals("#171717", branding.getTextColor());
        Assertions.assertEquals("data:image/png;base64,light", branding.getLightLogo());
        Assertions.assertEquals("data:image/png;base64,dark", branding.getDarkLogo());
        Assertions.assertEquals(BrandingTheme.LIGHT, branding.getDefaultTheme());
    }

    private PublicBrandingDto withCachedBranding(BrandingSettingsDto settings) {
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setBranding(settings);
        return withCachedPlatformSettings(platform);
    }

    /**
     * The cache is static, so it is stubbed for the duration of the call rather than written to — a value left behind
     * would be read by every later test sharing the JVM.
     */
    private PublicBrandingDto withCachedPlatformSettings(PlatformSettingsDto platform) {
        try (MockedStatic<SettingsCache> cache = mockStatic(SettingsCache.class)) {
            cache.when(() -> SettingsCache.getSettings(SettingsSection.PLATFORM)).thenReturn(platform);
            return service.getPublicBranding();
        }
    }
}
