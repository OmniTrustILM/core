package com.otilm.core.service.impl;

import com.otilm.api.model.core.branding.PublicBrandingDto;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.security.authz.UnauthenticatedEndpoint;
import com.otilm.core.service.BrandingExternalService;
import com.otilm.core.settings.SettingsCache;
import java.util.Objects;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;

/**
 * Serves the branding an unauthenticated caller may read.
 *
 * <p>
 * This is the platform's first anonymous endpoint carrying operator-configured content, so the response is assembled
 * field by field into a purpose-built DTO. Returning the settings DTO — or a subclass of it — would mean every field
 * later added to platform settings is served to anonymous callers by default, and nobody would have decided that.
 */
@Service
public class BrandingServiceImpl implements BrandingExternalService {

    @Override
    @UnauthenticatedEndpoint
    public PublicBrandingDto getPublicBranding() {
        PlatformSettingsDto platform = SettingsCache.getSettings(SettingsSection.PLATFORM);
        return toPublicBranding(platform == null ? null : platform.getBranding());
    }

    /**
     * Reads through the settings cache, which is populated at startup and on the configured refresh interval, so a page
     * load costs no database query. A cache that has not been populated yet reports unconfigured branding rather than
     * failing: the login page then renders the platform's own identity, which is what it did before branding existed.
     */
    private static PublicBrandingDto toPublicBranding(BrandingSettingsDto branding) {
        PublicBrandingDto publicBranding = new PublicBrandingDto();
        if (branding == null) {
            return publicBranding;
        }

        publicBranding.setPrimaryColor(branding.getPrimaryColor());
        publicBranding.setSecondaryColor(branding.getSecondaryColor());
        publicBranding.setTertiaryColor(branding.getTertiaryColor());
        publicBranding.setBackgroundColor(branding.getBackgroundColor());
        publicBranding.setTextColor(branding.getTextColor());
        publicBranding.setLightLogo(branding.getLightLogo());
        publicBranding.setDarkLogo(branding.getDarkLogo());
        publicBranding.setDefaultTheme(branding.getDefaultTheme());
        publicBranding.setConfigured(isConfigured(branding));
        return publicBranding;
    }

    /**
     * One flag rather than making the client work it out: on an unbranded instance every field is null, and a client
     * that cannot tell "nothing configured" from "response not understood" would have to guess which look to apply.
     */
    private static boolean isConfigured(BrandingSettingsDto branding) {
        return Stream
                .of(branding.getPrimaryColor(), branding.getSecondaryColor(), branding.getTertiaryColor(),
                        branding.getBackgroundColor(), branding.getTextColor(), branding.getLightLogo(),
                        branding.getDarkLogo(), branding.getDefaultTheme())
                .anyMatch(Objects::nonNull);
    }
}
