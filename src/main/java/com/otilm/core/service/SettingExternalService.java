package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import com.otilm.api.model.core.settings.EventSettingsDto;
import com.otilm.api.model.core.settings.EventsSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;

public interface SettingExternalService {

    /**
     * Get platform settings
     *
     * @return platform settings {@link com.otilm.api.model.core.settings.PlatformSettingsDto}
     */
    PlatformSettingsDto getPlatformSettings();

    /**
     * Update platform settings
     *
     * @param platformSettings Platform settings DTO
     */
    void updatePlatformSettings(PlatformSettingsUpdateDto platformSettings);

    /**
     * Get the branding applied across the platform user interface
     *
     * @return branding settings {@link com.otilm.api.model.core.settings.BrandingSettingsDto}
     */
    BrandingSettingsDto getBrandingSettings();

    /**
     * Update the branding applied across the platform user interface. A {@code null} field clears that part of the
     * branding, so a caller sends the full desired state rather than only the fields it wants to change.
     *
     * @param brandingSettings Branding settings DTO
     */
    void updateBrandingSettings(BrandingSettingsUpdateDto brandingSettings);

    EventsSettingsDto getEventsSettings();

    void updateEventsSettings(EventsSettingsDto eventsSettingsDto) throws NotFoundException;

    void updateEventSettings(EventSettingsDto eventSettingsDto) throws NotFoundException;

    AuthenticationSettingsDto getAuthenticationSettings(boolean withClientSecret);

    void updateAuthenticationSettings(AuthenticationSettingsUpdateDto authenticationSettingsDto);

    OAuth2ProviderSettingsResponseDto getOAuth2ProviderSettings(String providerName, boolean withClientSecret);

    void updateOAuth2ProviderSettings(String providerName, OAuth2ProviderSettingsUpdateDto providerSettings);

    void removeOAuth2Provider(String providerName);

    LoggingSettingsDto getLoggingSettings();

    void updateLoggingSettings(LoggingSettingsDto loggingSettingsDto);

}
