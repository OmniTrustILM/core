package com.czertainly.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.SettingController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.settings.*;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.SettingService;
import com.czertainly.core.util.converter.SettingsSectionCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SettingControllerImpl implements SettingController {

    private SettingService settingService;

    @Autowired
    public void setSettingService(SettingService settingService) {
        this.settingService = settingService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(SettingsSection.class, new SettingsSectionCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.DETAIL, name = "platform")
    public PlatformSettingsDto getPlatformSettings() {
        return settingService.getPlatformSettings();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.UPDATE, name = "platform")
    public void updatePlatformSettings(PlatformSettingsUpdateDto request) {
        settingService.updatePlatformSettings(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.DETAIL, name = "events")
    public EventsSettingsDto getEventsSettings() {
        return settingService.getEventsSettings();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.UPDATE, name = "events")
    public void updateEventsSettings(EventsSettingsDto eventsSettingsDto) throws NotFoundException {
        settingService.updateEventsSettings(eventsSettingsDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.UPDATE, name = "events")
    public void updateEventSettings(EventSettingsDto eventSettingsDto) throws NotFoundException {
        settingService.updateEventSettings(eventSettingsDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.DETAIL, name = "authentication")
    public AuthenticationSettingsDto getAuthenticationSettings() {
        return settingService.getAuthenticationSettings(false);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.UPDATE, name = "authentication")
    public void updateAuthenticationSettings(AuthenticationSettingsUpdateDto authenticationSettingsDto) {
        settingService.updateAuthenticationSettings(authenticationSettingsDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, affiliatedResource = Resource.AUTHENTICATION_PROVIDER, operation = Operation.DETAIL, name = "authentication")
    public OAuth2ProviderSettingsResponseDto getOAuth2ProviderSettings(@LogResource(name = true, affiliated = true) String providerName) {
        return settingService.getOAuth2ProviderSettings(providerName, false);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, affiliatedResource = Resource.AUTHENTICATION_PROVIDER, operation = Operation.UPDATE, name = "authentication")
    public void updateOAuth2ProviderSettings(@LogResource(name = true, affiliated = true) String providerName, OAuth2ProviderSettingsUpdateDto oauth2SettingsDto) {
        settingService.updateOAuth2ProviderSettings(providerName, oauth2SettingsDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, affiliatedResource = Resource.AUTHENTICATION_PROVIDER, operation = Operation.DELETE, name = "authentication")
    public void removeOAuth2Provider(@LogResource(name = true, affiliated = true) String providerName) {
        settingService.removeOAuth2Provider(providerName);
    }

    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.DETAIL, name = "logging")
    public LoggingSettingsDto getLoggingSettings() {
        return settingService.getLoggingSettings();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SETTINGS, operation = Operation.UPDATE, name = "logging")
    public void updateLoggingSettings(LoggingSettingsDto loggingSettingsDto) {
        settingService.updateLoggingSettings(loggingSettingsDto);
    }
}
