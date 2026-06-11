package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.settings.*;
import com.otilm.api.model.core.settings.authentication.*;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.service.SettingService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import com.otilm.core.settings.SettingsCache;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service("settingService")
@Transactional
public class SettingServiceImpl implements SettingService {
    public static final String UTILS_SERVICE_URL_NAME = "utilsServiceUrl";
    public static final String CBOM_REPOSITORY_URL_NAME = "cbomRepositoryUrl";
    public static final String CERTIFICATES_VALIDATION_SETTINGS_NAME = "certificatesValidation";

    public static final String LOGGING_AUDIT_LOG_OUTPUT_NAME = "output";
    public static final String LOGGING_AUDIT_LOG_VERBOSE_NAME = "verbose";
    public static final String LOGGING_RESOURCES_NAME = "resources";

    public static final String AUTHENTICATION_DISABLE_LOCALHOST_NAME = "disableLocalhostUser";

    private static final String DESERIALIZATION_ERROR_MESSAGE = "Cannot deserialize OAuth2 Provider Settings for provider '%s'.";
    private static final Logger logger = LoggerFactory.getLogger(SettingServiceImpl.class);

    private final ObjectMapper mapper;
    private final SettingsCache settingsCache;
    private final SettingRepository settingRepository;

    private TriggerExternalService triggerService;
    private TriggerInternalService triggerInternalService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public SettingServiceImpl(SettingsCache settingsCache, SettingRepository settingRepository, ObjectMapper mapper) {
        this.mapper = mapper;
        this.settingsCache = settingsCache;
        this.settingRepository = settingRepository;
    }

    @Autowired
    public void setTriggerService(TriggerExternalService triggerService) {
        this.triggerService = triggerService;
    }

    @Autowired
    public void setTriggerInternalService(TriggerInternalService triggerInternalService) {
        this.triggerInternalService = triggerInternalService;
    }

    @PostConstruct
    public void initCache() {
        refreshCache();
    }

    @Scheduled(fixedRateString = "${settings.cache.refresh-interval}", timeUnit = TimeUnit.SECONDS, initialDelayString = "${settings.cache.refresh-interval}")
    public void refreshCache() {
        settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettings());
        settingsCache.cacheSettings(SettingsSection.LOGGING, getLoggingSettings());
        settingsCache.cacheSettings(SettingsSection.EVENTS, loadEventsSettings());
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public PlatformSettingsDto getPlatformSettings() {
        List<Setting> settings = settingRepository.findBySection(SettingsSection.PLATFORM);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        PlatformSettingsDto platformSettings = new PlatformSettingsDto();
        // Utils
        Map<String, Setting> utilsSettings = mappedSettings.get(SettingsSectionCategory.PLATFORM_UTILS.getCode());
        UtilsSettingsDto utilsSettingsDto = new UtilsSettingsDto();
        if (utilsSettings != null) {
            Setting utilsServiceSetting = utilsSettings.get(UTILS_SERVICE_URL_NAME);
            if (utilsServiceSetting != null) {
                utilsSettingsDto.setUtilsServiceUrl(utilsServiceSetting.getValue());
            }
            Setting cbomRepositorySetting = utilsSettings.get(CBOM_REPOSITORY_URL_NAME);
            if (cbomRepositorySetting != null) {
                utilsSettingsDto.setCbomRepositoryUrl(cbomRepositorySetting.getValue());
            }
        }
        platformSettings.setUtils(utilsSettingsDto);

        // Certificates
        Map<String, Setting> certificateSettings = mappedSettings.get(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        CertificateSettingsDto certificateSettingsDto = new CertificateSettingsDto();
        CertificateValidationSettingsDto defaultValidationSettings = new CertificateValidationSettingsDto();
        defaultValidationSettings.setEnabled(true);
        defaultValidationSettings.setFrequency(1);
        defaultValidationSettings.setExpiringThreshold(30);

        if (certificateSettings != null && certificateSettings.get(CERTIFICATES_VALIDATION_SETTINGS_NAME) != null) {
            try {
                certificateSettingsDto.setValidation(objectMapper.readValue(certificateSettings.get(CERTIFICATES_VALIDATION_SETTINGS_NAME).getValue(), CertificateValidationSettingsDto.class));
            } catch (JsonProcessingException e) {
                logger.warn("Cannot deserialize platform certificates validation settings. Returning default settings.");
                certificateSettingsDto.setValidation(defaultValidationSettings);
            }
        } else {
            certificateSettingsDto.setValidation(defaultValidationSettings);
        }

        platformSettings.setCertificates(certificateSettingsDto);

        return platformSettings;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updatePlatformSettings(PlatformSettingsUpdateDto platformSettings) {
        List<Setting> settings = settingRepository.findBySection(SettingsSection.PLATFORM);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        // Auxiliary services: utils service and cbom repository
        if (platformSettings.getUtils() != null) {
            Setting utilSetting;
            Map<String, Setting> platformUtilsSettings = mappedSettings.get(SettingsSectionCategory.PLATFORM_UTILS.getCode());
            if (platformUtilsSettings == null || (utilSetting = platformUtilsSettings.get(UTILS_SERVICE_URL_NAME)) == null) {
                utilSetting = new Setting();
                utilSetting.setSection(SettingsSection.PLATFORM);
                utilSetting.setCategory(SettingsSectionCategory.PLATFORM_UTILS.getCode());
                utilSetting.setName(UTILS_SERVICE_URL_NAME);
            }

            utilSetting.setValue(platformSettings.getUtils().getUtilsServiceUrl());
            settingRepository.save(utilSetting);

            Setting cbomRepositorySetting;
            if (platformUtilsSettings == null || (cbomRepositorySetting = platformUtilsSettings.get(CBOM_REPOSITORY_URL_NAME)) == null) {
                cbomRepositorySetting = new Setting();
                cbomRepositorySetting.setSection(SettingsSection.PLATFORM);
                cbomRepositorySetting.setCategory(SettingsSectionCategory.PLATFORM_UTILS.getCode());
                cbomRepositorySetting.setName(CBOM_REPOSITORY_URL_NAME);
            }

            cbomRepositorySetting.setValue(platformSettings.getUtils().getCbomRepositoryUrl());
            settingRepository.save(cbomRepositorySetting);
        }

        // Certificate Settings
        if (platformSettings.getCertificates() != null) {
            Setting certificatesValidationSetting;
            Map<String, Setting> certificateSettings = mappedSettings.get(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
            if (certificateSettings == null || (certificatesValidationSetting = certificateSettings.get(CERTIFICATES_VALIDATION_SETTINGS_NAME)) == null) {
                certificatesValidationSetting = new Setting();
                certificatesValidationSetting.setSection(SettingsSection.PLATFORM);
                certificatesValidationSetting.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
                certificatesValidationSetting.setName(CERTIFICATES_VALIDATION_SETTINGS_NAME);
            }

            try {
                CertificateValidationSettingsUpdateDto validation = platformSettings.getCertificates().getValidation();
                // Set null values for validation disabled
                if (!validation.isEnabled()) {
                    validation.setFrequency(null);
                    validation.setExpiringThreshold(null);
                }
                certificatesValidationSetting.setValue(objectMapper.writeValueAsString(validation));
            } catch (JsonProcessingException e) {
                throw new ValidationException("Cannot serialize platform certificates settings: " + e.getMessage());
            }
            settingRepository.save(certificatesValidationSetting);

        }

        settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettings());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public EventsSettingsDto getEventsSettings() {
        return loadEventsSettings();
    }

    // Called directly by internal/scheduled callers to bypass the @ExternalAuthorization proxy on getEventsSettings().
    private EventsSettingsDto loadEventsSettings() {
        return new EventsSettingsDto(triggerInternalService.getTriggersAssociations(null, null));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateEventsSettings(EventsSettingsDto eventsSettingsDto) throws NotFoundException {
        for (ResourceEvent event : eventsSettingsDto.getEventsMapping().keySet()) {
            triggerService.createTriggerAssociations(event, null, null, eventsSettingsDto.getEventsMapping().get(event), true);
        }

        settingsCache.cacheSettings(SettingsSection.EVENTS, eventsSettingsDto);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateEventSettings(EventSettingsDto eventSettingsDto) throws NotFoundException {
        triggerService.createTriggerAssociations(eventSettingsDto.getEvent(), null, null, eventSettingsDto.getTriggerUuids(), true);
        settingsCache.cacheSettings(SettingsSection.EVENTS, getEventsSettings());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public LoggingSettingsDto getLoggingSettings() {
        LoggingSettingsDto loggingSettingsDto = new LoggingSettingsDto();
        List<Setting> settings = settingRepository.findBySection(SettingsSection.LOGGING);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        // audit logging
        Setting setting;
        Map<String, Setting> auditLoggingSettings = mappedSettings.get(SettingsSectionCategory.AUDIT_LOGGING.getCode());
        AuditLoggingSettingsDto auditLoggingSettingsDto = new AuditLoggingSettingsDto();
        if (auditLoggingSettings != null) {
            if ((setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_OUTPUT_NAME)) != null) {
                auditLoggingSettingsDto.setOutput(AuditLogOutput.valueOf(setting.getValue()));
            }
            if ((setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_VERBOSE_NAME)) != null) {
                auditLoggingSettingsDto.setVerbose(Boolean.parseBoolean(setting.getValue()));
            }
            if ((setting = auditLoggingSettings.get(LOGGING_RESOURCES_NAME)) != null) {
                ResourceLoggingSettingsDto resources;
                try {
                    resources = mapper.readValue(setting.getValue(), ResourceLoggingSettingsDto.class);
                } catch (JsonProcessingException e) {
                    logger.warn("Cannot deserialize audit logs resource settings. Returning default settings.");
                    resources = new ResourceLoggingSettingsDto();
                }
                auditLoggingSettingsDto.setResourceLogging(resources);
            }
        }
        loggingSettingsDto.setAuditLogs(auditLoggingSettingsDto);

        // event logging
        Map<String, Setting> eventLoggingSettings = mappedSettings.get(SettingsSectionCategory.EVENT_LOGGING.getCode());
        ResourceLoggingSettingsDto eventLoggingSettingsDto = new ResourceLoggingSettingsDto();
        if (eventLoggingSettings != null && (setting = eventLoggingSettings.get(LOGGING_RESOURCES_NAME)) != null) {
            ResourceLoggingSettingsDto resources;
            try {
                resources = mapper.readValue(setting.getValue(), ResourceLoggingSettingsDto.class);
            } catch (JsonProcessingException e) {
                logger.warn("Cannot deserialize event logs resource settings. Returning default settings.");
                resources = new ResourceLoggingSettingsDto();
            }
            eventLoggingSettingsDto = resources;
        }
        loggingSettingsDto.setEventLogs(eventLoggingSettingsDto);

        return loggingSettingsDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateLoggingSettings(LoggingSettingsDto loggingSettingsDto) {
        List<Setting> settings = settingRepository.findBySection(SettingsSection.LOGGING);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        // audit logging
        Setting setting;
        Map<String, Setting> auditLoggingSettings = mappedSettings.get(SettingsSectionCategory.AUDIT_LOGGING.getCode());
        if (auditLoggingSettings == null || (setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_OUTPUT_NAME)) == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.LOGGING);
            setting.setCategory(SettingsSectionCategory.AUDIT_LOGGING.getCode());
            setting.setName(LOGGING_AUDIT_LOG_OUTPUT_NAME);
        }
        setting.setValue(loggingSettingsDto.getAuditLogs().getOutput().toString());
        settingRepository.save(setting);

        if (auditLoggingSettings == null || (setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_VERBOSE_NAME)) == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.LOGGING);
            setting.setCategory(SettingsSectionCategory.AUDIT_LOGGING.getCode());
            setting.setName(LOGGING_AUDIT_LOG_VERBOSE_NAME);
        }
        setting.setValue(String.valueOf(loggingSettingsDto.getAuditLogs().isVerbose()));
        settingRepository.save(setting);

        if (auditLoggingSettings == null || (setting = auditLoggingSettings.get(LOGGING_RESOURCES_NAME)) == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.LOGGING);
            setting.setCategory(SettingsSectionCategory.AUDIT_LOGGING.getCode());
            setting.setName(LOGGING_RESOURCES_NAME);
        }
        try {
            setting.setValue(mapper.writeValueAsString(mapper.convertValue(loggingSettingsDto.getAuditLogs(), ResourceLoggingSettingsDto.class)));
            settingRepository.save(setting);
        } catch (JsonProcessingException e) {
            throw new ValidationException("Cannot serialize audit logging resources settings: " + e.getMessage());
        }

        // event logging
        Map<String, Setting> eventLoggingSettings = mappedSettings.get(SettingsSectionCategory.EVENT_LOGGING.getCode());
        if (eventLoggingSettings == null || (setting = eventLoggingSettings.get(LOGGING_RESOURCES_NAME)) == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.LOGGING);
            setting.setCategory(SettingsSectionCategory.EVENT_LOGGING.getCode());
            setting.setName(LOGGING_RESOURCES_NAME);
        }
        try {
            setting.setValue(mapper.writeValueAsString(loggingSettingsDto.getEventLogs()));
            settingRepository.save(setting);
        } catch (JsonProcessingException e) {
            throw new ValidationException("Cannot serialize event logging resources settings: " + e.getMessage());
        }

        settingsCache.cacheSettings(SettingsSection.LOGGING, loggingSettingsDto);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public AuthenticationSettingsDto getAuthenticationSettings(boolean withClientSecret) {
        AuthenticationSettingsDto authenticationSettings = new AuthenticationSettingsDto();

        List<Setting> oauth2ProviderSettings = settingRepository.findBySectionAndCategory(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        for (Setting oauth2Provider : oauth2ProviderSettings) {
            OAuth2ProviderSettingsDto oAuth2ProviderSettings;
            try {
                oAuth2ProviderSettings = objectMapper.readValue(oauth2Provider.getValue(), OAuth2ProviderSettingsDto.class);
                if (!withClientSecret) oAuth2ProviderSettings.setClientSecret(null);
            } catch (JsonProcessingException e) {
                throw new ValidationException(DESERIALIZATION_ERROR_MESSAGE.formatted(oauth2Provider.getName()));
            }
            authenticationSettings.getOAuth2Providers().put(oauth2Provider.getName(), oAuth2ProviderSettings);
        }
        Setting disableLocalhostSetting = settingRepository.findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, null, AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        if (disableLocalhostSetting != null) {
            authenticationSettings.setDisableLocalhostUser(Boolean.parseBoolean(disableLocalhostSetting.getValue()));
        }

        return authenticationSettings;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateAuthenticationSettings(AuthenticationSettingsUpdateDto authenticationSettingsDto) {
        Setting disableLocalhostSetting = settingRepository.findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, null, AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        if (disableLocalhostSetting == null) {
            disableLocalhostSetting = new Setting();
            disableLocalhostSetting.setSection(SettingsSection.AUTHENTICATION);
            disableLocalhostSetting.setName(AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        }
        disableLocalhostSetting.setValue(String.valueOf(authenticationSettingsDto.isDisableLocalhostUser()));
        settingRepository.save(disableLocalhostSetting);

        if (authenticationSettingsDto.getOAuth2Providers() != null) {
            settingRepository.deleteBySectionAndCategory(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode());

            for (OAuth2ProviderSettingsDto providerDto : authenticationSettingsDto.getOAuth2Providers()) {
                updateOAuth2ProviderSettings(providerDto.getName(), providerDto);
            }
        }
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.DETAIL)
    public OAuth2ProviderSettingsResponseDto getOAuth2ProviderSettings(String providerName, boolean withClientSecret) {
        Setting setting = settingRepository.findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        OAuth2ProviderSettingsResponseDto settingsDto = null;
        if (setting != null) {
            try {
                settingsDto = objectMapper.readValue(setting.getValue(), OAuth2ProviderSettingsResponseDto.class);
                if (!withClientSecret) settingsDto.setClientSecret(null);
            } catch (JsonProcessingException e) {
                throw new ValidationException(DESERIALIZATION_ERROR_MESSAGE.formatted(providerName));
            }
            settingsDto.setJwkSetKeys(convertJwkToListOfKeyDtos(checkJwkSetValidity(settingsDto)));
        }
        return settingsDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateOAuth2ProviderSettings(String providerName, OAuth2ProviderSettingsUpdateDto settingsDto) {
        validateOAuth2ProviderSettings(settingsDto, false);
        Setting settingForRegistrationId = settingRepository.findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        boolean isNewProvider = settingForRegistrationId == null;

        Setting setting = isNewProvider ? new Setting() : settingForRegistrationId;
        setting.setSection(SettingsSection.AUTHENTICATION);
        setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        setting.setName(providerName);

        // if request does not contain client secret, keep old one
        if (settingsDto.getClientSecret() != null && !settingsDto.getClientSecret().isEmpty()) {
            settingsDto.setClientSecret(SecretsUtil.encryptAndEncodeSecretString(settingsDto.getClientSecret(), SecretEncodingVersion.V1));
        } else if (!isNewProvider) {
            OAuth2ProviderSettingsDto storedProviderSettings;
            try {
                storedProviderSettings = objectMapper.readValue(setting.getValue(), OAuth2ProviderSettingsDto.class);
            } catch (JsonProcessingException e) {
                throw new ValidationException(DESERIALIZATION_ERROR_MESSAGE.formatted(providerName));
            }
            settingsDto.setClientSecret(storedProviderSettings.getClientSecret());
        }

        // serialize full provider settings
        try {
            OAuth2ProviderSettingsDto fullSettingsDto;
            if (settingsDto instanceof OAuth2ProviderSettingsDto s) {
                fullSettingsDto = s;
            } else {
                fullSettingsDto = objectMapper.convertValue(settingsDto, OAuth2ProviderSettingsDto.class);
                fullSettingsDto.setName(providerName);
            }
            setting.setValue(objectMapper.writeValueAsString(fullSettingsDto));
        } catch (JsonProcessingException e) {
            throw new ValidationException("Cannot serialize OAuth2 provider settings for provider '%s'.".formatted(providerName));
        }
        settingRepository.save(setting);

        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void removeOAuth2Provider(String providerName) {
        Long deleted = settingRepository.deleteBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        if (deleted > 0) {
            settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true));
        }
    }

    private Map<String, Map<String, Setting>> mapSettingsByCategory(List<Setting> settings) {
        var mapping = new HashMap<String, Map<String, Setting>>();

        for (Setting setting : settings) {
            Map<String, Setting> categorySettings = mapping.computeIfAbsent(setting.getCategory(), k -> new HashMap<>());
            categorySettings.put(setting.getName(), setting);
        }

        return mapping;
    }

    private void validateOAuth2ProviderSettings(OAuth2ProviderSettingsUpdateDto settingsDto, boolean checkAvailability) {
        if (settingsDto.getJwkSet() == null && settingsDto.getJwkSetUrl() == null)
            throw new ValidationException("Missing JWK Set URL or encoded JWK Set.");
        checkJwkSetValidity(settingsDto);
        if (checkAvailability) {
            for (String urlString : List.of(settingsDto.getJwkSetUrl(), settingsDto.getAuthorizationUrl(), settingsDto.getTokenUrl(), settingsDto.getLogoutUrl())) {
                URL url;
                try {
                    url = new URI(urlString).toURL();
                    HttpURLConnection huc = (HttpURLConnection) url.openConnection();
                    huc.setRequestMethod("OPTIONS");
                    if (huc.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
                        throw new ValidationException("URL %s is could not be reached.");
                    }
                } catch (IOException | URISyntaxException e) {
                    throw new ValidationException("Could not verify if URL %s is reachable: %s".formatted(urlString, e.getCause().toString()));
                }
            }
        }
    }

    private JWKSet checkJwkSetValidity(OAuth2ProviderSettingsUpdateDto settingsDto) {
        String jwkSet;
        if (settingsDto.getJwkSetUrl() != null) {
            try {
                URL url = new URI(settingsDto.getJwkSetUrl()).toURL();
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(5000);
                urlConnection.setReadTimeout(5000);
                try (InputStream stream = url.openStream()) {
                    jwkSet = new String(stream.readAllBytes());
                }
            } catch (MalformedURLException | URISyntaxException e) {
                throw new ValidationException("Unable to convert JWK Set URL to URL instance: " + e.getMessage());
            } catch (IOException e) {
                throw new ValidationException("Unable to open connection for JWK Set URL: " + e.getMessage());
            }
        } else {
            jwkSet = new String(Base64.getDecoder().decode(settingsDto.getJwkSet()));
        }
        try {
            return JWKSet.parse(jwkSet);
        } catch (ParseException e) {
            throw new ValidationException("JWK Set is invalid: " + e.getMessage());
        }

    }

    private List<JwkDto> convertJwkToListOfKeyDtos(JWKSet jwkSet) {
        List<JwkDto> jwkSetKeys = new ArrayList<>();
        for (JWK jwk : jwkSet.getKeys()) {
            JwkDto jwkDto = new JwkDto();
            jwkDto.setKid(jwk.getKeyID());
            jwkDto.setAlgorithm(jwk.getAlgorithm() != null ? jwk.getAlgorithm().getName() : null);
            jwkDto.setUse(jwk.getKeyUse() != null ? jwk.getKeyUse().getValue() : null);
            jwkDto.setKeyType(jwk.getKeyType().getValue());
            byte[] publicKeyBytes;
            try {
                switch (jwk.getKeyType().getValue()) {
                    case "EC" -> publicKeyBytes = jwk.toECKey().toPublicKey().getEncoded();
                    case "RSA" -> publicKeyBytes = jwk.toRSAKey().toPublicKey().getEncoded();
                    case "oct" -> publicKeyBytes = jwk.toOctetSequenceKey().toByteArray();
                    case "OKP" -> publicKeyBytes = jwk.toOctetKeyPair().getDecodedX();
                    default -> publicKeyBytes = new byte[0];
                }
            } catch (JOSEException e) {
                throw new ValidationException("Could not convert %s key with KID %s to Public key".formatted(jwk.getKeyType().getValue(), jwk.getKeyID()));
            }

            jwkDto.setPublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));
            jwkSetKeys.add(jwkDto);
        }
        return jwkSetKeys;
    }

}
