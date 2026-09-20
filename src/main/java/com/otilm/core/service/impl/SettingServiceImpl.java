package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import com.otilm.api.model.core.settings.BrandingTheme;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsDto;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateRequestAttributesSettingsDto;
import com.otilm.api.model.core.settings.CertificateRequestAttributesSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.settings.EventSettingsDto;
import com.otilm.api.model.core.settings.EventsSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.JwkDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.certificate.request.DefaultRequestAttributeSet;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.registration.CertificateRegistrationDefaults;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.settings.branding.BrandingSettingsValidator;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service("settingService")
@Transactional
public class SettingServiceImpl implements SettingExternalService, SettingInternalService {
    public static final String UTILS_SERVICE_URL_NAME = "utilsServiceUrl";
    public static final String CBOM_REPOSITORY_URL_NAME = "cbomRepositoryUrl";
    public static final String CBOM_SYNC_OVERLAP_SECONDS_NAME = "cbomSyncOverlapSeconds";
    public static final String CBOM_SYNC_SKIPPED_RETRY_RUNS_NAME = "cbomSyncSkippedRetryRuns";
    public static final String CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME = "cbomSyncMaxIngestDocuments";
    public static final String CBOM_SYNC_SKIP_RETENTION_DAYS_NAME = "cbomSyncSkipRetentionDays";
    public static final String CBOM_SYNC_PAGE_SIZE_NAME = "cbomSyncPageSize";
    public static final String CBOM_SYNC_ASSET_INGEST_ENABLED_NAME = "cbomSyncAssetIngestEnabled";
    public static final String CBOM_SYNC_ASSET_BATCH_SIZE_NAME = "cbomSyncAssetBatchSize";
    public static final String CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS_NAME = "cbomSyncIngestRetryAfterSeconds";
    public static final String CERTIFICATES_VALIDATION_SETTINGS_NAME = "certificatesValidation";
    public static final String CERTIFICATES_REGISTRATION_SETTINGS_NAME = "certificatesRegistration";

    public static final String LOGGING_AUDIT_LOG_OUTPUT_NAME = "output";
    public static final String LOGGING_AUDIT_LOG_VERBOSE_NAME = "verbose";
    public static final String LOGGING_RESOURCES_NAME = "resources";

    public static final String AUTHENTICATION_DISABLE_LOCALHOST_NAME = "disableLocalhostUser";

    private static final String DESERIALIZATION_ERROR_MESSAGE = "Cannot deserialize OAuth2 Provider Settings for provider '%s'.";
    private static final Logger logger = LoggerFactory.getLogger(SettingServiceImpl.class);

    /**
     * Branding is stored as one row per field rather than one serialized blob, so that clearing a single colour or logo
     * removes only its own row and that field falls back to its platform default independently of the rest.
     */
    private static final Map<String, BrandingField> BRANDING_FIELDS = brandingFields();

    /**
     * The corrupt text last reported per utils setting. The read runs on every cache refresh, so a value is reported
     * when it appears, whenever its text changes, and again after a valid or unset read has cleared the entry; three
     * entries at most. A refresh that read a corrupt value racing a request that read its correction can leave the
     * entry behind for one refresh cycle; the next read clears it.
     */
    private final Map<String, String> lastReportedCorruptUtilsValue = new ConcurrentHashMap<>();

    private final ObjectMapper wireMapper;
    private final SettingsCache settingsCache;
    private final SettingRepository settingRepository;

    private TriggerExternalService triggerService;
    private TriggerInternalService triggerInternalService;

    /** Settings are persisted, so they keep Jackson's storage shape rather than the wire mapper's null suppression. */
    private final ObjectMapper storageMapper = ObjectMapperFactory.storage();

    @Autowired
    public SettingServiceImpl(SettingsCache settingsCache, SettingRepository settingRepository,
            ObjectMapper wireMapper) {
        this.wireMapper = wireMapper;
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

    @Override
    @Scheduled(fixedRateString = "${settings.cache.refresh-interval}", timeUnit = TimeUnit.SECONDS,
            initialDelayString = "${settings.cache.refresh-interval}")
    public void refreshCache() {
        settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettings());
        settingsCache.cacheSettings(SettingsSection.LOGGING, getLoggingSettings());
        settingsCache.cacheSettings(SettingsSection.EVENTS, loadEventsSettings());
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public PlatformSettingsDto getPlatformSettings() {
        return buildPlatformSettings();
    }

    @Override
    public PlatformSettingsDto getPlatformSettingsInternal() {
        return buildPlatformSettings();
    }

    private PlatformSettingsDto buildPlatformSettings() {
        List<Setting> settings = settingRepository.findBySection(SettingsSection.PLATFORM);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        PlatformSettingsDto platformSettings = new PlatformSettingsDto();
        // Utils
        Map<String, Setting> utilsSettings = mappedSettings.get(SettingsSectionCategory.PLATFORM_UTILS.getCode());
        UtilsSettingsDto utilsSettingsDto = new UtilsSettingsDto();
        utilsSettingsDto.setUtilsServiceUrl(utilsValue(utilsSettings, UTILS_SERVICE_URL_NAME));
        utilsSettingsDto.setCbomRepositoryUrl(utilsValue(utilsSettings, CBOM_REPOSITORY_URL_NAME));
        // The CBOM sync policy reads back with its defaults filled in, so a form shows what the sync will use.
        utilsSettingsDto
                .setCbomSyncOverlapSeconds(utilsInteger(utilsSettings, CBOM_SYNC_OVERLAP_SECONDS_NAME,
                        CbomSyncPolicy.DEFAULT_OVERLAP_SECONDS, 0, UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS));
        utilsSettingsDto
                .setCbomSyncSkippedRetryRuns(utilsInteger(utilsSettings, CBOM_SYNC_SKIPPED_RETRY_RUNS_NAME,
                        CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS, 0,
                        UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS));
        utilsSettingsDto
                .setCbomSyncMaxIngestDocuments(utilsInteger(utilsSettings, CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME,
                        CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, 0,
                        UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS));
        utilsSettingsDto
                .setCbomSyncSkipRetentionDays(utilsInteger(utilsSettings, CBOM_SYNC_SKIP_RETENTION_DAYS_NAME,
                        CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS, UtilsSettingsDto.MIN_CBOM_SYNC_SKIP_RETENTION_DAYS,
                        UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS));
        utilsSettingsDto
                .setCbomSyncPageSize(
                        utilsInteger(utilsSettings, CBOM_SYNC_PAGE_SIZE_NAME, CbomSyncPolicy.DEFAULT_PAGE_SIZE,
                                UtilsSettingsDto.MIN_CBOM_SYNC_PAGE_SIZE, UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE));
        utilsSettingsDto
                .setCbomSyncAssetIngestEnabled(utilsBoolean(utilsSettings, CBOM_SYNC_ASSET_INGEST_ENABLED_NAME,
                        CbomSyncPolicy.DEFAULT_ASSET_INGEST_ENABLED));
        utilsSettingsDto
                .setCbomSyncAssetBatchSize(utilsInteger(utilsSettings, CBOM_SYNC_ASSET_BATCH_SIZE_NAME,
                        CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, UtilsSettingsDto.MIN_CBOM_SYNC_ASSET_BATCH_SIZE,
                        UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE));
        utilsSettingsDto
                .setCbomSyncIngestRetryAfterSeconds(utilsInteger(utilsSettings,
                        CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS_NAME, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER_SECONDS, 0,
                        UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS));
        platformSettings.setUtils(utilsSettingsDto);

        // Certificates
        Map<String, Setting> certificateSettings = mappedSettings
                .get(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        CertificateSettingsDto certificateSettingsDto = new CertificateSettingsDto();
        CertificateValidationSettingsDto defaultValidationSettings = new CertificateValidationSettingsDto();
        defaultValidationSettings.setEnabled(true);
        defaultValidationSettings.setFrequency(1);
        defaultValidationSettings.setExpiringThreshold(30);

        if (certificateSettings != null && certificateSettings.get(CERTIFICATES_VALIDATION_SETTINGS_NAME) != null) {
            try {
                certificateSettingsDto
                        .setValidation(storageMapper
                                .readValue(certificateSettings.get(CERTIFICATES_VALIDATION_SETTINGS_NAME).getValue(),
                                        CertificateValidationSettingsDto.class));
            } catch (JsonProcessingException e) {
                logger
                        .warn("Cannot deserialize platform certificates validation settings. Returning default settings.");
                certificateSettingsDto.setValidation(defaultValidationSettings);
            }
        } else {
            certificateSettingsDto.setValidation(defaultValidationSettings);
        }

        certificateSettingsDto.setRequestAttributes(readRequestAttributesSettings(certificateSettings));

        CertificateRegistrationSettingsDto defaultRegistrationSettings = new CertificateRegistrationSettingsDto();
        defaultRegistrationSettings.setDefaultIssuanceWindowDays(CertificateRegistrationDefaults.ISSUANCE_WINDOW_DAYS);
        defaultRegistrationSettings.setMaxFailedAttempts(CertificateRegistrationDefaults.MAX_FAILED_ATTEMPTS);
        if (certificateSettings != null && certificateSettings.get(CERTIFICATES_REGISTRATION_SETTINGS_NAME) != null) {
            try {
                certificateSettingsDto
                        .setRegistration(storageMapper
                                .readValue(certificateSettings.get(CERTIFICATES_REGISTRATION_SETTINGS_NAME).getValue(),
                                        CertificateRegistrationSettingsDto.class));
            } catch (JsonProcessingException e) {
                logger
                        .warn("Cannot deserialize platform certificates registration settings. Returning default settings.");
                certificateSettingsDto.setRegistration(defaultRegistrationSettings);
            }
        } else {
            certificateSettingsDto.setRegistration(defaultRegistrationSettings);
        }

        platformSettings.setCertificates(certificateSettingsDto);

        // Branding
        platformSettings
                .setBranding(
                        readBrandingSettings(mappedSettings.get(SettingsSectionCategory.PLATFORM_BRANDING.getCode())));

        return platformSettings;
    }

    private record BrandingField(Function<BrandingSettingsUpdateDto, String> fromUpdate,
            BiConsumer<BrandingSettingsDto, String> intoResponse) {
    }

    private static Map<String, BrandingField> brandingFields() {
        Map<String, BrandingField> fields = new LinkedHashMap<>();
        fields
                .put("primaryColor", new BrandingField(BrandingSettingsUpdateDto::getPrimaryColor,
                        BrandingSettingsDto::setPrimaryColor));
        fields
                .put("secondaryColor", new BrandingField(BrandingSettingsUpdateDto::getSecondaryColor,
                        BrandingSettingsDto::setSecondaryColor));
        fields
                .put("backgroundColor", new BrandingField(BrandingSettingsUpdateDto::getBackgroundColor,
                        BrandingSettingsDto::setBackgroundColor));
        fields
                .put("textColor",
                        new BrandingField(BrandingSettingsUpdateDto::getTextColor, BrandingSettingsDto::setTextColor));
        fields
                .put("lightLogo",
                        new BrandingField(BrandingSettingsUpdateDto::getLightLogo, BrandingSettingsDto::setLightLogo));
        fields
                .put("darkLogo",
                        new BrandingField(BrandingSettingsUpdateDto::getDarkLogo, BrandingSettingsDto::setDarkLogo));
        fields
                .put("defaultTheme",
                        new BrandingField(
                                update -> update.getDefaultTheme() == null ? null : update.getDefaultTheme().getCode(),
                                SettingServiceImpl::applyDefaultTheme));
        return Map.copyOf(fields);
    }

    /**
     * A stored theme code that no longer maps to anything is dropped rather than thrown: branding is read on every page
     * render, and one unrecognised value must not take the whole platform settings read down with it.
     */
    private static void applyDefaultTheme(BrandingSettingsDto branding, String code) {
        try {
            branding.setDefaultTheme(BrandingTheme.findByCode(code));
        } catch (ValidationException e) {
            logger.warn("Ignoring unknown stored branding default theme '{}'.", code);
        }
    }

    private BrandingSettingsDto readBrandingSettings(Map<String, Setting> brandingSettings) {
        BrandingSettingsDto branding = new BrandingSettingsDto();
        if (brandingSettings == null) {
            return branding;
        }
        BRANDING_FIELDS.forEach((name, field) -> {
            Setting setting = brandingSettings.get(name);
            if (setting != null && setting.getValue() != null && !setting.getValue().isBlank()) {
                field.intoResponse().accept(branding, setting.getValue());
            }
        });
        return branding;
    }

    private Map<String, Setting> storedBrandingSettings() {
        Map<String, Setting> stored = new HashMap<>();
        settingRepository
                .findBySectionAndCategory(SettingsSection.PLATFORM, SettingsSectionCategory.PLATFORM_BRANDING.getCode())
                .forEach(setting -> stored.put(setting.getName(), setting));
        return stored;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.LIST)
    public BrandingSettingsDto getBrandingSettings() {
        return readBrandingSettings(storedBrandingSettings());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE_BRANDING)
    public void updateBrandingSettings(BrandingSettingsUpdateDto brandingSettings) {
        // SVG logos come back sanitized, so the submitted document never reaches the settings table.
        BrandingSettingsUpdateDto sanitized = BrandingSettingsValidator.validated(brandingSettings);

        // Held before the rows are read, because a field is written by looking for its row and inserting when there is
        // none: two concurrent first updates would otherwise both find nothing and insert the same field twice.
        settingRepository.lockBrandingWrites();

        Map<String, Setting> stored = storedBrandingSettings();
        BRANDING_FIELDS
                .forEach((name, field) -> writeBrandingField(name, field.fromUpdate().apply(sanitized),
                        stored.get(name)));

        cacheAfterCommit(() -> settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettingsInternal()));
    }

    private void writeBrandingField(String name, String value, Setting stored) {
        if (value == null) {
            // Reset to default is per field: with no row, the read leaves the field unset and the UI uses its own.
            if (stored != null) {
                settingRepository.delete(stored);
            }
            return;
        }

        Setting setting = stored;
        if (setting == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.PLATFORM);
            setting.setCategory(SettingsSectionCategory.PLATFORM_BRANDING.getCode());
            setting.setName(name);
        }
        setting.setValue(value);
        settingRepository.save(setting);
    }

    private Setting certificateSetting(Map<String, Setting> certificateSettings, String name) {
        return platformSetting(certificateSettings, SettingsSectionCategory.PLATFORM_CERTIFICATES, name);
    }

    /**
     * The stored row of one platform setting, or a new unsaved one for it. The caller holds the category's advisory
     * lock ({@code lockUtilsWrites}, {@code lockCertificateWrites}) from before the rows were read: this inserts when
     * it finds no row, and two writers that both find none would insert the name twice.
     */
    private static Setting platformSetting(Map<String, Setting> categorySettings, SettingsSectionCategory category,
            String name) {
        Setting setting = categorySettings == null ? null : categorySettings.get(name);
        if (setting == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.PLATFORM);
            setting.setCategory(category.getCode());
            setting.setName(name);
        }
        return setting;
    }

    private CertificateRequestAttributesSettingsDto readRequestAttributesSettings(
            Map<String, Setting> certificateSettings) {
        CertificateRequestAttributesSettingsDto dto = new CertificateRequestAttributesSettingsDto();
        Setting definitions = certificateSettings == null
                ? null
                : certificateSettings.get(DefaultRequestAttributeSet.SETTING_NAME);
        // resolve() seeds the built-in default set (CsrAttributes) when nothing has been stored yet.
        dto
                .setRequestAttributes(
                        DefaultRequestAttributeSet.resolve(definitions == null ? null : definitions.getValue()));

        Setting strict = certificateSettings == null
                ? null
                : certificateSettings.get(DefaultRequestAttributeSet.STRICT_SETTING_NAME);
        if (strict != null && strict.getValue() != null && !strict.getValue().isBlank()) {
            dto.setExternalCsrValidationStrict(Boolean.valueOf(strict.getValue().trim()));
        }
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updatePlatformSettings(PlatformSettingsUpdateDto platformSettings) {
        // Held before the rows are read, as for branding: a value is written by looking for its row and inserting when
        // there is none, so two concurrent first updates would otherwise insert a name twice. Utils first, then
        // certificates, always in this order, so the two keys cannot wait on each other.
        if (platformSettings.getUtils() != null) {
            settingRepository.lockUtilsWrites();
        }
        if (platformSettings.getCertificates() != null) {
            settingRepository.lockCertificateWrites();
        }
        List<Setting> settings = settingRepository.findBySection(SettingsSection.PLATFORM);
        Map<String, Map<String, Setting>> mappedSettings = mapSettingsByCategory(settings);

        if (platformSettings.getUtils() != null) {
            updateUtilsSettings(platformSettings, mappedSettings);
        }
        if (platformSettings.getCertificates() != null) {
            updateCertificateSettings(platformSettings, mappedSettings);
        }

        // Refresh the cache only once the transaction commits; otherwise a later rollback would
        // leave the cache holding values that never reached the database.
        cacheAfterCommit(() -> settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettings()));
    }

    // Auxiliary services: utils service and cbom repository, plus the CBOM sync policy the sync reads per run
    private void updateUtilsSettings(PlatformSettingsUpdateDto platformSettings,
            Map<String, Map<String, Setting>> mappedSettings) {
        Map<String, Setting> platformUtilsSettings = mappedSettings
                .get(SettingsSectionCategory.PLATFORM_UTILS.getCode());
        UtilsSettingsDto utils = platformSettings.getUtils();
        upsertUtilsSetting(platformUtilsSettings, UTILS_SERVICE_URL_NAME, utils.getUtilsServiceUrl());
        upsertUtilsSetting(platformUtilsSettings, CBOM_REPOSITORY_URL_NAME, utils.getCbomRepositoryUrl());
        // Stored as text like every setting. An unset value removes the row, and the read falls back to the default.
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_OVERLAP_SECONDS_NAME,
                integerText(utils.getCbomSyncOverlapSeconds()));
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_SKIPPED_RETRY_RUNS_NAME,
                integerText(utils.getCbomSyncSkippedRetryRuns()));
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME,
                integerText(utils.getCbomSyncMaxIngestDocuments()));
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_SKIP_RETENTION_DAYS_NAME,
                integerText(utils.getCbomSyncSkipRetentionDays()));
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_PAGE_SIZE_NAME, integerText(utils.getCbomSyncPageSize()));
        // The one field the stored-as-sent rule does not cover: left out, it keeps the stored value. Both of its
        // values are expressible, so nothing becomes unreachable, and a client that sends the section without it
        // cannot restart an ingest an operator has stopped.
        if (utils.getCbomSyncAssetIngestEnabled() != null) {
            upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_ASSET_INGEST_ENABLED_NAME,
                    booleanText(utils.getCbomSyncAssetIngestEnabled()));
        }
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_ASSET_BATCH_SIZE_NAME,
                integerText(utils.getCbomSyncAssetBatchSize()));
        upsertUtilsSetting(platformUtilsSettings, CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS_NAME,
                integerText(utils.getCbomSyncIngestRetryAfterSeconds()));
    }

    /** Writes one utils value; an unset value leaves no row behind, as the branding writes do. */
    private void upsertUtilsSetting(Map<String, Setting> platformUtilsSettings, String name, String value) {
        Setting stored = platformUtilsSettings == null ? null : platformUtilsSettings.get(name);
        if (value == null) {
            if (stored != null) {
                settingRepository.delete(stored);
            }
            return;
        }
        Setting setting = platformSetting(platformUtilsSettings, SettingsSectionCategory.PLATFORM_UTILS, name);
        setting.setValue(value);
        settingRepository.save(setting);
    }

    private static String utilsValue(Map<String, Setting> utilsSettings, String name) {
        Setting setting = utilsSettings == null ? null : utilsSettings.get(name);
        return setting == null ? null : setting.getValue();
    }

    /**
     * A stored value that is not an integer, or lies outside the bounds the API validates on the way in -- only a
     * manual edit can put one there -- reads as the default, so the sync keeps running on a known value rather than
     * failing on a corrupt one. Reported when it appears, whenever its text changes, and again after it was corrected
     * -- not on every cache refresh, which is where this runs.
     */
    private int utilsInteger(Map<String, Setting> utilsSettings, String name, int defaultValue, int minValue,
            int maxValue) {
        String value = utilsValue(utilsSettings, name);
        if (value == null || value.isBlank()) {
            lastReportedCorruptUtilsValue.remove(name);
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < minValue || parsed > maxValue) {
                reportCorruptUtilsValue(name, value, "outside %d..%d".formatted(minValue, maxValue), defaultValue);
                return defaultValue;
            }
            lastReportedCorruptUtilsValue.remove(name);
            return parsed;
        } catch (NumberFormatException e) {
            reportCorruptUtilsValue(name, value, "not an integer", defaultValue);
            return defaultValue;
        }
    }

    /**
     * As {@link #utilsInteger}, for a flag. Spelled out rather than {@code Boolean.parseBoolean}, which reads every
     * text that is not {@code true} as {@code false} -- so a typo in the asset-ingest row would silently stop every
     * ingest rather than read as the corrupt value it is.
     */
    private boolean utilsBoolean(Map<String, Setting> utilsSettings, String name, boolean defaultValue) {
        String value = utilsValue(utilsSettings, name);
        if (value == null || value.isBlank()) {
            lastReportedCorruptUtilsValue.remove(name);
            return defaultValue;
        }
        String text = value.trim();
        if (Boolean.TRUE.toString().equalsIgnoreCase(text) || Boolean.FALSE.toString().equalsIgnoreCase(text)) {
            lastReportedCorruptUtilsValue.remove(name);
            return Boolean.parseBoolean(text);
        }
        reportCorruptUtilsValue(name, value, "neither true nor false", defaultValue);
        return defaultValue;
    }

    private void reportCorruptUtilsValue(String name, String value, String problem, Object defaultValue) {
        if (!value.equals(lastReportedCorruptUtilsValue.put(name, value))) {
            logger
                    .warn("Platform setting {} holds '{}', {}; using the default {} until it is corrected", name, value,
                            problem, defaultValue);
        }
    }

    private static String integerText(Integer value) {
        return value == null ? null : Integer.toString(value);
    }

    private static String booleanText(Boolean value) {
        return value == null ? null : Boolean.toString(value);
    }

    private void updateCertificateSettings(PlatformSettingsUpdateDto platformSettings,
            Map<String, Map<String, Setting>> mappedSettings) {
        Map<String, Setting> certificateSettings = mappedSettings
                .get(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());

        CertificateValidationSettingsUpdateDto validation = platformSettings.getCertificates().getValidation();
        if (validation != null) {
            Setting certificatesValidationSetting = certificateSetting(certificateSettings,
                    CERTIFICATES_VALIDATION_SETTINGS_NAME);
            try {
                // Set null values for validation disabled
                if (!validation.isEnabled()) {
                    validation.setFrequency(null);
                    validation.setExpiringThreshold(null);
                }
                certificatesValidationSetting.setValue(storageMapper.writeValueAsString(validation));
            } catch (JsonProcessingException e) {
                logger.warn("Failed to serialize platform certificates validation settings", e);
                throw new ValidationException("Cannot serialize platform certificates settings.");
            }
            settingRepository.save(certificatesValidationSetting);
        }

        CertificateRequestAttributesSettingsUpdateDto requestAttributes = platformSettings
                .getCertificates()
                .getRequestAttributes();
        if (requestAttributes != null) {
            AttributeEngine.validateRequestAttributeDefinitions(requestAttributes.getRequestAttributes());
            Setting definitionsSetting = certificateSetting(certificateSettings,
                    DefaultRequestAttributeSet.SETTING_NAME);
            definitionsSetting.setValue(AttributeDefinitionUtils.serialize(requestAttributes.getRequestAttributes()));
            settingRepository.save(definitionsSetting);

            Setting strictSetting = certificateSetting(certificateSettings,
                    DefaultRequestAttributeSet.STRICT_SETTING_NAME);
            strictSetting
                    .setValue(requestAttributes.getExternalCsrValidationStrict() == null
                            ? null
                            : requestAttributes.getExternalCsrValidationStrict().toString());
            settingRepository.save(strictSetting);
        }

        CertificateRegistrationSettingsUpdateDto registration = platformSettings.getCertificates().getRegistration();
        if (registration != null) {
            Setting registrationSetting = certificateSetting(certificateSettings,
                    CERTIFICATES_REGISTRATION_SETTINGS_NAME);
            try {
                registrationSetting.setValue(storageMapper.writeValueAsString(registration));
            } catch (JsonProcessingException e) {
                logger.warn("Failed to serialize platform certificates registration settings", e);
                throw new ValidationException("Cannot serialize platform certificates settings.");
            }
            settingRepository.save(registrationSetting);
        }
    }

    private void cacheAfterCommit(Runnable refresh) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    refresh.run();
                }
            });
        } else {
            refresh.run();
        }
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
            triggerService
                    .createTriggerAssociations(event, null, null, eventsSettingsDto.getEventsMapping().get(event),
                            true);
        }

        settingsCache.cacheSettings(SettingsSection.EVENTS, eventsSettingsDto);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateEventSettings(EventSettingsDto eventSettingsDto) throws NotFoundException {
        triggerService
                .createTriggerAssociations(eventSettingsDto.getEvent(), null, null, eventSettingsDto.getTriggerUuids(),
                        true);
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
                    resources = wireMapper.readValue(setting.getValue(), ResourceLoggingSettingsDto.class);
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
                resources = wireMapper.readValue(setting.getValue(), ResourceLoggingSettingsDto.class);
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
        if (auditLoggingSettings == null
                || (setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_OUTPUT_NAME)) == null) {
            setting = new Setting();
            setting.setSection(SettingsSection.LOGGING);
            setting.setCategory(SettingsSectionCategory.AUDIT_LOGGING.getCode());
            setting.setName(LOGGING_AUDIT_LOG_OUTPUT_NAME);
        }
        setting.setValue(loggingSettingsDto.getAuditLogs().getOutput().toString());
        settingRepository.save(setting);

        if (auditLoggingSettings == null
                || (setting = auditLoggingSettings.get(LOGGING_AUDIT_LOG_VERBOSE_NAME)) == null) {
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
            setting
                    .setValue(wireMapper
                            .writeValueAsString(wireMapper
                                    .convertValue(loggingSettingsDto.getAuditLogs(),
                                            ResourceLoggingSettingsDto.class)));
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
            setting.setValue(wireMapper.writeValueAsString(loggingSettingsDto.getEventLogs()));
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

        List<Setting> oauth2ProviderSettings = settingRepository
                .findBySectionAndCategory(SettingsSection.AUTHENTICATION,
                        SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        for (Setting oauth2Provider : oauth2ProviderSettings) {
            OAuth2ProviderSettingsDto oAuth2ProviderSettings;
            try {
                oAuth2ProviderSettings = storageMapper
                        .readValue(oauth2Provider.getValue(), OAuth2ProviderSettingsDto.class);
                if (!withClientSecret) {
                    oAuth2ProviderSettings.setClientSecret(null);
                }
            } catch (JsonProcessingException e) {
                throw new ValidationException(DESERIALIZATION_ERROR_MESSAGE.formatted(oauth2Provider.getName()));
            }
            authenticationSettings.getOAuth2Providers().put(oauth2Provider.getName(), oAuth2ProviderSettings);
        }
        Setting disableLocalhostSetting = settingRepository
                .findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, null,
                        AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        if (disableLocalhostSetting != null) {
            authenticationSettings.setDisableLocalhostUser(Boolean.parseBoolean(disableLocalhostSetting.getValue()));
        }

        return authenticationSettings;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateAuthenticationSettings(AuthenticationSettingsUpdateDto authenticationSettingsDto) {
        Setting disableLocalhostSetting = settingRepository
                .findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION, null,
                        AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        if (disableLocalhostSetting == null) {
            disableLocalhostSetting = new Setting();
            disableLocalhostSetting.setSection(SettingsSection.AUTHENTICATION);
            disableLocalhostSetting.setName(AUTHENTICATION_DISABLE_LOCALHOST_NAME);
        }
        disableLocalhostSetting.setValue(String.valueOf(authenticationSettingsDto.isDisableLocalhostUser()));
        settingRepository.save(disableLocalhostSetting);

        if (authenticationSettingsDto.getOAuth2Providers() != null) {
            Set<String> issuerUrls = new HashSet<>();
            for (OAuth2ProviderSettingsDto providerDto : authenticationSettingsDto.getOAuth2Providers()) {
                if (providerDto.getIssuerUrl() != null && !issuerUrls.add(providerDto.getIssuerUrl())) {
                    throw new ValidationException(
                            "Multiple OAuth2 providers in the request use issuer URL '%s'. Issuer URLs must be unique across providers."
                                    .formatted(providerDto.getIssuerUrl()));
                }
            }

            for (OAuth2ProviderSettingsDto providerDto : authenticationSettingsDto.getOAuth2Providers()) {
                normalizeAndValidateOAuth2ProviderSettings(providerDto);
            }

            settingRepository.lockOAuth2ProviderWrites();
            settingRepository
                    .deleteBySectionAndCategory(SettingsSection.AUTHENTICATION,
                            SettingsSectionCategory.OAUTH2_PROVIDER.getCode());

            for (OAuth2ProviderSettingsDto providerDto : authenticationSettingsDto.getOAuth2Providers()) {
                persistOAuth2Provider(providerDto.getName(), providerDto);
            }
        }
        cacheAfterCommit(
                () -> settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true)));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.DETAIL)
    @org.springframework.transaction.annotation.Transactional(propagation = Propagation.NOT_SUPPORTED)
    public OAuth2ProviderSettingsResponseDto getOAuth2ProviderSettings(String providerName, boolean withClientSecret) {
        Setting setting = settingRepository
                .findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION,
                        SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        OAuth2ProviderSettingsResponseDto settingsDto = null;
        if (setting != null) {
            try {
                settingsDto = storageMapper.readValue(setting.getValue(), OAuth2ProviderSettingsResponseDto.class);
                if (!withClientSecret) {
                    settingsDto.setClientSecret(null);
                }
            } catch (JsonProcessingException e) {
                throw new ValidationException(DESERIALIZATION_ERROR_MESSAGE.formatted(providerName));
            }
            try {
                settingsDto.setJwkSetKeys(convertJwkToListOfKeyDtos(checkJwkSetValidity(settingsDto)));
            } catch (ValidationException e) {
                logger.warn("Unable to load JWK Set keys for OAuth2 provider '{}': {}", providerName, e.getMessage());
                settingsDto.setJwkSetKeys(List.of());
            }
        }
        return settingsDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void updateOAuth2ProviderSettings(String providerName, OAuth2ProviderSettingsUpdateDto settingsDto) {
        normalizeAndValidateOAuth2ProviderSettings(settingsDto);

        settingRepository.lockOAuth2ProviderWrites();
        validateIssuerUniqueness(providerName, settingsDto.getIssuerUrl());

        persistOAuth2Provider(providerName, settingsDto);
        cacheAfterCommit(
                () -> settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true)));
    }

    private void persistOAuth2Provider(String providerName, OAuth2ProviderSettingsUpdateDto settingsDto) {
        Setting settingForRegistrationId = settingRepository
                .findBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION,
                        SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        boolean isNewProvider = settingForRegistrationId == null;

        Setting setting = isNewProvider ? new Setting() : settingForRegistrationId;
        setting.setSection(SettingsSection.AUTHENTICATION);
        setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        setting.setName(providerName);

        // if request does not contain client secret, keep old one
        if (settingsDto.getClientSecret() != null && !settingsDto.getClientSecret().isEmpty()) {
            settingsDto
                    .setClientSecret(SecretsUtil
                            .encryptAndEncodeSecretString(settingsDto.getClientSecret(), SecretEncodingVersion.V1));
        } else if (!isNewProvider) {
            OAuth2ProviderSettingsDto storedProviderSettings;
            try {
                storedProviderSettings = storageMapper.readValue(setting.getValue(), OAuth2ProviderSettingsDto.class);
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
                fullSettingsDto = storageMapper.convertValue(settingsDto, OAuth2ProviderSettingsDto.class);
                fullSettingsDto.setName(providerName);
            }
            setting.setValue(storageMapper.writeValueAsString(fullSettingsDto));
        } catch (JsonProcessingException e) {
            throw new ValidationException(
                    "Cannot serialize OAuth2 provider settings for provider '%s'.".formatted(providerName));
        }
        settingRepository.save(setting);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SETTINGS, action = ResourceAction.UPDATE)
    public void removeOAuth2Provider(String providerName) {
        settingRepository.lockOAuth2ProviderWrites();

        Long deleted = settingRepository
                .deleteBySectionAndCategoryAndName(SettingsSection.AUTHENTICATION,
                        SettingsSectionCategory.OAUTH2_PROVIDER.getCode(), providerName);
        if (deleted > 0) {
            cacheAfterCommit(
                    () -> settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, getAuthenticationSettings(true)));
        }
    }

    private void validateIssuerUniqueness(String providerName, String issuerUrl) {
        if (issuerUrl == null) {
            return;
        }
        for (Map.Entry<String, OAuth2ProviderSettingsDto> entry : getAuthenticationSettings(true)
                .getOAuth2Providers()
                .entrySet()) {
            if (!entry.getKey().equals(providerName) && issuerUrl.equals(entry.getValue().getIssuerUrl())) {
                throw new ValidationException(
                        "OAuth2 provider '%s' already uses issuer URL '%s'. Issuer URLs must be unique across providers."
                                .formatted(entry.getKey(), issuerUrl));
            }
        }
    }

    private Map<String, Map<String, Setting>> mapSettingsByCategory(List<Setting> settings) {
        var mapping = new HashMap<String, Map<String, Setting>>();

        for (Setting setting : settings) {
            Map<String, Setting> categorySettings = mapping
                    .computeIfAbsent(setting.getCategory(), k -> new HashMap<>());
            categorySettings.put(setting.getName(), setting);
        }

        return mapping;
    }

    private void normalizeAndValidateOAuth2ProviderSettings(OAuth2ProviderSettingsUpdateDto settingsDto) {
        String jwkSetUrl = settingsDto.getJwkSetUrl();
        if (jwkSetUrl != null && jwkSetUrl.isBlank()) {
            settingsDto.setJwkSetUrl(null);
            jwkSetUrl = null;
        }
        if (settingsDto.getJwkSet() == null && jwkSetUrl == null) {
            throw new ValidationException("Missing JWK Set URL or encoded JWK Set.");
        }
        if (jwkSetUrl == null) {
            convertJwkToListOfKeyDtos(checkJwkSetValidity(settingsDto));
            return;
        }
        parseJwkSetUrl(jwkSetUrl);
    }

    private URL parseJwkSetUrl(String jwkSetUrl) {
        try {
            URI uri = new URI(jwkSetUrl);
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                throw new ValidationException("JWK Set URL must use http or https.");
            }
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
            throw new ValidationException("JWK Set URL is invalid.");
        }
    }

    private JWKSet checkJwkSetValidity(OAuth2ProviderSettingsUpdateDto settingsDto) {
        String jwkSet;
        if (settingsDto.getJwkSetUrl() != null) {
            try {
                URL url = parseJwkSetUrl(settingsDto.getJwkSetUrl());
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(5000);
                urlConnection.setReadTimeout(5000);
                try (InputStream stream = urlConnection.getInputStream()) {
                    jwkSet = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
                }
            } catch (IOException e) {
                throw new ValidationException("Unable to open connection for JWK Set URL: " + e.getMessage());
            }
        } else {
            try {
                jwkSet = new String(Base64.getDecoder().decode(settingsDto.getJwkSet()), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new ValidationException("Encoded JWK Set is invalid.");
            }
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
                throw new ValidationException("Could not convert %s key with KID %s to Public key"
                        .formatted(jwk.getKeyType().getValue(), jwk.getKeyID()));
            }

            jwkDto.setPublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));
            jwkSetKeys.add(jwkDto);
        }
        return jwkSetKeys;
    }

}
