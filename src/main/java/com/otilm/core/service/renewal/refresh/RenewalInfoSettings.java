package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsDto;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.core.service.SettingInternalService;

/**
 * The platform settings that pace the refresh of authority renewal information, all in seconds except the batch size.
 */
public record RenewalInfoSettings(int minIntervalSeconds, int maxIntervalSeconds, int defaultIntervalSeconds,
        int batchSize, int recheckIntervalSeconds) {

    public static final int DEFAULT_MIN_INTERVAL_SECONDS = 3600;
    public static final int DEFAULT_MAX_INTERVAL_SECONDS = 86400;
    public static final int DEFAULT_DEFAULT_INTERVAL_SECONDS = 21600;
    public static final int DEFAULT_BATCH_SIZE = 20;
    public static final int DEFAULT_RECHECK_INTERVAL_SECONDS = 604800;

    public static final RenewalInfoSettings DEFAULTS = new RenewalInfoSettings(DEFAULT_MIN_INTERVAL_SECONDS,
            DEFAULT_MAX_INTERVAL_SECONDS, DEFAULT_DEFAULT_INTERVAL_SECONDS, DEFAULT_BATCH_SIZE,
            DEFAULT_RECHECK_INTERVAL_SECONDS);

    /** The settings of the DTO, a missing value replaced by its default. */
    public static RenewalInfoSettings from(CertificateRenewalInfoSettingsDto dto) {
        if (dto == null) {
            return DEFAULTS;
        }
        return new RenewalInfoSettings(orDefault(dto.getRefreshMinInterval(), DEFAULT_MIN_INTERVAL_SECONDS),
                orDefault(dto.getRefreshMaxInterval(), DEFAULT_MAX_INTERVAL_SECONDS),
                orDefault(dto.getRefreshDefaultInterval(), DEFAULT_DEFAULT_INTERVAL_SECONDS),
                orDefault(dto.getRefreshBatchSize(), DEFAULT_BATCH_SIZE),
                orDefault(dto.getRefreshRecheckInterval(), DEFAULT_RECHECK_INTERVAL_SECONDS));
    }

    /** The current platform settings. */
    public static RenewalInfoSettings current(SettingInternalService settingService) {
        PlatformSettingsDto platform = settingService.getPlatformSettingsInternal();
        CertificateSettingsDto certificates = platform == null ? null : platform.getCertificates();
        return from(certificates == null ? null : certificates.getRenewalInfo());
    }

    /** The DTO the settings API reports. */
    public CertificateRenewalInfoSettingsDto toDto() {
        CertificateRenewalInfoSettingsDto dto = new CertificateRenewalInfoSettingsDto();
        dto.setRefreshMinInterval(minIntervalSeconds);
        dto.setRefreshMaxInterval(maxIntervalSeconds);
        dto.setRefreshDefaultInterval(defaultIntervalSeconds);
        dto.setRefreshBatchSize(batchSize);
        dto.setRefreshRecheckInterval(recheckIntervalSeconds);
        return dto;
    }

    private static int orDefault(Integer value, int fallback) {
        return value != null ? value : fallback;
    }
}
