package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsDto;
import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SettingServiceRenewalInfoITest extends BaseSpringBootTest {

    @Autowired
    private SettingExternalService settingService;

    @Test
    void reportsTheDefaults_whenNothingWasStored() {
        // given — no renewal-info settings stored

        // when
        CertificateRenewalInfoSettingsDto settings = settingService
                .getPlatformSettings()
                .getCertificates()
                .getRenewalInfo();

        // then
        assertThat(settings.getRefreshMinInterval()).isEqualTo(3600);
        assertThat(settings.getRefreshMaxInterval()).isEqualTo(86400);
        assertThat(settings.getRefreshDefaultInterval()).isEqualTo(21600);
        assertThat(settings.getRefreshBatchSize()).isEqualTo(20);
        assertThat(settings.getRefreshRecheckInterval()).isEqualTo(604800);
    }

    @Test
    void storesTheUpdateAndKeepsOtherCertificateSettings_whenUpdatingRenewalInfo() {
        // given
        CertificateRenewalInfoSettingsUpdateDto renewalInfo = new CertificateRenewalInfoSettingsUpdateDto();
        renewalInfo.setRefreshMinInterval(600);
        renewalInfo.setRefreshDefaultInterval(1200);
        renewalInfo.setRefreshMaxInterval(7200);
        renewalInfo.setRefreshBatchSize(50);
        renewalInfo.setRefreshRecheckInterval(86400);

        // when
        settingService.updatePlatformSettings(update(renewalInfo));

        // then
        CertificateSettingsDto certificates = settingService.getPlatformSettings().getCertificates();
        assertThat(certificates.getRenewalInfo().getRefreshMinInterval()).isEqualTo(600);
        assertThat(certificates.getRenewalInfo().getRefreshDefaultInterval()).isEqualTo(1200);
        assertThat(certificates.getRenewalInfo().getRefreshMaxInterval()).isEqualTo(7200);
        assertThat(certificates.getRenewalInfo().getRefreshBatchSize()).isEqualTo(50);
        assertThat(certificates.getRenewalInfo().getRefreshRecheckInterval()).isEqualTo(86400);
        assertThat(certificates.getValidation()).isNotNull();
        assertThat(certificates.getRegistration()).isNotNull();
    }

    @Test
    void rejectsTheUpdate_whenIntervalsAreOutOfOrder() {
        // given
        CertificateRenewalInfoSettingsUpdateDto renewalInfo = new CertificateRenewalInfoSettingsUpdateDto();
        renewalInfo.setRefreshMinInterval(7200);
        renewalInfo.setRefreshDefaultInterval(3600);
        renewalInfo.setRefreshMaxInterval(86400);
        PlatformSettingsUpdateDto update = update(renewalInfo);

        // when
        ThrowingCallable updateSettings = () -> settingService.updatePlatformSettings(update);

        // then
        assertThatThrownBy(updateSettings).isInstanceOf(ValidationException.class);
    }

    @Test
    void rejectsTheUpdate_whenBatchSizeIsAboveTheLimit() {
        // given
        CertificateRenewalInfoSettingsUpdateDto renewalInfo = new CertificateRenewalInfoSettingsUpdateDto();
        renewalInfo.setRefreshBatchSize(51);
        PlatformSettingsUpdateDto update = update(renewalInfo);

        // when
        ThrowingCallable updateSettings = () -> settingService.updatePlatformSettings(update);

        // then
        assertThatThrownBy(updateSettings).isInstanceOf(ValidationException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static PlatformSettingsUpdateDto update(CertificateRenewalInfoSettingsUpdateDto renewalInfo) {
        CertificateSettingsUpdateDto certificates = new CertificateSettingsUpdateDto();
        certificates.setRenewalInfo(renewalInfo);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setCertificates(certificates);
        return update;
    }
}
