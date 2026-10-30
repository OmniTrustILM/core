package com.otilm.core.integration.service.impl;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.core.certificate.request.DefaultRequestAttributeSet;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@Transactional
class RaProfileCertificateRequestAttributeServiceStrictITest extends BaseSpringBootTest {

    @Autowired
    private RaProfileCertificateRequestAttributeService service;

    @Autowired
    private SettingRepository settingRepository;

    @Test
    void defaultsToLenient_whenNothingConfigured() {
        // given — an RA profile with no per-profile config and no platform strict setting seeded
        RaProfile raProfile = new RaProfile();
        raProfile.setName("test-ra");

        // when / then — resolution falls through to lenient (false)
        assertThat(service.resolveExternalCsrValidationStrict(raProfile)).isFalse();
    }

    @Test
    void usesPlatformDefault_whenNoPerProfileOverride() {
        // given — no per-profile override, but the platform strict setting is seeded true
        RaProfile raProfile = new RaProfile();
        raProfile.setName("test-ra");
        seedPlatformStrictSetting("true");

        // when / then — resolution falls back to the platform default (true)
        assertThat(service.resolveExternalCsrValidationStrict(raProfile)).isTrue();
    }

    @Test
    void usesPlatformDefault_whenPlatformSettingDisablesStrict() {
        // given — no per-profile override and the platform strict setting explicitly false
        RaProfile raProfile = new RaProfile();
        raProfile.setName("test-ra");
        seedPlatformStrictSetting("false");

        // when / then — the platform default (false) is honoured, not silently treated as strict
        assertThat(service.resolveExternalCsrValidationStrict(raProfile)).isFalse();
    }

    private void seedPlatformStrictSetting(String value) {
        Setting setting = new Setting();
        setting.setSection(SettingsSection.PLATFORM);
        setting.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        setting.setName(DefaultRequestAttributeSet.STRICT_SETTING_NAME);
        setting.setValue(value);
        settingRepository.save(setting);
    }
}
