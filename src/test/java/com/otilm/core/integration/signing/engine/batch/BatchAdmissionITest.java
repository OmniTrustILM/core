package com.otilm.core.integration.signing.engine.batch;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.batch.BatchAdmission;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BatchAdmissionITest extends BaseSpringBootTest {

    @Autowired
    private SettingExternalService settingService;

    private PlatformSettingsDto originalPlatformSettings;

    @BeforeEach
    void rememberTheCache() {
        originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
    }

    @AfterEach
    void restoreTheCache() {
        new SettingsCache()
                .cacheSettings(SettingsSection.PLATFORM,
                        originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
    }

    @Test
    void refusesTheNextRequest_whenAnOperatorLowersTheCapWithoutARestart() {
        // given
        List<String> threeItems = List.of("doc-1", "doc-2", "doc-3");
        settingService.updatePlatformSettings(signingCap(3));
        ThrowingCallable admitThreeItems = () -> BatchAdmission.admit(threeItems);
        assertThatCode(admitThreeItems).doesNotThrowAnyException();

        // when
        var loweredCap = 2;
        settingService.updatePlatformSettings(signingCap(loweredCap));

        // then
        assertThatThrownBy(admitThreeItems)
                .isInstanceOf(SigningEngineException.class)
                .hasMessageContaining("at most " + loweredCap + " items");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static PlatformSettingsUpdateDto signingCap(int maxItemsPerRequest) {
        SigningSettingsDto signing = new SigningSettingsDto();
        signing.setMaxItemsPerRequest(maxItemsPerRequest);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setSigning(signing);
        return update;
    }
}
