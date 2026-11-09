package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BatchAdmissionTest {

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
    void refusesNamingTheCap_whenItemsExceedTheConfiguredCap() {
        // given
        var configuredCap = 2;
        cacheCap(configuredCap);
        List<String> threeItems = List.of("doc-1", "doc-2", "doc-3");

        // when
        ThrowingCallable admit = () -> BatchAdmission.admit(threeItems);

        // then
        assertThatThrownBy(admit)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT))
                .hasMessageContaining("at most " + configuredCap + " items");
    }

    @Test
    void admits_whenItemsReachTheCapExactly() {
        // given
        cacheCap(3);
        List<String> threeItems = List.of("doc-1", "doc-2", "doc-3");

        // when
        ThrowingCallable admit = () -> BatchAdmission.admit(threeItems);

        // then
        assertThatCode(admit).doesNotThrowAnyException();
    }

    @Test
    void refusesOnTheRepeatedItem_whenAnIdentifierRepeats() {
        // given
        cacheCap(4);
        var repeated = "doc-2";
        List<String> withRepeat = List.of("doc-1", repeated, "doc-3", repeated);

        // when
        ThrowingCallable admit = () -> BatchAdmission.admit(withRepeat);

        // then
        assertThatThrownBy(admit).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.itemIdentifier()).isEqualTo(repeated);
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void cacheCap(int maxItemsPerRequest) {
        SigningSettingsDto signing = new SigningSettingsDto();
        signing.setMaxItemsPerRequest(maxItemsPerRequest);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setSigning(signing);
        new SettingsCache().cacheSettings(SettingsSection.PLATFORM, platform);
    }
}
