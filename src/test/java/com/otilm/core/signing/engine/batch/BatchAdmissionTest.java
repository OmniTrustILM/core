package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

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
        var configuredCap = 3;
        cacheCap(configuredCap);
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

    @ParameterizedTest
    @MethodSource("platformSettingsWithoutACap")
    void admitsTheDefaultCapOfItems_whenNoCapIsConfigured(PlatformSettingsDto withoutACap) {
        // given
        cachePlatformSettings(withoutACap);
        List<String> defaultCapOfItems = createItems(SigningSettingsDto.DEFAULT_MAX_ITEMS_PER_REQUEST);

        // when
        ThrowingCallable admit = () -> BatchAdmission.admit(defaultCapOfItems);

        // then
        assertThatCode(admit).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @MethodSource("platformSettingsWithoutACap")
    void refusesNamingTheDefaultCap_whenNoCapIsConfigured(PlatformSettingsDto withoutACap) {
        // given
        cachePlatformSettings(withoutACap);
        var defaultCap = SigningSettingsDto.DEFAULT_MAX_ITEMS_PER_REQUEST;
        List<String> onePastTheDefaultCap = createItems(defaultCap + 1);

        // when
        ThrowingCallable admit = () -> BatchAdmission.admit(onePastTheDefaultCap);

        // then
        assertThatThrownBy(admit)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT))
                .hasMessageContaining("at most " + defaultCap + " items");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void cacheCap(int maxItemsPerRequest) {
        SigningSettingsDto signing = new SigningSettingsDto();
        signing.setMaxItemsPerRequest(maxItemsPerRequest);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setSigning(signing);
        cachePlatformSettings(platform);
    }

    private static void cachePlatformSettings(PlatformSettingsDto platform) {
        new SettingsCache().cacheSettings(SettingsSection.PLATFORM, platform);
    }

    private static List<String> createItems(int count) {
        return IntStream.rangeClosed(1, count).mapToObj(i -> "doc-" + i).toList();
    }

    private static Stream<Named<PlatformSettingsDto>> platformSettingsWithoutACap() {
        PlatformSettingsDto withUnsetCap = new PlatformSettingsDto();
        withUnsetCap.setSigning(new SigningSettingsDto());
        return Stream
                .of(named("no signing section", new PlatformSettingsDto()),
                        named("signing section without a cap", withUnsetCap));
    }
}
