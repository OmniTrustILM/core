package com.otilm.core.service.renewal;

import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.service.renewal.WindowWrite.Authority;
import com.otilm.core.service.renewal.WindowWrite.AuthorityNoAdvice;
import com.otilm.core.service.renewal.WindowWrite.Forced;
import com.otilm.core.service.renewal.WindowWrite.Policy;
import com.otilm.core.service.renewal.WindowWrite.RaProfileReset;
import java.time.Instant;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class RenewalWindowRulesTest {

    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final Instant EARLIER_UPDATE = Instant.parse("2026-11-01T10:00:00Z");
    private static final Window POLICY_WINDOW = window("2026-12-10T00:00:00Z", "2026-12-20T00:00:00Z");
    private static final Window AUTHORITY_WINDOW = window("2026-12-05T00:00:00Z", "2026-12-08T00:00:00Z");
    private static final Window FORCED_WINDOW = window("2026-11-23T10:00:00Z", "2026-11-24T10:00:00Z");
    private static final Window BEFORE_FORCED_WINDOW = window("2026-11-23T09:00:00Z", "2026-11-23T12:00:00Z");
    private static final Window AFTER_POLICY_WINDOW = window("2026-12-15T00:00:00Z", "2026-12-25T00:00:00Z");
    private static final String URL = "https://ca.example.com/why";

    private static final RenewalState ABSENT = RenewalState.NONE;
    private static final RenewalState POLICY = state(POLICY_WINDOW, null, RenewalWindowSource.POLICY);
    private static final RenewalState AUTHORITY = state(AUTHORITY_WINDOW, URL, RenewalWindowSource.AUTHORITY);
    private static final RenewalState FORCED = state(FORCED_WINDOW, null, RenewalWindowSource.FORCED);

    @ParameterizedTest(name = "{0}")
    @MethodSource("ruleTable")
    void appliesTheEffectiveWindowRule(String row, RenewalState current, WindowWrite write, RenewalState expected,
            boolean expectedChanged, boolean expectedAdvanced) {
        // when
        RuleOutcome outcome = RenewalWindowRules.apply(current, write, NOW);

        // then
        assertThat(outcome.windowChanged()).isEqualTo(expectedChanged);
        assertThat(outcome.advanced()).isEqualTo(expectedAdvanced);
        assertThat(outcome.next().sameWindowAs(expected)).isTrue();
    }

    @Test
    void keepsTheStoredStateUntouched_whenTheWriteChangesNothing() {
        // given
        var current = new RenewalState(POLICY_WINDOW.start(), POLICY_WINDOW.end(), null, RenewalWindowSource.POLICY,
                EARLIER_UPDATE, true);

        // when
        RuleOutcome outcome = RenewalWindowRules.apply(current, new Policy(POLICY_WINDOW), NOW);

        // then
        assertThat(outcome.next()).isEqualTo(current);
    }

    @Test
    void stampsTheChangeTimeAndAdvancedFlag_whenTheWindowChanges() {
        // when
        RuleOutcome outcome = RenewalWindowRules.apply(POLICY, new Authority(AUTHORITY_WINDOW, URL), NOW);

        // then
        assertThat(outcome.next().updatedAt()).isEqualTo(NOW);
        assertThat(outcome.next().advanced()).isTrue();
        assertThat(outcome.next().explanationUrl()).isEqualTo(URL);
    }

    @Test
    void clearsTheAdvancedFlag_whenAPolicyWriteChangesAnAdvancedWindow() {
        // given
        var advancedWithoutWindow = new RenewalState(null, null, null, null, EARLIER_UPDATE, true);

        // when
        RuleOutcome outcome = RenewalWindowRules.apply(advancedWithoutWindow, new Policy(POLICY_WINDOW), NOW);

        // then
        assertThat(outcome.next().advanced()).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> ruleTable() {
        return Stream
                .of(arguments("policy over absent -> POLICY", ABSENT, new Policy(POLICY_WINDOW), POLICY, true, false),
                        arguments("policy over POLICY with a new window -> POLICY", POLICY,
                                new Policy(AFTER_POLICY_WINDOW),
                                state(AFTER_POLICY_WINDOW, null, RenewalWindowSource.POLICY), true, false),
                        arguments("policy over AUTHORITY -> unchanged", AUTHORITY, new Policy(POLICY_WINDOW), AUTHORITY,
                                false, false),
                        arguments("policy over FORCED -> unchanged", FORCED, new Policy(POLICY_WINDOW), FORCED, false,
                                false),
                        arguments("policy off over POLICY -> none", POLICY, new Policy(null), ABSENT, true, false),
                        arguments("policy off over absent -> unchanged", ABSENT, new Policy(null), ABSENT, false,
                                false),
                        arguments("policy off over FORCED -> unchanged", FORCED, new Policy(null), FORCED, false,
                                false),
                        arguments("policy moving the start earlier never sets advanced",
                                state(AFTER_POLICY_WINDOW, null, RenewalWindowSource.POLICY), new Policy(POLICY_WINDOW),
                                POLICY, true, false),
                        arguments("authority over POLICY -> AUTHORITY", POLICY, new Authority(AUTHORITY_WINDOW, URL),
                                AUTHORITY, true, true),
                        arguments("authority over absent -> AUTHORITY", ABSENT, new Authority(AUTHORITY_WINDOW, URL),
                                AUTHORITY, true, false),
                        arguments("authority (later start) over POLICY -> AUTHORITY, not advanced", POLICY,
                                new Authority(AFTER_POLICY_WINDOW, null),
                                state(AFTER_POLICY_WINDOW, null, RenewalWindowSource.AUTHORITY), true, false),
                        arguments("authority over AUTHORITY -> AUTHORITY", AUTHORITY,
                                new Authority(POLICY_WINDOW, null),
                                state(POLICY_WINDOW, null, RenewalWindowSource.AUTHORITY), true, false),
                        arguments("authority (later start) over FORCED -> unchanged", FORCED,
                                new Authority(AUTHORITY_WINDOW, URL), FORCED, false, false),
                        arguments("authority (same start) over FORCED -> unchanged", FORCED,
                                new Authority(FORCED_WINDOW, URL), FORCED, false, false),
                        arguments("authority (earlier start) over FORCED -> AUTHORITY, advanced", FORCED,
                                new Authority(BEFORE_FORCED_WINDOW, URL),
                                state(BEFORE_FORCED_WINDOW, URL, RenewalWindowSource.AUTHORITY), true, true),
                        arguments("authority without advice over AUTHORITY -> none", AUTHORITY, new AuthorityNoAdvice(),
                                ABSENT, true, false),
                        arguments("authority without advice over POLICY -> unchanged", POLICY, new AuthorityNoAdvice(),
                                POLICY, false, false),
                        arguments("authority without advice over FORCED -> unchanged", FORCED, new AuthorityNoAdvice(),
                                FORCED, false, false),
                        arguments("forced over absent -> FORCED, not advanced", ABSENT, new Forced(FORCED_WINDOW, null),
                                FORCED, true, false),
                        arguments("forced over POLICY -> FORCED, advanced", POLICY, new Forced(FORCED_WINDOW, null),
                                FORCED, true, true),
                        arguments("forced over AUTHORITY -> FORCED, advanced", AUTHORITY,
                                new Forced(FORCED_WINDOW, null), FORCED, true, true),
                        arguments("forced (later start) over FORCED -> FORCED, not advanced",
                                state(BEFORE_FORCED_WINDOW, null, RenewalWindowSource.FORCED),
                                new Forced(FORCED_WINDOW, null), FORCED, true, false),
                        arguments("forced (later start) over POLICY -> FORCED, not advanced", POLICY,
                                new Forced(AFTER_POLICY_WINDOW, URL),
                                state(AFTER_POLICY_WINDOW, URL, RenewalWindowSource.FORCED), true, false),
                        arguments("forced with the same window -> unchanged", FORCED, new Forced(FORCED_WINDOW, null),
                                FORCED, false, false),
                        arguments("RA profile reset with FORCED -> FORCED kept", FORCED, new RaProfileReset(), FORCED,
                                false, false),
                        arguments("RA profile reset with AUTHORITY -> none", AUTHORITY, new RaProfileReset(), ABSENT,
                                true, false),
                        arguments("RA profile reset with POLICY -> none", POLICY, new RaProfileReset(), ABSENT, true,
                                false),
                        arguments("RA profile reset with absent -> unchanged", ABSENT, new RaProfileReset(), ABSENT,
                                false, false),
                        arguments("unchanged policy write -> not changed", POLICY, new Policy(POLICY_WINDOW), POLICY,
                                false, false),
                        arguments("unchanged authority write -> not changed", AUTHORITY,
                                new Authority(AUTHORITY_WINDOW, URL), AUTHORITY, false, false));
    }

    private static Window window(String start, String end) {
        return new Window(Instant.parse(start), Instant.parse(end));
    }

    private static RenewalState state(Window window, String url, RenewalWindowSource source) {
        return new RenewalState(window.start(), window.end(), url, source, EARLIER_UPDATE, false);
    }
}
