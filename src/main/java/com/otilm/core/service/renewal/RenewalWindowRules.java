package com.otilm.core.service.renewal;

import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.service.renewal.WindowWrite.Authority;
import com.otilm.core.service.renewal.WindowWrite.AuthorityNoAdvice;
import com.otilm.core.service.renewal.WindowWrite.Forced;
import com.otilm.core.service.renewal.WindowWrite.Policy;
import com.otilm.core.service.renewal.WindowWrite.RaProfileReset;
import java.time.Instant;

/**
 * Decides the effective renewal window of a certificate from its current state and a write:
 * <ul>
 * <li>a policy window sets or removes only a window that came from the policy, or a missing one;</li>
 * <li>an authority window replaces a policy or authority window, and a forced one only when it starts earlier;</li>
 * <li>a forced window always replaces the current one;</li>
 * <li>an authority without advice, or a new RA profile, removes an authority window; a new RA profile also removes a
 * policy window. A forced window stays.</li>
 * </ul>
 * A change marks the state {@code advanced} when an authority or forced window moves an existing start earlier.
 */
public final class RenewalWindowRules {

    private RenewalWindowRules() {
    }

    public static RuleOutcome apply(RenewalState current, WindowWrite write, Instant now) {
        RenewalState candidate = switch (write) {
            case Policy(Window window) -> applyPolicy(current, window);
            case Authority authority -> applyAuthority(current, authority);
            case AuthorityNoAdvice ignored -> removeIfSource(current, RenewalWindowSource.AUTHORITY);
            case Forced(Window window, String explanationUrl) ->
                window(window, explanationUrl, RenewalWindowSource.FORCED);
            case RaProfileReset ignored -> current.source() == RenewalWindowSource.FORCED ? current : RenewalState.NONE;
        };
        if (candidate.sameWindowAs(current)) {
            return new RuleOutcome(current, false, false);
        }
        boolean advanced = !(write instanceof Policy) && movesStartEarlier(current, candidate);
        RenewalState next = new RenewalState(candidate.windowStart(), candidate.windowEnd(), candidate.explanationUrl(),
                candidate.source(), now, advanced);
        return new RuleOutcome(next, true, advanced);
    }

    private static RenewalState applyPolicy(RenewalState current, Window window) {
        if (current.hasWindow() && current.source() != RenewalWindowSource.POLICY) {
            return current;
        }
        return window == null ? RenewalState.NONE : window(window, null, RenewalWindowSource.POLICY);
    }

    private static RenewalState applyAuthority(RenewalState current, Authority authority) {
        if (current.source() == RenewalWindowSource.FORCED
                && !authority.window().start().isBefore(current.windowStart())) {
            return current;
        }
        return window(authority.window(), authority.explanationUrl(), RenewalWindowSource.AUTHORITY);
    }

    private static RenewalState removeIfSource(RenewalState current, RenewalWindowSource source) {
        return current.source() == source ? RenewalState.NONE : current;
    }

    private static boolean movesStartEarlier(RenewalState current, RenewalState next) {
        return current.hasWindow() && next.hasWindow() && next.windowStart().isBefore(current.windowStart());
    }

    private static RenewalState window(Window window, String explanationUrl, RenewalWindowSource source) {
        return new RenewalState(window.start(), window.end(), explanationUrl, source, null, false);
    }
}
