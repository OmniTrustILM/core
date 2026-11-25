package com.otilm.core.service.renewal;

/**
 * The result of applying a write to a renewal state.
 *
 * @param next the state to store; the current state itself when nothing changed
 * @param windowChanged whether the window, its explanation or its source changed
 * @param advanced whether the change moved an existing window's start earlier on the authority's or an administrator's
 * word
 */
public record RuleOutcome(RenewalState next, boolean windowChanged, boolean advanced) {
}
