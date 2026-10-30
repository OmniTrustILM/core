package com.otilm.core.signing.engine.state;

import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Validates cursor moves against a {@code (from, to)} table the workflow supplies, so the engine carries no cursor
 * vocabulary of its own. Assigning the initial cursor is the workflow's own business and bypasses the guard.
 */
public final class TransitionGuard<S extends Enum<S>> {

    private final Map<S, Set<S>> permittedTargets;

    public TransitionGuard(Class<S> cursorType, Collection<StateTransition<S>> table) {
        Objects.requireNonNull(cursorType, "cursorType");
        Objects.requireNonNull(table, "table");
        Map<S, Set<S>> targets = new EnumMap<>(cursorType);
        table.forEach(edge -> targets.computeIfAbsent(edge.from(), from -> EnumSet.noneOf(cursorType)).add(edge.to()));
        this.permittedTargets = targets;
    }

    /**
     * Whether the table permits the move. Lets a resuming run skip a step it already took rather than tripping
     * {@link #requireTransition}.
     */
    public boolean canTransition(S from, S to) {
        return permittedTargets.getOrDefault(from, Set.of()).contains(to);
    }

    /**
     * Asserts the move is permitted.
     *
     * @throws IllegalStateException if the table does not permit it — reaching an undefined edge is an engine bug, not
     * something a caller supplied
     */
    public void requireTransition(S from, S to) {
        if (!canTransition(from, to)) {
            throw new IllegalStateException("Cannot transition from '%s' to '%s'".formatted(from, to));
        }
    }
}
