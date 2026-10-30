package com.otilm.core.signing.engine.state;

import java.util.Objects;

/**
 * One permitted {@code (from, to)} edge of a workflow's transition table.
 */
public record StateTransition<S extends Enum<S>>(S from, S to) {

    public StateTransition {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
    }
}
