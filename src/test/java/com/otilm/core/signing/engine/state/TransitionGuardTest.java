package com.otilm.core.signing.engine.state;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TransitionGuardTest {

    private enum Cursor {
        STARTED,
        MIDDLE,
        FINISHED
    }

    /** STARTED branches, the way a level cursor either exits at its target or carries on to the next level. */
    private static final TransitionGuard<Cursor> GUARD = new TransitionGuard<>(Cursor.class,
            List
                    .of(new StateTransition<>(Cursor.STARTED, Cursor.MIDDLE),
                            new StateTransition<>(Cursor.STARTED, Cursor.FINISHED),
                            new StateTransition<>(Cursor.MIDDLE, Cursor.FINISHED)));

    @Test
    void permitsEveryTargetOfABranchingState() {
        // when / then
        assertThat(GUARD.canTransition(Cursor.STARTED, Cursor.MIDDLE)).isTrue();
        assertThat(GUARD.canTransition(Cursor.STARTED, Cursor.FINISHED)).isTrue();
    }

    @Test
    void refusesAReversedEdge() {
        // when / then
        assertThat(GUARD.canTransition(Cursor.FINISHED, Cursor.MIDDLE)).isFalse();
    }

    @Test
    void refusesAnyMoveFromAStateWithNoOutgoingEdge() {
        // when / then
        assertThat(GUARD.canTransition(Cursor.FINISHED, Cursor.STARTED)).isFalse();
    }

    @Test
    void requireTransitionAcceptsAPermittedMove() {
        // when / then
        assertThatCode(() -> GUARD.requireTransition(Cursor.MIDDLE, Cursor.FINISHED)).doesNotThrowAnyException();
    }

    @Test
    void requireTransitionNamesBothStatesWhenRefusing() {
        // when / then
        assertThatThrownBy(() -> GUARD.requireTransition(Cursor.MIDDLE, Cursor.STARTED))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("MIDDLE")
                .hasMessageContaining("STARTED");
    }
}
