package com.otilm.core.signing.contentsigning.state;

import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.signing.engine.state.TransitionGuard;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ContentSigningTransitionsTest {

    @Test
    void guardPermitsEveryEdgeOfTheLadderInOrder() {
        // given
        TransitionGuard<ContentSigningCursor> guard = ContentSigningTransitions.guard();

        // when / then: the whole ladder, including the rungs above the executable B+T range
        assertThat(guard.canTransition(ContentSigningCursor.DTBS_COMPUTED, ContentSigningCursor.SIGNATURE_ACQUIRED))
                .isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.SIGNATURE_ACQUIRED, ContentSigningCursor.SIGNED)).isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.SIGNED, ContentSigningCursor.SIG_TIMESTAMP_ACQUIRED))
                .isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.SIG_TIMESTAMP_ACQUIRED, ContentSigningCursor.TIMESTAMPED))
                .isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.TIMESTAMPED, ContentSigningCursor.LONG_TERM)).isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.LONG_TERM, ContentSigningCursor.ARCHIVE_TIMESTAMP_ACQUIRED))
                .isTrue();
        assertThat(guard.canTransition(ContentSigningCursor.ARCHIVE_TIMESTAMP_ACQUIRED, ContentSigningCursor.ARCHIVAL))
                .isTrue();
    }

    @Test
    void guardRefusesASkippedRung() {
        // given
        TransitionGuard<ContentSigningCursor> guard = ContentSigningTransitions.guard();

        // when / then: skipping the signature acquisition would sign nothing
        assertThat(guard.canTransition(ContentSigningCursor.DTBS_COMPUTED, ContentSigningCursor.SIGNED)).isFalse();
        assertThat(guard.canTransition(ContentSigningCursor.SIGNED, ContentSigningCursor.TIMESTAMPED)).isFalse();
    }

    @Test
    void guardRefusesGoingBackwards() {
        // given
        TransitionGuard<ContentSigningCursor> guard = ContentSigningTransitions.guard();

        // when / then
        assertThat(guard.canTransition(ContentSigningCursor.SIGNED, ContentSigningCursor.DTBS_COMPUTED)).isFalse();
    }

    @Test
    void exitCursorNamesTheCursorThatCompletesEachLevel() {
        // when / then
        assertThat(ContentSigningTransitions.exitCursorFor(SignatureLevel.SIGNED))
                .isEqualTo(ContentSigningCursor.SIGNED);
        assertThat(ContentSigningTransitions.exitCursorFor(SignatureLevel.TIMESTAMPED))
                .isEqualTo(ContentSigningCursor.TIMESTAMPED);
        assertThat(ContentSigningTransitions.exitCursorFor(SignatureLevel.LONG_TERM))
                .isEqualTo(ContentSigningCursor.LONG_TERM);
        assertThat(ContentSigningTransitions.exitCursorFor(SignatureLevel.ARCHIVAL))
                .isEqualTo(ContentSigningCursor.ARCHIVAL);
    }
}
