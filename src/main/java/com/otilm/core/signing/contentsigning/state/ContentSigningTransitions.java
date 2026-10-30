package com.otilm.core.signing.contentsigning.state;

import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.signing.engine.state.StateTransition;
import com.otilm.core.signing.engine.state.TransitionGuard;
import java.util.List;

/**
 * The content-signing ladder as a {@code (from, to)} table. The table spans every rung.
 */
public final class ContentSigningTransitions {

    private static final TransitionGuard<ContentSigningCursor> GUARD = new TransitionGuard<>(ContentSigningCursor.class,
            List
                    .of(new StateTransition<>(ContentSigningCursor.DTBS_COMPUTED,
                            ContentSigningCursor.SIGNATURE_ACQUIRED),
                            new StateTransition<>(ContentSigningCursor.SIGNATURE_ACQUIRED, ContentSigningCursor.SIGNED),
                            new StateTransition<>(ContentSigningCursor.SIGNED,
                                    ContentSigningCursor.SIG_TIMESTAMP_ACQUIRED),
                            new StateTransition<>(ContentSigningCursor.SIG_TIMESTAMP_ACQUIRED,
                                    ContentSigningCursor.TIMESTAMPED),
                            new StateTransition<>(ContentSigningCursor.TIMESTAMPED, ContentSigningCursor.LONG_TERM),
                            new StateTransition<>(ContentSigningCursor.LONG_TERM,
                                    ContentSigningCursor.ARCHIVE_TIMESTAMP_ACQUIRED),
                            new StateTransition<>(ContentSigningCursor.ARCHIVE_TIMESTAMP_ACQUIRED,
                                    ContentSigningCursor.ARCHIVAL)));

    /**
     * The highest rung any step reaches today. Raising it requires the matching ladder steps to exist here and in the
     * engine.
     */
    public static final SignatureLevel HIGHEST_EXECUTABLE_LEVEL = SignatureLevel.TIMESTAMPED;

    private ContentSigningTransitions() {
    }

    public static TransitionGuard<ContentSigningCursor> guard() {
        return GUARD;
    }

    /** The cursor a run has reached once it has produced a signature at {@code level}. */
    public static ContentSigningCursor exitCursorFor(SignatureLevel level) {
        return switch (level) {
            case SIGNED -> ContentSigningCursor.SIGNED;
            case TIMESTAMPED -> ContentSigningCursor.TIMESTAMPED;
            case LONG_TERM -> ContentSigningCursor.LONG_TERM;
            case ARCHIVAL -> ContentSigningCursor.ARCHIVAL;
        };
    }
}
