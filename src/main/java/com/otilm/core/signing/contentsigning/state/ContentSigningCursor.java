package com.otilm.core.signing.contentsigning.state;

/**
 * How far a content-signing run has got. Each cursor names a completed step, and the four that share a name with a
 * {@link com.otilm.api.model.common.signature.SignatureLevel} are the levels a run can exit at.
 */
public enum ContentSigningCursor {
    DTBS_COMPUTED,
    SIGNATURE_ACQUIRED,
    SIGNED,
    SIG_TIMESTAMP_ACQUIRED,
    TIMESTAMPED,
    LONG_TERM,
    ARCHIVE_TIMESTAMP_ACQUIRED,
    ARCHIVAL
}
