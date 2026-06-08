package com.czertainly.core.signing.record;

import com.czertainly.core.model.signing.SigningRecordPolicyModel;

/**
 * Decides what a {@link SigningRecordPolicyModel} is configured to record about a signing operation.
 * Writers consult this before producing a record, so versions that capture nothing are skipped early.
 */
public final class SigningRecordPolicy {

    private SigningRecordPolicy() {
    }

    /**
     * Whether the version is configured to record anything at all about a signing operation.
     */
    public static boolean hasAnyRecordableContent(SigningRecordPolicyModel policy) {
        return policy.recordRequestMetadata()
                || policy.recordSignature()
                || policy.recordSignedDocument()
                || policy.recordDtbs();
    }
}
