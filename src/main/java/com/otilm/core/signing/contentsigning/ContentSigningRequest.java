package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import java.util.Objects;

/**
 * One content-signing run's input.
 *
 * @param targetLevel the level asked for, which the profile's ceiling has the final say over
 * @param document how the document travels to the connector — inline, or as a digest for detached packaging
 * @param authorizedDigest the digest of the document the caller authorized, which the binding gate compares the
 * connector's echo against
 */
public record ContentSigningRequest(SignatureLevel targetLevel, DocumentTransferDto document,
        DocumentDigest authorizedDigest) {

    public ContentSigningRequest {
        Objects.requireNonNull(targetLevel, "targetLevel");
        Objects.requireNonNull(document, "document");
        Objects.requireNonNull(authorizedDigest, "authorizedDigest");
    }
}
