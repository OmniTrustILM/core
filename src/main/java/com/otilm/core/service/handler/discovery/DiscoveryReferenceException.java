package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorServerException;
import com.otilm.core.attribute.engine.ForeignReferenceException;
import com.otilm.core.attribute.engine.MissingReferenceException;
import com.otilm.core.attribute.engine.ReferenceExpansionException;
import org.springframework.http.HttpStatus;

/**
 * A Discovery v2 call Core did not make because it could not resolve the run's references. Its message is Core's own,
 * so the run's failure reason can carry it: it names the reference for Core's own reference refusals, and only says
 * that a referenced object could not be loaded otherwise, as another connector's words may be in that failure.
 */
public class DiscoveryReferenceException extends ConnectorServerException {

    private static final String PREFIX = "Core could not resolve the run's references: ";

    private DiscoveryReferenceException(String reason, Throwable cause) {
        super(PREFIX + reason, cause, HttpStatus.BAD_GATEWAY);
    }

    /** A refusal the resolver raised, naming the reference when the refusal is one of Core's own. */
    public static DiscoveryReferenceException refused(RuntimeException refusal) {
        boolean coresOwn = refusal instanceof ForeignReferenceException || refusal instanceof MissingReferenceException
                || refusal instanceof ReferenceExpansionException;
        return new DiscoveryReferenceException(
                coresOwn ? refusal.getMessage() : "a referenced object could not be loaded.", refusal);
    }

    /** A failure of another connector the resolver asked, such as a secret's vault. */
    public static DiscoveryReferenceException failed(Exception failure) {
        return new DiscoveryReferenceException("a referenced object could not be loaded from its connector.", failure);
    }
}
