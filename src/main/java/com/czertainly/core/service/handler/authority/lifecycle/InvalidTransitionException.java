package com.czertainly.core.service.handler.authority.lifecycle;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.auth.Resource;

import java.util.UUID;

/**
 * Thrown when {@link CertificateStateMachine#transition} is called with a (from, to) pair
 * that has no row in {@link CertificateStateTransition}. Carries the attempted transition
 * (operator intent), not internal event vocabulary.
 *
 * <p>Generic — designed to be reused for future state machines (Secret, CryptographicKey).
 * Both state types must implement {@link IPlatformEnum} so labels are available for messages.</p>
 */
public class InvalidTransitionException extends ValidationException {

    private final Resource resource;
    private final UUID resourceUuid;
    private final IPlatformEnum fromState;
    private final IPlatformEnum toStateAttempted;

    public InvalidTransitionException(Resource resource, UUID resourceUuid,
                                      IPlatformEnum fromState, IPlatformEnum toStateAttempted) {
        super(ValidationError.create(
            "Cannot transition %s '%s' from state '%s' to '%s'".formatted(
                resource.getLabel(), resourceUuid,
                fromState.getLabel(), toStateAttempted.getLabel())));
        this.resource = resource;
        this.resourceUuid = resourceUuid;
        this.fromState = fromState;
        this.toStateAttempted = toStateAttempted;
    }

    public Resource getResource() { return resource; }
    public UUID getResourceUuid() { return resourceUuid; }
    public IPlatformEnum getFromState() { return fromState; }
    public IPlatformEnum getToStateAttempted() { return toStateAttempted; }
}
