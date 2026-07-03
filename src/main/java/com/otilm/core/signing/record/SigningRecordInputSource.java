package com.otilm.core.signing.record;

import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;

/**
 * A deferred {@link SigningRecordInput}: it exposes the signing profile cheaply — so a strategy can evaluate the
 * {@code recordingEnabled} gate and emit its intake metrics — while postponing the assembly of the full input
 * until recording is known to be on. The deferred part is the potentially expensive work, notably the
 * {@code requestMetadataJson} serialization, which on the TSA hot path would otherwise be built and discarded for
 * profiles that have recording disabled.
 *
 * @see com.otilm.core.signing.tsa.TspSigningRecordFactory#source
 */
public interface SigningRecordInputSource {

    /**
     * The wildcard return type is intentional: signing-profile models are resolved from a name-keyed cache as
     * {@code SigningProfileModel<? extends SigningWorkflow, ? extends SigningSchemeModel>} (see
     * {@code SigningProfileInternalService#getSigningProfileModel}), so no concrete workflow/scheme type arguments are
     * ever available here. Parameterizing this interface would only propagate always-wildcard type variables
     * through the whole strategy chain without carrying any information.
     */
    @SuppressWarnings("java:S1452")
    SigningProfileModel<? extends SigningWorkflow, ? extends SigningSchemeModel> signingProfile();

    SigningRecordInput build();
}
