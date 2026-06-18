package com.otilm.core.signing.record;

import com.otilm.core.model.signing.SigningProfileModel;

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

    SigningProfileModel<?, ?> signingProfile();

    SigningRecordInput build();
}
