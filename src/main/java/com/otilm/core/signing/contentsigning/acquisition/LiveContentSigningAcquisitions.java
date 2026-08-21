package com.otilm.core.signing.contentsigning.acquisition;

import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.signer.SignerFactory;
import com.otilm.core.signing.tsa.InternalTimestampSource;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import org.springframework.stereotype.Component;

/** Acquires within one synchronous run: the key signs now, the timestamp is issued now, nothing is persisted. */
@Component
public class LiveContentSigningAcquisitions implements ContentSigningAcquisitions {

    private final SignerFactory signerFactory;
    private final InternalTimestampSource timestampSource;

    public LiveContentSigningAcquisitions(SignerFactory signerFactory, InternalTimestampSource timestampSource) {
        this.signerFactory = signerFactory;
        this.timestampSource = timestampSource;
    }

    @Override
    public byte[] signatureValue(ResolvedManagedContentSigningProfile profile, byte[] dtbs)
            throws SigningEngineException {
        return signerFactory.create(profile.resolvedScheme()).sign(dtbs);
    }

    @Override
    public IssuedTimestamp signatureTimestamp(ResolvedManagedContentSigningProfile profile, TimestampImprint imprint,
            String step) throws SigningEngineException {
        if (profile.timestampSourceProfileName() == null) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' names no timestamp source, so no timestamp can be embedded"
                            .formatted(profile.name()),
                    "Internal error while timestamping the signature");
        }
        return timestampSource.timestamp(imprint, profile.timestampSourceProfileName(), step);
    }
}
