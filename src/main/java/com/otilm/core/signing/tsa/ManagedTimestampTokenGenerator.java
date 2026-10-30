package com.otilm.core.signing.tsa;

import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.tsa.messages.TspRequest;
import java.math.BigInteger;
import java.time.Instant;
import org.bouncycastle.tsp.TimeStampToken;

public interface ManagedTimestampTokenGenerator {

    TimeStampToken generate(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile,
            CertificateChain certificateChain, BigInteger serialNumber, Instant genTime) throws SigningEngineException;
}
