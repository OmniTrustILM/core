package com.czertainly.core.signing.tsa;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import org.bouncycastle.tsp.TimeStampToken;

import java.math.BigInteger;
import java.time.Instant;

public interface ManagedTimestampTokenGenerator {

    TimeStampToken generate(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile,
                            CertificateChain certificateChain, BigInteger serialNumber, Instant genTime
    ) throws TspException;
}
