package com.otilm.core.signing.tsa;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.core.util.clocksource.ClockSource;
import com.otilm.core.util.serialnumber.ClockDriftException;
import com.otilm.core.util.serialnumber.SerialNumberGenerationException;
import com.otilm.core.util.serialnumber.SerialNumberGenerator;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Objects;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Core engine that issues RFC 3161 timestamp tokens.
 *
 * <p>
 * {@link #issue} is the protocol-neutral entry point; {@link #process} wraps it for RFC 3161.
 */
@Component
public class ManagedTimestampEngine {

    private static final Logger logger = LoggerFactory.getLogger(ManagedTimestampEngine.class);

    private static final String INTERNAL_ERROR_CLIENT_MESSAGE = "Internal error";

    private final TimeQualityRegister timeQualityRegister;
    private final SerialNumberGenerator serialNumberGenerator;
    private final ManagedTimestampTokenGenerator tokenGenerator;
    private final SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    private final ClockSource clockSource;
    private final SigningRecordStrategyFactory signingRecordStrategyFactory;
    private final TimestampSigningRecordFactory timestampSigningRecordFactory;

    public ManagedTimestampEngine(TimeQualityRegister timeQualityRegister, SerialNumberGenerator serialNumberGenerator,
            ManagedTimestampTokenGenerator tokenGenerator,
            SigningCertificateValidatorFactory signingCertificateValidatorFactory, ClockSource clockSource,
            SigningRecordStrategyFactory signingRecordStrategyFactory,
            TimestampSigningRecordFactory timestampSigningRecordFactory) {
        this.timeQualityRegister = timeQualityRegister;
        this.serialNumberGenerator = serialNumberGenerator;
        this.tokenGenerator = tokenGenerator;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.clockSource = clockSource;
        this.signingRecordStrategyFactory = signingRecordStrategyFactory;
        this.timestampSigningRecordFactory = timestampSigningRecordFactory;
    }

    /**
     * Renders an {@link #issue} run as an RFC 3161 response. A failure becomes a rejection carrying the same failure
     * info and client text the protocol edge would have produced from the thrown exception.
     */
    public TspResponse process(TspRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedTimestampingProfile timestampingProfile) {
        try {
            return TspResponse
                    .granted(issue(request, signingProfile, timestampingProfile, SigningProtocol.TSP).encoded());
        } catch (SigningEngineException e) {
            return TspResponse.rejected(TspErrorMapper.toFailureInfo(e.failure()), e.clientMessage());
        }
    }

    /**
     * Issues a timestamp token below any protocol edge, reporting failures in the Signing Engine's own currency.
     *
     * @param protocol how the issuance was initiated, which is what its signing record will carry
     * @throws SigningEngineException if the time reference, the signing certificate, or token assembly does not permit
     * issuing
     */
    public IssuedTimestamp issue(TspRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedTimestampingProfile timestampingProfile, SigningProtocol protocol)
            throws SigningEngineException {
        Objects.requireNonNull(protocol, "protocol");
        try {
            return issueToken(request, signingProfile, timestampingProfile, protocol);
        } catch (SigningEngineException e) {
            logFailure(timestampingProfile, protocol, e);
            throw e;
        }
    }

    private IssuedTimestamp issueToken(TspRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedTimestampingProfile timestampingProfile, SigningProtocol protocol)
            throws SigningEngineException {
        requirePolicy(request, timestampingProfile);
        ResolvedManagedScheme signingScheme = timestampingProfile.resolvedScheme();
        requireTrustworthyTime(timestampingProfile);
        requireAcceptableSigningCertificate(timestampingProfile, signingScheme);

        try {
            BigInteger serialNumber = serialNumberGenerator.generate();
            Instant genTime = clockSource.wallTimeInstant();
            var certificateChain = signingScheme.chain();

            TimeStampToken token = tokenGenerator
                    .generate(request, timestampingProfile, certificateChain, serialNumber, genTime);
            if (Boolean.TRUE.equals(timestampingProfile.validateTokenSignature())) {
                token.validate(new JcaSimpleSignerInfoVerifierBuilder().build(certificateChain.signingCertificate()));
            }

            requireTokenBoundToRequest(token, request, serialNumber);

            byte[] encodedToken = token.getEncoded();
            recordSigning(signingProfile, request, serialNumber, genTime, encodedToken, protocol);
            return new IssuedTimestamp(encodedToken, serialNumber, genTime);

        } catch (SigningEngineException e) {
            // keeps engine failures out of the catch-all below, which would collapse their classification
            throw e;
        } catch (TSPValidationException e) {
            throw new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, "timestamp signature validation failed",
                    e, "Timestamp signature validation failed");
        } catch (ClockDriftException e) {
            throw new SigningEngineException(SigningEngineFailure.TIME_UNAVAILABLE,
                    "clock drift detected during timestamp generation", e, "Clock drift detected");
        } catch (SerialNumberGenerationException e) {
            throw new SigningEngineException(SigningEngineFailure.STEP_FAILED, "timestamp generation interrupted", e,
                    INTERNAL_ERROR_CLIENT_MESSAGE);
        } catch (Exception e) {
            throw new SigningEngineException(SigningEngineFailure.STEP_FAILED,
                    "unexpected error during timestamp generation", e, INTERNAL_ERROR_CLIENT_MESSAGE);
        }
    }

    /** Refusing here keeps the formatter from being asked to encode a policy that does not exist. */
    private static void requirePolicy(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile)
            throws SigningEngineException {
        if (EffectiveTimestampPolicy.resolve(request, timestampingProfile.defaultPolicyId()).isEmpty()) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "timestamping Signing Profile '%s' configures no default policy ID and the request names none"
                            .formatted(timestampingProfile.name()),
                    "No timestamp policy ID is available");
        }
    }

    /**
     * A timestamp asserts that a document existed at a stated moment, so an untrustworthy time reference must stop
     * issuance rather than produce a token nobody can rely on.
     */
    private void requireTrustworthyTime(ResolvedManagedTimestampingProfile timestampingProfile)
            throws SigningEngineException {
        TimeQualityConfigurationModel timeQualityConfiguration = timestampingProfile.timeQualityConfiguration();
        TimeQualityStatus timeStatus = timeQualityRegister.getStatus(timeQualityConfiguration);
        if (timeStatus != TimeQualityStatus.OK) {
            throw new SigningEngineException(SigningEngineFailure.TIME_UNAVAILABLE,
                    "time quality status is %s for timestampingProfile '%s' using timeQualityProfile '%s'"
                            .formatted(timeStatus, timestampingProfile.name(), timeQualityConfiguration.getName()),
                    "Time quality is not sufficient for timestampingProfile '%s'"
                            .formatted(timestampingProfile.name()));
        }
        logger
                .info("Time quality status for time quality configuration '{}': {}", timeQualityConfiguration.getName(),
                        timeStatus);
    }

    private void requireAcceptableSigningCertificate(ResolvedManagedTimestampingProfile timestampingProfile,
            ResolvedManagedScheme signingScheme) throws SigningEngineException {
        ValidationResult result = signingCertificateValidatorFactory
                .getValidator(signingScheme)
                .validate(signingScheme, SigningWorkflowType.TIMESTAMPING, timestampingProfile.isQualifiedTimestamp(),
                        CertificatePurposeRequirements.NONE);
        if (result instanceof ValidationResult.Nok(SigningEngineFailure failure, String logMessage, String clientMessage)) {
            throw new SigningEngineException(failure,
                    "signing certificate of timestampingProfile '%s' is not acceptable: %s"
                            .formatted(timestampingProfile.name(), logMessage),
                    clientMessage);
        }
    }

    /**
     * The connector assembles the {@code TSTInfo}, so the token it returns is only as trustworthy as its echo of what
     * was asked for. On the RFC 3161 path the client checks this itself against its own request; in-process issuance
     * has no such counterparty, and the token goes straight into a signature. The generation time is deliberately not
     * compared: its encoded precision is the connector's choice, so an exact match would be brittle without adding
     * assurance the imprint and serial do not already give.
     */
    private static void requireTokenBoundToRequest(TimeStampToken token, TspRequest request, BigInteger serialNumber)
            throws SigningEngineException {
        TimeStampTokenInfo info = token.getTimeStampInfo();
        String stampedAlgorithm = info.getMessageImprintAlgOID().getId();
        if (!request.hashAlgorithm().getOid().equals(stampedAlgorithm)) {
            throw brokenEcho("connector stamped a %s imprint but %s was requested"
                    .formatted(stampedAlgorithm, request.hashAlgorithm().getCode()));
        }
        if (!MessageDigest.isEqual(request.hashedMessage(), info.getMessageImprintDigest())) {
            throw brokenEcho("connector stamped an imprint other than the one requested");
        }
        if (!serialNumber.equals(info.getSerialNumber())) {
            throw brokenEcho("connector stamped serial number %s but %s was issued"
                    .formatted(info.getSerialNumber().toString(16), serialNumber.toString(16)));
        }
    }

    private static SigningEngineException brokenEcho(String defect) {
        return new SigningEngineException(SigningEngineFailure.CONNECTOR_FAULT, defect, INTERNAL_ERROR_CLIENT_MESSAGE);
    }

    private static void logFailure(ResolvedManagedTimestampingProfile timestampingProfile, SigningProtocol protocol,
            SigningEngineException e) {
        if (isPlatformFault(e.failure())) {
            logger
                    .error("Timestamp issuance failed for signing profile '{}' via {}: {}", timestampingProfile.name(),
                            protocol, e.operatorMessage(), e);
        } else {
            logger
                    .warn("Refusing to issue a timestamp for signing profile '{}' via {}: {}",
                            timestampingProfile.name(), protocol, e.operatorMessage());
        }
    }

    /** Exhaustive so that a new failure class has to choose its log level rather than inherit one. */
    private static boolean isPlatformFault(SigningEngineFailure failure) {
        return switch (failure) {
            case SIGNER_FAULT, STEP_FAILED, CONNECTOR_FAULT -> true;
            case INVALID_INPUT, MALFORMED_INPUT, MISCONFIGURED, TIME_UNAVAILABLE, BINDING_VIOLATION -> false;
        };
    }

    /**
     * Records the issued timestamp. The signature has already been produced by the managed key, so a recording failure
     * must never withdraw it: it is logged and swallowed, leaving the issued token intact. The engine hands the
     * strategy a deferred {@link SigningRecordInputSource} so the strategy's {@code recordingEnabled} gate
     * short-circuits disabled profiles before the input — and its request-metadata serialization — is assembled on the
     * hot path.
     */
    private void recordSigning(SigningProfileModel<?, ?> signingProfile, TspRequest request, BigInteger serialNumber,
            Instant genTime, byte[] encodedToken, SigningProtocol protocol) {
        try {
            SigningRecordInputSource source = timestampSigningRecordFactory
                    .source(signingProfile, request, serialNumber, genTime, encodedToken, protocol);
            signingRecordStrategyFactory
                    .strategyFor(signingProfile.recordPolicy().persistenceMode())
                    .recordSigning(source);
        } catch (Exception e) {
            logger
                    .error("Failed to record signing for signing profile '{}'; the timestamp was issued regardless",
                            signingProfile.name(), e);
        }
    }
}
