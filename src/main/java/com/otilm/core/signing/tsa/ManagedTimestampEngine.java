package com.otilm.core.signing.tsa;


import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.signing.tsa.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.certificate.ValidationResult;
import com.otilm.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.otilm.core.util.clocksource.ClockSource;
import com.otilm.core.util.serialnumber.ClockDriftException;
import com.otilm.core.util.serialnumber.SerialNumberGenerationException;
import com.otilm.core.util.serialnumber.SerialNumberGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Core engine that processes RFC 3161 timestamp requests.
 *
 * <p>Validates time quality, generates a serial number, delegates token creation
 * to {@link ManagedTimestampTokenGenerator}, verifies the signer certificate, and optionally
 * validates the token signature before returning the response.
 */
@Component
public class ManagedTimestampEngine {

    private static final Logger logger = LoggerFactory.getLogger(ManagedTimestampEngine.class);

    private final TimeQualityRegister timeQualityRegister;
    private final SerialNumberGenerator serialNumberGenerator;
    private final ManagedTimestampTokenGenerator tokenGenerator;
    private final SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    private final ClockSource clockSource;
    private final SigningRecordStrategyFactory signingRecordStrategyFactory;
    private final TspSigningRecordFactory tspSigningRecordFactory;


    public ManagedTimestampEngine(TimeQualityRegister timeQualityRegister, SerialNumberGenerator serialNumberGenerator, ManagedTimestampTokenGenerator tokenGenerator, SigningCertificateValidatorFactory signingCertificateValidatorFactory, ClockSource clockSource, SigningRecordStrategyFactory signingRecordStrategyFactory, TspSigningRecordFactory tspSigningRecordFactory) {
        this.timeQualityRegister = timeQualityRegister;
        this.serialNumberGenerator = serialNumberGenerator;
        this.tokenGenerator = tokenGenerator;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.clockSource = clockSource;
        this.signingRecordStrategyFactory = signingRecordStrategyFactory;
        this.tspSigningRecordFactory = tspSigningRecordFactory;
    }

    public TspResponse process(TspRequest request, SigningProfileModel<?, ?> signingProfile, ResolvedManagedTimestampingProfile timestampingProfile) throws TspException {

        ResolvedManagedScheme signingScheme = timestampingProfile.resolvedScheme();
        var signerCertificateValidator = signingCertificateValidatorFactory.getValidator(signingScheme);
        TimeQualityConfigurationModel timeQualityConfiguration = timestampingProfile.timeQualityConfiguration();

        var timeStatus = timeQualityRegister.getStatus(timeQualityConfiguration);
        if (timeStatus != TimeQualityStatus.OK) {
            logger.warn("Rejecting timestamp request for timestampingProfile '{}' using timeQualityProfile '{}': time quality status is {}", timestampingProfile.name(), timeQualityConfiguration.getName(), timeStatus);
            return TspResponse.rejected(TspFailureInfo.TIME_NOT_AVAILABLE, "Time quality is not sufficient for timestampingProfile '%s'".formatted(timestampingProfile.name()));
        }
        logger.info("Time quality status for time quality configuration '{}': {}", timeQualityConfiguration.getName(), timeStatus);

        var validationResult = signerCertificateValidator.validate(signingScheme, timestampingProfile.isQualifiedTimestamp());
        if (validationResult instanceof ValidationResult.Nok(
                TspFailureInfo failureInfo, String logMessage, String clientMessage
        )) {
            logger.warn("Rejecting timestamp request for signing profile '{}': {}", timestampingProfile.name(), logMessage);
            return TspResponse.rejected(failureInfo, clientMessage);
        }

        try {
            var serialNumber = serialNumberGenerator.generate();
            var genTime = clockSource.wallTimeInstant();
            var certificateChain = signingScheme.chain();

            var token = tokenGenerator.generate(request, timestampingProfile, certificateChain, serialNumber, genTime);

            if (Boolean.TRUE.equals(timestampingProfile.validateTokenSignature())) {
                var verifier = new JcaSimpleSignerInfoVerifierBuilder().build(certificateChain.signingCertificate());
                token.validate(verifier);
            }

            byte[] encodedToken = token.getEncoded();
            recordSigning(signingProfile, request, serialNumber, genTime, encodedToken);

            return TspResponse.granted(encodedToken);

        } catch (TspException e) {
            throw e; // TspController maps this to a proper rejection response
        } catch (TSPValidationException e) {
            logger.error("Timestamp signature validation failed", e);
            return TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "Timestamp signature validation failed");
        } catch (ClockDriftException e) {
            logger.error("Clock drift detected during timestamp generation", e);
            return TspResponse.rejected(TspFailureInfo.TIME_NOT_AVAILABLE, "Clock drift detected");
        } catch (SerialNumberGenerationException e) {
            logger.error("Timestamp generation interrupted", e);
            return TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "Internal error");
        } catch (Exception e) {
            logger.error("Unexpected error during timestamp generation", e);
            return TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "Internal error");
        }

    }

    /**
     * Records the granted timestamp. The signature has already been produced by the managed key, so a recording
     * failure must never downgrade the response: it is logged and swallowed, leaving the granted token intact.
     * The {@code recordingEnabled} policy gate lives inside the strategy, so disabled profiles are a no-op.
     */
    private void recordSigning(SigningProfileModel<?, ?> signingProfile, TspRequest request, BigInteger serialNumber, Instant genTime, byte[] encodedToken) {
        try {
            SigningRecordInput input = tspSigningRecordFactory.build(signingProfile, request, serialNumber, genTime, encodedToken);
            signingRecordStrategyFactory.strategyFor(signingProfile.recordPolicy().persistenceMode()).recordSigning(input);
        } catch (Exception e) {
            logger.error("Failed to record signing for signing profile '{}'; the timestamp was granted regardless", signingProfile.name(), e);
        }
    }
}
