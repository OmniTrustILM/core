package com.czertainly.core.signing.tsa;


import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.signing.tsa.certificate.SigningCertificateValidatorFactory;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import com.czertainly.core.signing.tsa.messages.TspResponse;
import com.czertainly.core.signing.tsa.certificate.ValidationResult;
import com.czertainly.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.util.clocksource.ClockSource;
import com.czertainly.core.util.serialnumber.ClockDriftException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerationException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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


    public ManagedTimestampEngine(TimeQualityRegister timeQualityRegister, SerialNumberGenerator serialNumberGenerator, ManagedTimestampTokenGenerator tokenGenerator, SigningCertificateValidatorFactory signingCertificateValidatorFactory, ClockSource clockSource) {
        this.timeQualityRegister = timeQualityRegister;
        this.serialNumberGenerator = serialNumberGenerator;
        this.tokenGenerator = tokenGenerator;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.clockSource = clockSource;
    }

    public TspResponse process(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile) throws TspException {

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

            var result = tokenGenerator.generate(request, timestampingProfile, certificateChain, serialNumber, genTime);

            if (Boolean.TRUE.equals(timestampingProfile.validateTokenSignature())) {
                var verifier = new JcaSimpleSignerInfoVerifierBuilder().build(certificateChain.signingCertificate());
                result.validate(verifier);
            }

            return TspResponse.granted(result.getEncoded());

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
}
