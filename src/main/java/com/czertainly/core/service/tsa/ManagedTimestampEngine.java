package com.czertainly.core.service.tsa;


import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.czertainly.core.service.tsa.messages.TspRequest;
import com.czertainly.core.service.tsa.messages.TspResponse;
import com.czertainly.core.service.tsa.certificateprovider.CertificateProviderFactory;
import com.czertainly.core.service.tsa.certificateprovider.ValidationResult;
import com.czertainly.core.service.tsa.timequality.TimeQualityRegister;
import com.czertainly.core.service.tsa.timequality.TimeQualityStatus;
import com.czertainly.core.util.clocksource.ClockSource;
import com.czertainly.core.util.serialnumber.ClockDriftException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerationException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPException;
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
    private final CertificateProviderFactory certificateProviderFactory;
    private final ClockSource clockSource;


    public ManagedTimestampEngine(TimeQualityRegister timeQualityRegister, SerialNumberGenerator serialNumberGenerator, ManagedTimestampTokenGenerator tokenGenerator, CertificateProviderFactory certificateProviderFactory, ClockSource clockSource) {
        this.timeQualityRegister = timeQualityRegister;
        this.serialNumberGenerator = serialNumberGenerator;
        this.tokenGenerator = tokenGenerator;
        this.certificateProviderFactory = certificateProviderFactory;
        this.clockSource = clockSource;
    }

    public TspResponse process(TspRequest request, SigningProfileModel<ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel>, ? extends SigningSchemeModel> timestampingProfile) throws TspException {

        SigningSchemeModel signingScheme = timestampingProfile.signingScheme();
        var certificateProvider = certificateProviderFactory.getProvider(signingScheme);
        var timestampingWorkflow = timestampingProfile.workflow();
        var timeQualityConfiguration = timestampingWorkflow.timeQualityConfiguration();

        var timeStatus = timeQualityRegister.getStatus(timeQualityConfiguration);
        if (timeStatus == TimeQualityStatus.DEGRADED) {
            logger.warn("Rejecting timestamp request for timestampingProfile '{}' using timeQualityProfile '{}': time quality degraded", timestampingProfile.name(), timeQualityConfiguration.getName());
            return TspResponse.rejected(TspFailureInfo.TIME_NOT_AVAILABLE, "Time quality is degraded for timestampingProfile '%s'".formatted(timestampingProfile.name()));
        } else {
            logger.info("Time quality status for profile '{}': {}", timeQualityConfiguration.getName(), timeStatus);
        }

        var validationResult = certificateProvider.validate(signingScheme, timestampingWorkflow.isQualifiedTimestamp());
        if (validationResult instanceof ValidationResult.Nok(
                TspFailureInfo failureInfo, String logMessage, String clientMessage
        )) {
            logger.warn("Rejecting timestamp request for profile '{}': {}", timestampingProfile.name(), logMessage);
            return TspResponse.rejected(failureInfo, clientMessage);
        }

        try {
            var serialNumber = serialNumberGenerator.generate();
            var genTime = clockSource.wallTimeInstant();
            var certificateChain = certificateProvider.getCertificateChain(signingScheme);

            var result = tokenGenerator.generate(request, timestampingProfile, certificateChain, serialNumber, genTime);

            if (timestampingWorkflow.validateTokenSignature()) {
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
