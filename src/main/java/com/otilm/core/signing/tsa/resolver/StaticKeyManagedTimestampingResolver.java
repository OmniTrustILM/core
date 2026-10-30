package com.otilm.core.signing.tsa.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.service.TimeQualityConfigurationInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import com.otilm.core.signing.engine.resolver.SigningProfileResolver;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Resolves a {@link SigningProfileModel} with a {@link ManagedTimestampingWorkflow} and {@link StaticKeyManagedSigning}
 * scheme into the transient {@link ResolvedManagedTimestampingProfile} consumed by the timestamping pipeline.
 *
 * <p>
 * The cached model deliberately holds only UUIDs for objects owned by other caches or repositories (Time Quality
 * Configuration, Signature Formatting Provider, signing certificate). This resolver dereferences those UUIDs at request
 * time. The resolved form is never cached.
 * </p>
 */
@Component
public class StaticKeyManagedTimestampingResolver implements SigningProfileResolver {

    private final ManagedSchemeResolver schemeResolver;
    private final TimeQualityConfigurationInternalService timeQualityConfigurationService;
    private final ConnectorInternalService connectorService;

    public StaticKeyManagedTimestampingResolver(ManagedSchemeResolver schemeResolver,
            TimeQualityConfigurationInternalService timeQualityConfigurationService,
            ConnectorInternalService connectorService) {
        this.schemeResolver = schemeResolver;
        this.timeQualityConfigurationService = timeQualityConfigurationService;
        this.connectorService = connectorService;
    }

    @Override
    public boolean supports(SigningProfileModel<?, ?> profile) {
        return profile.workflow() instanceof ManagedTimestampingWorkflow;
    }

    @Override
    public ResolvedManagedTimestampingProfile resolve(SigningProfileModel<?, ?> model) throws SigningEngineException {
        ManagedTimestampingWorkflow workflow = (ManagedTimestampingWorkflow) model.workflow();
        ResolvedManagedScheme resolvedScheme = schemeResolver.resolve(model.name(), model.signingScheme());
        TimeQualityConfigurationModel timeQualityConfiguration = resolveTimeQualityConfiguration(
                workflow.timeQualityConfigurationUuid());
        ApiClientConnectorInfo signatureFormattingConnector = resolveSignatureFormattingConnector(
                workflow.signatureFormattingConnectorUuid());

        return new ResolvedManagedTimestampingProfile(model.uuid(), model.name(), model.description(), model.version(),
                model.enabled(), model.enabledProtocols(), workflow.isQualifiedTimestamp(), workflow.defaultPolicyId(),
                workflow.allowedPolicyIds(), workflow.allowedDigestAlgorithms(), workflow.validateTokenSignature(),
                workflow.signatureFormattingConnectorAttributes(), timeQualityConfiguration,
                signatureFormattingConnector, resolvedScheme);
    }

    private TimeQualityConfigurationModel resolveTimeQualityConfiguration(UUID timeQualityConfigurationUuid)
            throws SigningEngineException {
        if (timeQualityConfigurationUuid == null) {
            // No explicit Time Quality Configuration: fall back to the local system clock.
            return LocalClockTimeQualityConfiguration.INSTANCE;
        }
        try {
            return timeQualityConfigurationService.getTimeQualityConfigurationModel(timeQualityConfigurationUuid);
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Time Quality Configuration not found: " + timeQualityConfigurationUuid, e,
                    "Internal error: signing configuration is invalid");
        }
    }

    private ApiClientConnectorInfo resolveSignatureFormattingConnector(UUID signatureFormattingConnectorUuid)
            throws SigningEngineException {
        try {
            return connectorService.getConnectorForApiClient(signatureFormattingConnectorUuid);
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signature formatting connector not found: " + signatureFormattingConnectorUuid, e,
                    "Internal error: signing configuration is invalid");
        }
    }

}
