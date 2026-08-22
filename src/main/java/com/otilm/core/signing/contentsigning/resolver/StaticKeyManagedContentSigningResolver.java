package com.otilm.core.signing.contentsigning.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.service.TimeQualityConfigurationInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.signing.contentsigning.TimestampSourceResolver;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import com.otilm.core.signing.engine.resolver.SigningProfileResolver;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Resolves a {@link SigningProfileModel} with a {@link ManagedContentSigningWorkflow} into the transient
 * {@link ResolvedManagedContentSigningProfile}.
 */
@Component
public class StaticKeyManagedContentSigningResolver implements SigningProfileResolver {

    private final ManagedSchemeResolver schemeResolver;
    private final ConnectorInternalService connectorService;
    private final TimeQualityConfigurationInternalService timeQualityConfigurationService;
    private final TimestampSourceResolver timestampSourceResolver;

    public StaticKeyManagedContentSigningResolver(ManagedSchemeResolver schemeResolver,
            ConnectorInternalService connectorService,
            TimeQualityConfigurationInternalService timeQualityConfigurationService,
            TimestampSourceResolver timestampSourceResolver) {
        this.schemeResolver = schemeResolver;
        this.connectorService = connectorService;
        this.timeQualityConfigurationService = timeQualityConfigurationService;
        this.timestampSourceResolver = timestampSourceResolver;
    }

    @Override
    public boolean supports(SigningProfileModel<?, ?> profile) {
        return profile.workflow() instanceof ManagedContentSigningWorkflow;
    }

    @Override
    public ResolvedManagedContentSigningProfile resolve(SigningProfileModel<?, ?> model) throws SigningEngineException {
        ManagedContentSigningWorkflow workflow = (ManagedContentSigningWorkflow) model.workflow();
        ResolvedManagedScheme resolvedScheme = schemeResolver.resolve(model.name(), model.signingScheme());
        ApiClientConnectorInfo connector = resolveFormattingConnector(workflow.signatureFormattingConnectorUuid());
        TimeQualityConfigurationModel timeQualityConfiguration = resolveTimeQualityConfiguration(
                workflow.timeQualityConfigurationUuid());
        String timestampSourceProfileName = workflow.maxLevel() == SignatureLevel.SIGNED
                ? null
                : timestampSourceResolver.profileNameFor(workflow.timestampSourceProfileUuid());

        return new ResolvedManagedContentSigningProfile(model.uuid(), model.name(), model.description(),
                model.version(), model.enabled(), model.enabledProtocols(),
                workflow.signatureFormattingConnectorAttributes(), workflow.family(), workflow.maxLevel(),
                timestampSourceProfileName, workflow.documentSizeCap(), timeQualityConfiguration, connector,
                resolvedScheme);
    }

    private ApiClientConnectorInfo resolveFormattingConnector(UUID connectorUuid) throws SigningEngineException {
        try {
            return connectorService.getConnectorForApiClient(connectorUuid);
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signature formatting connector not found: " + connectorUuid, e,
                    "Internal error: signing configuration is invalid");
        }
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
}
