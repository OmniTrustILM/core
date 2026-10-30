package com.otilm.core.signing.contentsigning.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
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
    private final TimestampSourceResolver timestampSourceResolver;

    public StaticKeyManagedContentSigningResolver(ManagedSchemeResolver schemeResolver,
            ConnectorInternalService connectorService, TimestampSourceResolver timestampSourceResolver) {
        this.schemeResolver = schemeResolver;
        this.connectorService = connectorService;
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
        String timestampSourceProfileName = workflow.maxLevel() == SignatureLevel.SIGNED
                ? null
                : timestampSourceResolver.profileNameFor(workflow.timestampSourceProfileUuid());

        return new ResolvedManagedContentSigningProfile(model.uuid(), model.name(), model.description(),
                model.version(), model.enabled(), model.enabledProtocols(),
                workflow.signatureFormattingConnectorAttributes(), workflow.family(), workflow.maxLevel(),
                timestampSourceProfileName, workflow.documentSizeCap(), workflow.certificatePurpose(), connector,
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

}
