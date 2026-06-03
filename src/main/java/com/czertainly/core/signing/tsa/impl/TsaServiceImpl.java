package com.czertainly.core.signing.tsa.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.czertainly.core.model.signing.workflow.SigningWorkflow;
import com.czertainly.core.service.SigningProfileService;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.signing.tsa.ManagedTimestampEngine;
import com.czertainly.core.signing.tsa.TsaService;
import com.czertainly.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import com.czertainly.core.signing.tsa.messages.TspResponse;
import com.czertainly.core.signing.tsa.validator.TspRequestValidator;
import org.springframework.stereotype.Service;

@Service
public class TsaServiceImpl implements TsaService {

    private final TspRequestValidator tspRequestValidator;
    private final TspProfileService tspProfileService;
    private final SigningProfileService signingProfileService;
    private final SigningProfileResolverFactory signingProfileResolverFactory;
    private final ManagedTimestampEngine managedTimestampEngine;

    public TsaServiceImpl(TspRequestValidator tspRequestValidator, SigningProfileService signingProfileService, SigningProfileResolverFactory signingProfileResolverFactory, TspProfileService tspProfileService, ManagedTimestampEngine managedTimestampEngine) {
        this.tspRequestValidator = tspRequestValidator;
        this.signingProfileService = signingProfileService;
        this.signingProfileResolverFactory = signingProfileResolverFactory;
        this.tspProfileService = tspProfileService;
        this.managedTimestampEngine = managedTimestampEngine;
    }

    @Override
    public TspResponse processTspRequestForTspProfile(String tspProfileName, TspRequest request) throws NotFoundException, TspException {

        TspProfileModel tspProfile = tspProfileService.getTspProfile(tspProfileName);

        return processTspRequestForSigningProfile(tspProfile.defaultSigningProfileName(), request);
    }

    @Override
    public TspResponse processTspRequestForSigningProfile(String signingProfileName, TspRequest request) throws NotFoundException, TspException {
        SigningProfileModel<?, ?> signingProfile = signingProfileService.getSigningProfileModel(signingProfileName);

        SigningWorkflow workflow = signingProfile.workflow();
        if (!(workflow instanceof ManagedTimestampingWorkflow timestampingWorkflow)) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Signing Profile '%s' is not a managed timestamping profile (workflow: %s)".formatted(
                            signingProfileName, workflow.getClass().getSimpleName()),
                    "The system is misconfigured.");
        }
        tspRequestValidator.validate(timestampingWorkflow, request);

        ResolvedManagedTimestampingProfile resolvedProfile = signingProfileResolverFactory.resolve(signingProfile);
        return managedTimestampEngine.process(request, resolvedProfile);
    }
}
