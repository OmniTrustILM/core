package com.otilm.core.signing.tsa.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.signing.tsa.ManagedTimestampEngine;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.validator.TspRequestValidator;
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

        if (tspProfile.defaultSigningProfileName() == null) {
            var message = "TSP profile '%s' does not have a default signing profile".formatted(tspProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }
        SigningProfileModel<?, ?> signingProfile = signingProfileService.getSigningProfileModel(tspProfile.defaultSigningProfileName());

        return processTspRequest(signingProfile, tspProfile, request);
    }

    @Override
    public TspResponse processTspRequestForSigningProfile(String signingProfileName, TspRequest request) throws NotFoundException, TspException {
        SigningProfileModel<?, ?> signingProfile = signingProfileService.getSigningProfileModel(signingProfileName);

        if (signingProfile.tspProfileName() == null) {
            var message = "Signing profile '%s' does not have a TSP profile associated.".formatted(signingProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }
        TspProfileModel tspProfile = tspProfileService.getTspProfile(signingProfile.tspProfileName());

        return processTspRequest(signingProfile, tspProfile, request);
    }

    private TspResponse processTspRequest(SigningProfileModel<?, ?> signingProfile, TspProfileModel tspProfile, TspRequest request) throws TspException {
        if (!signingProfile.enabled()) {
            var message = "Signing profile '%s' is disabled".formatted(signingProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }

        if (!signingProfile.enabledProtocols().contains(SigningProtocol.TSP) || signingProfile.tspProfileName() == null) {
            var message = "Signing profile '%s' does not have the TSP protocol enabled".formatted(signingProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }

        if (!tspProfile.enabled()) {
            var message = "TSP profile '%s' is disabled".formatted(tspProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }

        SigningWorkflow workflow = signingProfile.workflow();
        if (!(workflow instanceof ManagedTimestampingWorkflow timestampingWorkflow)) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Signing Profile '%s' is not a managed timestamping profile (workflow: %s)".formatted(
                            signingProfile.name(), workflow.getClass().getSimpleName()),
                    "The system is misconfigured.");
        }
        tspRequestValidator.validate(timestampingWorkflow, request);

        ResolvedManagedTimestampingProfile resolvedProfile = signingProfileResolverFactory.resolve(signingProfile);
        return managedTimestampEngine.process(request, resolvedProfile);
    }
}
