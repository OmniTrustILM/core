package com.otilm.core.signing.tsa.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.signing.tsa.ManagedTimestampEngine;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.validator.TspRequestValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TsaServiceImpl implements TsaService {

    private final TspRequestValidator tspRequestValidator;
    private final TspProfileService tspProfileService;
    private final SigningProfileService signingProfileService;
    private final SigningProfileResolverFactory signingProfileResolverFactory;
    private final ManagedTimestampEngine managedTimestampEngine;

    private TsaServiceImpl self;

    public TsaServiceImpl(TspRequestValidator tspRequestValidator, SigningProfileService signingProfileService, SigningProfileResolverFactory signingProfileResolverFactory, TspProfileService tspProfileService, ManagedTimestampEngine managedTimestampEngine) {
        this.tspRequestValidator = tspRequestValidator;
        this.signingProfileService = signingProfileService;
        this.signingProfileResolverFactory = signingProfileResolverFactory;
        this.tspProfileService = tspProfileService;
        this.managedTimestampEngine = managedTimestampEngine;
    }

    @Lazy
    @Autowired
    public void setSelf(TsaServiceImpl self) {
        this.self = self;
    }

    @Override
    public TspResponse processTspRequestForTspProfile(String tspProfileName, TspRequest request) throws NotFoundException, TspException {
        TspProfileModel tspProfile = tspProfileService.getTspProfile(tspProfileName);
        try {
            return self.authorizeAndProcessForTspProfile(SecuredUUID.fromUUID(tspProfile.uuid()), tspProfile, request);
        } catch (AccessDeniedException e) {
            throw notFoundForDeniedTimestamping(TspProfileService.class, tspProfile.name(), e);
        }
    }

    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.TIMESTAMP)
    public TspResponse authorizeAndProcessForTspProfile(SecuredUUID tspProfileUuid, TspProfileModel tspProfile, TspRequest request)
            throws NotFoundException, TspException {
        LoggingHelper.putLogResourceInfo(Resource.TSP_PROFILE, true, tspProfile.uuid().toString(), tspProfile.name());

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
        LoggingHelper.putLogResourceInfo(Resource.SIGNING_PROFILE, true, signingProfile.uuid().toString(), signingProfile.name());

        if (signingProfile.tspProfileUuid() == null) {
            // No linked TSP profile means there is no TSP_PROFILE resource to run authorization against, so we
            // cannot tell whether the caller is permitted. Surface it as not-found so an unauthorized caller cannot
            // distinguish it from a non-existent profile (enumeration defense). See notFoundForDeniedTimestamping.
            log.warn("Signing profile '{}' has no associated TSP profile; cannot authorize timestamping", signingProfile.name());
            throw new NotFoundException(SigningProfileService.class, signingProfileName);
        }

        try {
            return self.authorizeAndProcessForSigningProfile(SecuredUUID.fromUUID(signingProfile.tspProfileUuid()), signingProfile, request);
        } catch (AccessDeniedException e) {
            throw notFoundForDeniedTimestamping(SigningProfileService.class, signingProfile.name(), e);
        }
    }

    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.TIMESTAMP)
    public TspResponse authorizeAndProcessForSigningProfile(SecuredUUID tspProfileUuid, SigningProfileModel<?, ?> signingProfile, TspRequest request)
            throws NotFoundException, TspException {
        if (!signingProfile.enabledProtocols().contains(SigningProtocol.TSP)) {
            var message = "Signing profile '%s' does not have the TSP protocol enabled.".formatted(signingProfile.name());
            throw new TspException(TspFailureInfo.BAD_REQUEST, message, message);
        }

        TspProfileModel tspProfile = tspProfileService.getTspProfile(signingProfile.tspProfileUuid());

        return processTspRequest(signingProfile, tspProfile, request);
    }

    private NotFoundException notFoundForDeniedTimestamping(Class<?> resourceService, String profileName, AccessDeniedException e) {
        // Collapse authorization denial into not-found: a distinct "forbidden" response would let a caller probe
        // which profiles exist by observing the differing outcome (narration/enumeration defense). The controllers
        // render NotFoundException as the same generic in-band rejection used for a non-existent profile.
        log.warn("Timestamping authorization denied for {} '{}': {}", resourceService.getSimpleName(), profileName, e.getMessage());
        return new NotFoundException(resourceService, profileName);
    }

    private TspResponse processTspRequest(SigningProfileModel<?, ?> signingProfile, TspProfileModel tspProfile, TspRequest request) throws TspException {
        if (!signingProfile.enabled()) {
            var message = "Signing profile '%s' is disabled".formatted(signingProfile.name());
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
