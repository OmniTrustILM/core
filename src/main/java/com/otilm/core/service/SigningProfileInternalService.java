package com.otilm.core.service;

import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;
import java.util.Optional;

public interface SigningProfileInternalService extends ResourceExtensionService {

    SecuredList<SigningProfile> listSigningProfileEntitiesAssociatedTimeQualityConfiguration(SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter);

    SecuredList<SigningProfile> listSigningProfilesAssociatedWithTsp(SecuredUUID tspProfileUuid, SecurityFilter filter);

    SigningProfile getSigningProfileEntity(SecuredUUID uuid) throws NotFoundException;

    /**
     * Returns the cached, immutable model of the signing profile's latest version. The model is a sealed generic
     * record whose concrete type parameters are resolved by the caller via pattern matching.
     *
     * @throws NotFoundException        if no signing profile with the given name exists
     * @throws IllegalStateException    if the profile has no version row matching its {@code latestVersion},
     *                                  or the version declares a managed scheme but its {@code managedSigningType}
     *                                  is {@code null}
     * @throws IllegalArgumentException if the profile is not a managed timestamping profile — the only kind
     *                                  the model currently supports
     */
    SigningProfileModel<? extends SigningWorkflow, ? extends SigningSchemeModel> getSigningProfileModel(String name) throws NotFoundException;

    /**
     * Resolves the governing TSP profile for a request targeting the indirect signing profile-based route,
     * without any authorization check.
     *
     * <p>Intended for use by {@code TspAuthenticationFilter}, which runs before a {@code SecurityContext} exists.
     * @return {@link Optional#empty()} when the Signing Profile exists but is not linked to any TSP Profile
     *
     * @throws NotFoundException if no Signing Profile with the given name exists, or the linked TSP Profile can no longer be resolved.
     */
    Optional<TspProfileModel> resolveTspProfileForSigningProfileAuthentication(String signingProfileName) throws NotFoundException;

    List<String> findAllNames();
}
