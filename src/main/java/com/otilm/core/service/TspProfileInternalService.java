package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;
import java.util.UUID;

public interface TspProfileInternalService extends ResourceExtensionService {

    SecuredList<TspProfile> listTspProfilesUsingSigningProfileAsDefault(SecuredUUID signingProfileUuid, SecurityFilter filter);

    TspProfile getTspProfileEntity(SecuredUUID uuid) throws NotFoundException;

    List<String> findAllNames();

    TspProfileModel getTspProfile(String name) throws NotFoundException;

    /**
     * Loads the TSP profile model by name without any authorization check.
     *
     * <p>Intended for use by {@code TspAuthenticationFilter}, which runs before a {@code SecurityContext} exists.
     */
    TspProfileModel resolveTspProfileForAuthentication(String name) throws NotFoundException;

    TspProfileModel getTspProfile(UUID uuid) throws NotFoundException;

    /**
     * Clears every entry in the TSP profile cache.
     */
    void evictAllCachedModels();
}
