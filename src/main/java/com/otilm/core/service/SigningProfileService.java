package com.otilm.core.service;

import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SigningProfileService extends ResourceExtensionService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SigningProfileListDto> listSigningProfiles(SearchRequestDto request, SecurityFilter filter);

    List<SimplifiedSigningProfileDto> listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter);

    SecuredList<SigningProfile> listSigningProfileEntitiesAssociatedTimeQualityConfiguration(SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter);

    SecuredList<SigningProfile> listSigningProfilesAssociatedWithTsp(SecuredUUID tspProfileUuid, SecurityFilter filter);

    SigningProfileDto getSigningProfile(SecuredUUID uuid, Integer version) throws NotFoundException;

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

    List<SigningProtocol> listSupportedProtocols(SigningWorkflowType workflowType);

    SigningProfileDto createSigningProfile(SigningProfileRequestDto request) throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException;

    SigningProfileDto updateSigningProfile(SecuredUUID uuid, SigningProfileRequestDto request) throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException;

    void deleteSigningProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    List<BulkActionMessageDto> bulkDeleteSigningProfiles(List<SecuredUUID> uuids);

    void enableSigningProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkEnableSigningProfiles(List<SecuredUUID> uuids);

    void disableSigningProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDisableSigningProfiles(List<SecuredUUID> uuids);

    List<CertificateDto> listSigningCertificates(SigningWorkflowType signingWorkflowType, boolean qualifiedTimestamp);

    List<BaseAttribute> listSignatureAttributesForCertificate(UUID certificateUuid) throws NotFoundException;

    List<BaseAttribute> listSignatureFormatterConnectorAttributes(UUID connectorUuid, SecuredUUID signingProfileUuid) throws NotFoundException, ConnectorException, AttributeException;

    PaginationResponseDto<SigningRecordListDto> listSigningRecordsForSigningProfile(SecuredUUID uuid, SearchRequestDto request, SecurityFilter filter) throws NotFoundException;

    TspActivationDetailDto getTspActivationDetails(SecuredUUID uuid) throws NotFoundException;

    TspActivationDetailDto activateTsp(SecuredUUID signingProfileUuid, SecuredUUID tspProfileUuid) throws NotFoundException;

    void deactivateTsp(SecuredUUID uuid) throws NotFoundException;
}
