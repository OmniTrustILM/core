package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface SigningProfileExternalService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SigningProfileListDto> listSigningProfiles(SearchRequestDto request, SecurityFilter filter);

    List<SimplifiedSigningProfileDto> listSigningProfilesAssociatedTimeQualityConfiguration(
            SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter);

    SigningProfileDto getSigningProfile(SecuredUUID uuid, Integer version) throws NotFoundException;

    List<SigningProtocol> listSupportedProtocols(SigningWorkflowType workflowType);

    SigningProfileDto createSigningProfile(SigningProfileRequestDto request)
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException;

    SigningProfileDto updateSigningProfile(SecuredUUID uuid, SigningProfileRequestDto request)
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException;

    void deleteSigningProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    List<BulkActionMessageDto> bulkDeleteSigningProfiles(List<SecuredUUID> uuids);

    void enableSigningProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkEnableSigningProfiles(List<SecuredUUID> uuids);

    void disableSigningProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDisableSigningProfiles(List<SecuredUUID> uuids);

    /**
     * Lists the certificates a signing profile of this workflow type could use.
     *
     * @param signingWorkflowType the workflow the profile being composed will run
     * @param qualifiedTimestamp meaningful only for TIMESTAMPING, where it demands id-etsi-qcs-QcCompliance
     * @param requireNonRepudiation demands the {@code nonRepudiation} key-usage bit specifically
     * @param requiredExtendedKeyUsageOids OIDs required on the certificate extended key usage
     * @return the eligible certificates, narrowed by the caller's security filter
     */
    List<CertificateDto> listSigningCertificates(SigningWorkflowType signingWorkflowType, boolean qualifiedTimestamp,
            boolean requireNonRepudiation, Set<String> requiredExtendedKeyUsageOids);

    List<BaseAttribute> listSignatureAttributesForCertificate(SecuredUUID certificateUuid)
            throws NotFoundException, ConnectorException;

    List<BaseAttribute> listSignatureFormattingConnectorAttributes(UUID connectorUuid, SecuredUUID signingProfileUuid)
            throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Lists the formatting attribute descriptors a content signing profile of this family and ceiling can reach. They
     * are merged into the single flat set that profile save validates against.
     *
     * @param connectorUuid the Signature Formatting Provider to ask
     * @param family the family the profile produces, which the provider must advertise
     * @param maxLevel the profile's ceiling, which decides the operations the merge covers
     * @param signingProfileUuid authorization only, and absent while the profile is still being created
     * @return the merged descriptors, in the order the reachable operations declare them
     */
    List<BaseAttribute> listContentSigningFormattingConnectorAttributes(UUID connectorUuid, SignatureFamily family,
            SignatureLevel maxLevel, SecuredUUID signingProfileUuid)
            throws NotFoundException, ConnectorException, AttributeException;

    PaginationResponseDto<SigningRecordListDto> listSigningRecordsForSigningProfile(SecuredUUID uuid,
            SearchRequestDto request, SecurityFilter filter) throws NotFoundException;

    TspActivationDetailDto getTspActivationDetails(SecuredUUID uuid, String baseUrl) throws NotFoundException;

    TspActivationDetailDto activateTsp(SecuredUUID signingProfileUuid, SecuredUUID tspProfileUuid, String baseUrl)
            throws NotFoundException;

    void deactivateTsp(SecuredUUID uuid) throws NotFoundException;
}
