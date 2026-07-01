package com.otilm.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.RAProfileManagementController;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import com.otilm.api.model.client.compliance.SimplifiedComplianceProfileDto;
import com.otilm.api.model.client.raprofile.*;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.RaProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@RestController
public class RAProfileManagementControllerImpl implements RAProfileManagementController {

    private RaProfileService raProfileService;

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.RA_PROFILE)
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.LIST)
    public List<RaProfileDto> listRaProfiles(Optional<Boolean> enabled) {
        return raProfileService.listRaProfiles(SecurityFilter.create(), enabled);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.CREATE)
    public ResponseEntity<?> createRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, AddRaProfileRequestDto request)
            throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        RaProfileDto raProfile = raProfileService.addRaProfile(SecuredParentUUID.fromString(authorityUuid), request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
                .buildAndExpand(raProfile.getUuid()).toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(raProfile.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.DETAIL)
    public RaProfileDto getRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DETAIL)
    public RaProfileDto getRaProfile(@LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getRaProfile(SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.UPDATE)
    public RaProfileDto editRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid, EditRaProfileRequestDto request)
            throws ConnectorException, AttributeException, NotFoundException {
        return raProfileService.editRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.UPDATE)
    public RaProfileDto updateRaProfileValidationConfiguration(String authorityUuid, String raProfileUuid, RaProfileCertificateValidationSettingsUpdateDto request) throws NotFoundException {
        return raProfileService.updateRaProfileValidationConfiguration(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.UPDATE)
    public RaProfileDto updateRaProfileRequestAttributesConfiguration(String authorityUuid, String raProfileUuid, RaProfileCertificateRequestAttributesUpdateDto request) throws NotFoundException {
        return raProfileService.updateRaProfileRequestAttributesConfiguration(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.DELETE)
    public void deleteRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.deleteRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DELETE)
    public void deleteRaProfile(@LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.deleteRaProfile(SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.DISABLE)
    public void disableRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.disableRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.ENABLE)
    public void enableRaProfile(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.enableRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DELETE)
    public void bulkDeleteRaProfile(@LogResource(uuid = true) List<String> uuids) throws NotFoundException, ValidationException {
        raProfileService.bulkDeleteRaProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DISABLE)
    public void bulkDisableRaProfile(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        raProfileService.bulkDisableRaProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.ENABLE)
    public void bulkEnableRaProfile(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        raProfileService.bulkEnableRaProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.ACME_PROFILE, operation = Operation.GET_PROTOCOL_INFO)
    public RaProfileAcmeDetailResponseDto getAcmeForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getAcmeForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.ACME_PROFILE, operation = Operation.ACTIVATE_PROTOCOL)
    public RaProfileAcmeDetailResponseDto activateAcmeForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid, @LogResource(uuid = true, affiliated = true) String acmeProfileUuid, ActivateAcmeForRaProfileRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException {
        return raProfileService.activateAcmeForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), SecuredUUID.fromString(acmeProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.ACME_PROFILE, operation = Operation.DEACTIVATE_PROTOCOL)
    public void deactivateAcmeForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.deactivateAcmeForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.GET_PROTOCOL_INFO)
    public RaProfileScepDetailResponseDto getScepForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getScepForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.ACTIVATE_PROTOCOL)
    public RaProfileScepDetailResponseDto activateScepForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid, @LogResource(uuid = true, affiliated = true) String scepProfileUuid, ActivateScepForRaProfileRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException {
        return raProfileService.activateScepForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), SecuredUUID.fromString(scepProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.DEACTIVATE_PROTOCOL)
    public void deactivateScepForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.deactivateScepForRaProfile(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.CMP_PROFILE, operation = Operation.GET_PROTOCOL_INFO)
    public RaProfileCmpDetailResponseDto getCmpForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getCmpForRaProfile(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid)
        );
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.CMP_PROFILE, operation = Operation.ACTIVATE_PROTOCOL)
    public RaProfileCmpDetailResponseDto activateCmpForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid, @LogResource(uuid = true, affiliated = true) String cmpProfileUuid, ActivateCmpForRaProfileRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return raProfileService.activateCmpForRaProfile(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                SecuredUUID.fromString(cmpProfileUuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.CMP_PROFILE, operation = Operation.DEACTIVATE_PROTOCOL)
    public void deactivateCmpForRaProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        raProfileService.deactivateCmpForRaProfile(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid)
        );
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.CHECK_COMPLIANCE)
    public void checkCompliance(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        raProfileService.checkCompliance(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.COMPLIANCE_PROFILE, operation = Operation.LIST_ASSOCIATIONS)
    public List<SimplifiedComplianceProfileDto> getAssociatedComplianceProfiles(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getComplianceProfiles(authorityUuid, raProfileUuid, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.APPROVAL_PROFILE, operation = Operation.LIST_ASSOCIATIONS)
    public List<ApprovalProfileDto> getAssociatedApprovalProfiles(String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws NotFoundException {
        return raProfileService.getAssociatedApprovalProfiles(authorityUuid, raProfileUuid, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.APPROVAL_PROFILE, operation = Operation.ASSOCIATE)
    public void associateRAProfileWithApprovalProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid, @LogResource(uuid = true, affiliated = true) String approvalProfileUuid) throws NotFoundException {
        raProfileService.associateApprovalProfile(authorityUuid, raProfileUuid, SecuredUUID.fromString(approvalProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.APPROVAL_PROFILE, operation = Operation.DISASSOCIATE)
    public void disassociateRAProfileFromApprovalProfile(String authorityUuid, @LogResource(uuid = true) String raProfileUuid, @LogResource(uuid = true, affiliated = true) String approvalProfileUuid) throws NotFoundException {
        raProfileService.disassociateApprovalProfile(authorityUuid, raProfileUuid, SecuredUUID.fromString(approvalProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.GET_CHAIN)
    public List<CertificateDetailDto> getAuthorityCertificateChain(@LogResource(uuid = true, affiliated = true) String authorityUuid, @LogResource(uuid = true) String raProfileUuid) throws ConnectorException, NotFoundException {
        return raProfileService.getAuthorityCertificateChain(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "revoke", affiliatedResource = Resource.RA_PROFILE, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listRevokeCertificateAttributes(String authorityUuid, @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws ConnectorException, NotFoundException {
        return raProfileService.listRevokeCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "issue", affiliatedResource = Resource.RA_PROFILE, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listIssueCertificateAttributes(String authorityUuid, @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws ConnectorException, NotFoundException {
        return raProfileService.listIssueCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

}
