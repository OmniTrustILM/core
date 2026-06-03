package com.czertainly.core.api.web;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.core.web.ComplianceProfileController;
import com.czertainly.api.model.client.compliance.*;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceProfileDto;
import com.czertainly.api.model.core.compliance.ComplianceProfilesListDto;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ComplianceProfileExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController("complianceProfileControllerV1")
public class ComplianceProfileControllerImpl implements ComplianceProfileController {

    private ComplianceProfileExternalService complianceProfileService;

    @Autowired
    public void setComplianceProfileService(ComplianceProfileExternalService complianceProfileService) {
        this.complianceProfileService = complianceProfileService;
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.LIST)
    public List<ComplianceProfilesListDto> listComplianceProfiles() {
        return complianceProfileService.listComplianceProfiles(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DETAIL)
    public ComplianceProfileDto getComplianceProfile(@LogResource(uuid = true) String uuid) throws NotFoundException, ConnectorException {
        return complianceProfileService.getComplianceProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<UuidDto> createComplianceProfile(ComplianceProfileRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        ComplianceProfileDto complianceProfile = complianceProfileService.createComplianceProfile(request);
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{complianceProfileUuid}")
                .buildAndExpand(complianceProfile.getUuid())
                .toUri();

        UuidDto dto = new UuidDto();
        dto.setUuid(complianceProfile.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_RULE, operation = Operation.LIST)
    public List<ComplianceRulesListResponseDto> getComplianceRules(String complianceProviderUuid, String kind, List<CertificateType> certificateType) throws NotFoundException, ConnectorException {
        return complianceProfileService.getComplianceRules(complianceProviderUuid, kind, certificateType);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_RULE, operation = Operation.ADD)
    public ComplianceProfileRuleDto addRule(@LogResource(uuid = true) String uuid, ComplianceRuleAdditionRequestDto request) throws AlreadyExistException, NotFoundException, ValidationException, ConnectorException {
        return complianceProfileService.addRule(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_RULE, operation = Operation.REMOVE)
    public void removeRule(@LogResource(uuid = true) String uuid, ComplianceRuleDeletionRequestDto request) throws NotFoundException, ConnectorException {
        complianceProfileService.removeRule(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_GROUP, operation = Operation.LIST)
    public List<ComplianceGroupsListResponseDto> getComplianceGroups(String complianceProviderUuid, String kind) throws NotFoundException, ConnectorException {
        return complianceProfileService.getComplianceGroups(complianceProviderUuid, kind);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_GROUP, operation = Operation.ADD)
    public void addGroup(@LogResource(uuid = true) String uuid, ComplianceGroupRequestDto request) throws AlreadyExistException, NotFoundException, ConnectorException {
        complianceProfileService.addGroup(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_GROUP, operation = Operation.REMOVE)
    public void removeGroup(@LogResource(uuid = true) String uuid, ComplianceGroupRequestDto request) throws NotFoundException, ConnectorException {
        complianceProfileService.removeGroup(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DELETE)
    public void deleteComplianceProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        complianceProfileService.deleteComplianceProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.LIST_ASSOCIATIONS)
    public List<SimplifiedRaProfileDto> getAssociatedRAProfiles(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return complianceProfileService.getAssociatedRAProfiles(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteComplianceProfiles(@LogResource(uuid = true) List<String> uuids) throws NotFoundException, ValidationException {
        return complianceProfileService.bulkDeleteComplianceProfiles(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteComplianceProfiles(@LogResource(uuid = true) List<String> uuids) throws ValidationException {
        return complianceProfileService.forceDeleteComplianceProfiles(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.ASSOCIATE)
    public void associateProfiles(@LogResource(uuid = true) String uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException, AlreadyExistException {
        complianceProfileService.associateProfile(SecuredUUID.fromString(uuid), raProfiles);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.DISASSOCIATE)
    public void disassociateProfiles(@LogResource(uuid = true) String uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException {
        complianceProfileService.disassociateProfile(SecuredUUID.fromString(uuid), raProfiles);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.CHECK_COMPLIANCE)
    public void checkCompliance(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        complianceProfileService.checkCompliance(SecuredUUID.fromList(uuids));
    }

}
