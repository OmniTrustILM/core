package com.otilm.core.api.web.v2;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.v2.ComplianceProfileController;
import com.otilm.api.model.client.compliance.v2.*;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.v2.ComplianceGroupListDto;
import com.otilm.api.model.core.compliance.v2.ComplianceProfileDto;
import com.otilm.api.model.core.compliance.v2.ComplianceProfileListDto;
import com.otilm.api.model.core.compliance.v2.ComplianceRuleListDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.v2.ComplianceProfileService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController("complianceProfileControllerV2")
public class ComplianceProfileControllerImpl implements ComplianceProfileController {

    private ComplianceProfileService complianceProfileService;

    @Autowired
    public void setComplianceProfileService(ComplianceProfileService complianceProfileService) {
        this.complianceProfileService = complianceProfileService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuthEndpoint(resourceName = Resource.COMPLIANCE_PROFILE)
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.LIST)
    public List<ComplianceProfileListDto> listComplianceProfiles() {
        return complianceProfileService.listComplianceProfiles(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DETAIL)
    public ComplianceProfileDto getComplianceProfile(@LogResource(uuid = true) UUID uuid) throws ConnectorException, NotFoundException {
        return complianceProfileService.getComplianceProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.CREATE)
    public ComplianceProfileDto createComplianceProfile(ComplianceProfileRequestDto request) throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException {
        return complianceProfileService.createComplianceProfile(request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.UPDATE)
    public ComplianceProfileDto updateComplianceProfile(@LogResource(uuid = true) UUID uuid, ComplianceProfileUpdateRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        return complianceProfileService.updateComplianceProfile(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DELETE)
    public void deleteComplianceProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        complianceProfileService.deleteComplianceProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteComplianceProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return complianceProfileService.bulkDeleteComplianceProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteComplianceProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return complianceProfileService.forceDeleteComplianceProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_RULE, affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST)
    public List<ComplianceRuleListDto> getComplianceRules(@LogResource(uuid = true, affiliated = true) UUID connectorUuid, String kind, @LogResource(resource = true, affiliated = true) Resource resource, String type, String format) throws ConnectorException, NotFoundException {
        return complianceProfileService.getComplianceRules(connectorUuid, kind, resource, type, format);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_GROUP, affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST)
    public List<ComplianceGroupListDto> getComplianceGroups(@LogResource(uuid = true, affiliated = true) UUID connectorUuid, String kind, @LogResource(resource = true, affiliated = true) Resource resource) throws ConnectorException, NotFoundException {
        return complianceProfileService.getComplianceGroups(connectorUuid, kind, resource);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_GROUP, affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST_RULES)
    public List<ComplianceRuleListDto> getComplianceGroupRules(@LogResource(uuid = true) UUID groupUuid, @LogResource(uuid = true, affiliated = true) UUID connectorUuid, String kind) throws ConnectorException, NotFoundException {
        return complianceProfileService.getComplianceGroupRules(groupUuid, connectorUuid, kind);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_RULE, operation = Operation.CREATE)
    public ComplianceRuleListDto createComplianceInternalRule(ComplianceInternalRuleRequestDto request) throws AlreadyExistException {
        return complianceProfileService.createComplianceInternalRule(request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_RULE, operation = Operation.UPDATE)
    public ComplianceRuleListDto updateComplianceInternalRule(@LogResource(uuid = true) UUID internalRuleUuid, ComplianceInternalRuleRequestDto request) throws NotFoundException {
        return complianceProfileService.updateComplianceInternalRule(internalRuleUuid, request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_RULE, operation = Operation.DELETE)
    public void deleteComplianceInternalRule(@LogResource(uuid = true) UUID internalRuleUuid) throws NotFoundException {
        complianceProfileService.deleteComplianceInternalRule(internalRuleUuid);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_RULE, operation = Operation.UPDATE)
    public void patchComplianceProfileRule(@LogResource(uuid = true) UUID uuid, ComplianceProfileRulesPatchRequestDto request) throws ConnectorException, NotFoundException {
        complianceProfileService.patchComplianceProfileRules(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, affiliatedResource = Resource.COMPLIANCE_GROUP, operation = Operation.UPDATE)
    public void patchComplianceProfileGroup(@LogResource(uuid = true) UUID uuid, ComplianceProfileGroupsPatchRequestDto request) throws ConnectorException, NotFoundException {
        complianceProfileService.patchComplianceProfileGroups(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.LIST_ASSOCIATIONS)
    public List<ResourceObjectDto> getAssociations(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return complianceProfileService.getAssociations(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.LIST_ASSOCIATIONS)
    public List<ComplianceProfileListDto> getAssociatedComplianceProfiles(@LogResource(resource = true, affiliated = true) Resource resource, @LogResource(uuid = true, affiliated = true) UUID associationObjectUuid) {
        return complianceProfileService.getAssociatedComplianceProfiles(resource, associationObjectUuid);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.ASSOCIATE)
    public void associateComplianceProfile(@LogResource(uuid = true) UUID uuid, @LogResource(resource = true, affiliated = true) Resource resource, @LogResource(uuid = true, affiliated = true) UUID associationObjectUuid) throws NotFoundException, AlreadyExistException {
        complianceProfileService.associateComplianceProfile(SecuredUUID.fromUUID(uuid), resource, associationObjectUuid);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.DISASSOCIATE)
    public void disassociateComplianceProfile(@LogResource(uuid = true) UUID uuid, @LogResource(resource = true, affiliated = true) Resource resource, @LogResource(uuid = true, affiliated = true) UUID associationObjectUuid) throws NotFoundException {
        complianceProfileService.disassociateComplianceProfile(SecuredUUID.fromUUID(uuid), resource, associationObjectUuid);
    }
}
