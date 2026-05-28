package com.czertainly.core.api.web.v2;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.v2.ComplianceController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.ComplianceExternalService;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class ComplianceControllerImpl implements ComplianceController {

    private ComplianceExternalService complianceService;

    @Autowired
    public void setComplianceService(ComplianceExternalService complianceService) {
        this.complianceService = complianceService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.COMPLIANCE_PROFILE, operation = Operation.CHECK_COMPLIANCE)
    public void checkCompliance(@LogResource(uuid = true) List<UUID> uuids, @LogResource(resource = true, affiliated = true) Resource resource, String type) throws ConnectorException, NotFoundException {
        var securedUuids = SecuredUUID.fromUuidList(uuids);
        complianceService.checkComplianceValidation(securedUuids, resource, type);
        complianceService.checkComplianceAsync(securedUuids, resource, type);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.NONE, operation = Operation.CHECK_COMPLIANCE)
    public void checkResourceObjectsCompliance(@LogResource(resource = true) Resource resource, @LogResource(uuid = true) List<UUID> objectUuids) throws NotFoundException {
        complianceService.checkResourceObjectsComplianceValidation(resource, objectUuids);
        complianceService.checkResourceObjectsComplianceAsync(resource, objectUuids);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.NONE, operation = Operation.CHECK_COMPLIANCE)
    public void checkResourceObjectCompliance(@LogResource(resource = true) Resource resource, @LogResource(uuid = true) UUID objectUuid) throws NotFoundException {
        complianceService.checkResourceObjectsComplianceValidation(resource, List.of(objectUuid));
        complianceService.checkResourceObjectComplianceAsync(resource, objectUuid);
    }

    @Override
    @AuditLogged(module = Module.COMPLIANCE, resource = Resource.NONE, operation = Operation.GET_COMPLIANCE_RESULT)
    public ComplianceCheckResultDto getComplianceCheckResult(@LogResource(resource = true) Resource resource, @LogResource(uuid = true) UUID objectUuid) throws NotFoundException {
        return complianceService.getComplianceCheckResult(resource, objectUuid);
    }
}
