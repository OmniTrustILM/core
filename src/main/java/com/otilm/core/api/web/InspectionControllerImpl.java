package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.InspectionController;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.api.model.client.inspection.InspectionResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.service.FileInspectionExternalService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InspectionControllerImpl implements InspectionController {

    private FileInspectionExternalService fileInspectionService;

    @Autowired
    public void setFileInspectionExternalService(FileInspectionExternalService fileInspectionService) {
        this.fileInspectionService = fileInspectionService;
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE,
            affiliatedResource = Resource.TOKEN_PROFILE, operation = Operation.INSPECT)
    public InspectionResponseDto inspect(@Sensitive @Valid InspectionRequestDto request) throws NotFoundException {
        try {
            return fileInspectionService.inspect(request);
        } finally {
            request.getFile().clear();
            if (request.getPassphrase() != null) {
                request.getPassphrase().clear();
            }
        }
    }
}
