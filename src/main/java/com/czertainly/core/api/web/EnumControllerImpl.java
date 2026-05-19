package com.czertainly.core.api.web;

import com.czertainly.api.interfaces.core.web.EnumController;
import com.czertainly.api.model.common.enums.PlatformEnum;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.enums.EnumItemDto;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.service.EnumExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class EnumControllerImpl implements EnumController {

    private EnumExternalService enumService;

    @Autowired
    public void setEnumService(EnumExternalService enumService) {
        this.enumService = enumService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PLATFORM_ENUM, operation = Operation.LIST)
    public Map<PlatformEnum, Map<String, EnumItemDto>> getPlatformEnums() {
        return enumService.getPlatformEnums();
    }
}
