package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.AuthController;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.AuthResourceDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserProfileDetailDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AuthExternalService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateException;
import java.util.List;

@RestController
public class AuthControllerImpl implements AuthController {

    private AuthExternalService authService;
    private ResourceExternalService resourceService;

    @Autowired
    public void setAuthService(AuthExternalService authService) {
        this.authService = authService;
    }

    @Autowired
    public void setResourceService(ResourceExternalService resourceService) {
        this.resourceService = resourceService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.GET_USER_PROFILE)
    public UserProfileDetailDto profile() {
        return authService.getAuthProfile();
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.UPDATE_USER_PROFILE)
    public UserDetailDto updateUserProfile(UpdateUserRequestDto request) throws NotFoundException, CertificateException {
        return authService.updateUserProfile(request);
    }

    @Override
    public List<AuthResourceDto> getAuthResources() {
        return authService.getAuthResources();
    }

    @Override
    public List<NameAndUuidDto> getObjectsForResource(Resource resourceName) throws NotFoundException {
        return resourceService.getResourceObjects(SecuredResource.fromResource(resourceName), SecurityFilter.create(), null, null);
    }


}

