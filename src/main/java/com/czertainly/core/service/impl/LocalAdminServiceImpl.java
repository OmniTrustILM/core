package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.auth.AddUserRequestDto;
import com.czertainly.api.model.core.auth.UserDetailDto;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authz.UnauthenticatedEndpoint;
import com.czertainly.core.service.LocalAdminExternalService;
import com.czertainly.core.service.UserManagementService;
import com.czertainly.core.util.AuthHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Service
@Transactional
public class LocalAdminServiceImpl implements LocalAdminExternalService {

    private RoleManagementApiClient roleManagementApiClient;
    private UserManagementService userManagementService;

    @Autowired
    private void setUserManagementService(UserManagementService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @Override
    @UnauthenticatedEndpoint
    public UserDetailDto createUser(AddUserRequestDto request) throws NotFoundException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, AttributeException {
        UserDetailDto userDetailDto = userManagementService.createUser(request);

        String superadminRoleUuid = getSuperadminRoleUuid();
        userDetailDto = userManagementService.updateRole(userDetailDto.getUuid(), superadminRoleUuid);

        return userDetailDto;
    }

    private String getSuperadminRoleUuid() {
        return roleManagementApiClient.getRoles().getData().stream().filter(e -> e.getSystemRole().equals(true) && e.getName().equals(AuthHelper.SUPERADMIN_USERNAME)).toList().getFirst().getUuid();
    }
}
