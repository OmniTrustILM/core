package com.czertainly.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.client.auth.UserIdentificationRequestDto;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserDto;

import java.security.cert.CertificateException;
import java.util.List;

public interface UserManagementService extends ResourceExtensionService  {
    List<UserDto> listUsers();

    UserDetailDto getUser(String userUuid) throws NotFoundException;

    UserDetailDto createUser(AddUserRequestDto request) throws CertificateException, NotFoundException, AttributeException;

    UserDetailDto updateUser(String userUuid, UpdateUserRequestDto request) throws NotFoundException, CertificateException, AttributeException;

    UserDetailDto updateUserInternal(String userUuid, UpdateUserRequestDto request, String certificateUuid, String certificateFingerPrint) throws NotFoundException, CertificateException;

    void deleteUser(String userUuid);

    UserDetailDto updateRoles(String userUuid, List<String> roleUuids);

    UserDetailDto updateRole(String userUuid, String roleUuid);

    SubjectPermissionsDto getPermissions(String userUuid);

    UserDetailDto enableUser(String userUuid);

    UserDetailDto disableUser(String userUuid);

    List<RoleDto> getUserRoles(String userUuid);

    UserDetailDto removeRole(String userUuid, String roleUuid);

    UserDetailDto identifyUser(UserIdentificationRequestDto request) throws NotFoundException, CertificateException;
}
