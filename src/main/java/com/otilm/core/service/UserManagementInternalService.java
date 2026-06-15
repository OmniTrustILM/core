package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.core.auth.UserDetailDto;

import java.security.cert.CertificateException;

public interface UserManagementInternalService extends ResourceExtensionService {

    UserDetailDto updateUserInternal(String userUuid, UpdateUserRequestDto request, String certificateUuid, String certificateFingerPrint) throws NotFoundException, CertificateException;
}
