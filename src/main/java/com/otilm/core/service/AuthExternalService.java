package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.core.auth.AuthResourceDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserProfileDetailDto;

import java.security.cert.CertificateException;
import java.util.List;

public interface AuthExternalService {

    UserProfileDetailDto getAuthProfile();

    List<AuthResourceDto> getAuthResources();

    UserDetailDto updateUserProfile(UpdateUserRequestDto request) throws NotFoundException, CertificateException;
}
