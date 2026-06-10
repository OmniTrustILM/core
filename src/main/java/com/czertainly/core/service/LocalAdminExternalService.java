package com.czertainly.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.core.auth.UserDetailDto;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface LocalAdminExternalService {
    UserDetailDto createUser(AddUserRequestDto request) throws NotFoundException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, AttributeException;
}
