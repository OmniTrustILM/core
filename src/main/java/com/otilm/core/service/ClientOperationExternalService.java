package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.authority.ClientAddEndEntityRequestDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateRevocationDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateSignRequestDto;
import com.otilm.api.model.client.authority.ClientCertificateSignResponseDto;
import com.otilm.api.model.client.authority.ClientEditEndEntityRequestDto;
import com.otilm.api.model.client.authority.ClientEndEntityDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

// TODO AUTH - Use UUID instead of string name
public interface ClientOperationExternalService {

    ClientCertificateSignResponseDto issueCertificate(String raProfileName, LegacyClientCertificateSignRequestDto request) throws NotFoundException, AlreadyExistException, CertificateException, ConnectorException, NoSuchAlgorithmException;

    void revokeCertificate(String raProfileName, LegacyClientCertificateRevocationDto request) throws NotFoundException, ConnectorException;

    List<ClientEndEntityDto> listEntities(String raProfileName) throws NotFoundException, ConnectorException;

    void addEndEntity(String raProfileName, ClientAddEndEntityRequestDto request) throws NotFoundException, AlreadyExistException, ConnectorException;

    ClientEndEntityDto getEndEntity(String raProfileName, String username) throws NotFoundException, ConnectorException;

    void editEndEntity(String raProfileName, String username, ClientEditEndEntityRequestDto request) throws NotFoundException, ConnectorException;

    void revokeAndDeleteEndEntity(String raProfileName, String username) throws NotFoundException, ConnectorException;

    void resetPassword(String raProfileName, String username) throws NotFoundException, ConnectorException;

    void checkAccessPermissions(SecuredUUID raProfileUuid, SecuredParentUUID authorityUuid);
}
