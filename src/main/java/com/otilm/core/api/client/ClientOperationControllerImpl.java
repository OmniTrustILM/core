package com.otilm.core.api.client;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.client.ClientOperationController;
import com.otilm.api.model.client.authority.ClientAddEndEntityRequestDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateRevocationDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateSignRequestDto;
import com.otilm.api.model.client.authority.ClientCertificateSignResponseDto;
import com.otilm.api.model.client.authority.ClientEditEndEntityRequestDto;
import com.otilm.api.model.client.authority.ClientEndEntityDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.ClientOperationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

@RestController
public class ClientOperationControllerImpl implements ClientOperationController {

    private ClientOperationService clientOperationService;

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.ISSUE)
    public ClientCertificateSignResponseDto issueCertificate(
            @PathVariable String raProfileName,
            @RequestBody LegacyClientCertificateSignRequestDto request)
            throws NotFoundException, CertificateException, AlreadyExistException, ConnectorException, NoSuchAlgorithmException {
        return clientOperationService.issueCertificate(raProfileName, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.REVOKE)
    public void revokeCertificate(@PathVariable String raProfileName, @RequestBody LegacyClientCertificateRevocationDto request) throws NotFoundException, ConnectorException {
        clientOperationService.revokeCertificate(raProfileName, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.LIST)
    public List<ClientEndEntityDto> listEntities(
            @PathVariable String raProfileName)
            throws NotFoundException, ConnectorException {
        return clientOperationService.listEntities(raProfileName);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.CREATE)
    public void addEndEntity(
            @PathVariable String raProfileName,
            @RequestBody ClientAddEndEntityRequestDto request)
            throws NotFoundException, AlreadyExistException, ConnectorException {
        clientOperationService.addEndEntity(raProfileName, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DETAIL)
    public ClientEndEntityDto getEndEntity(
            @LogResource(name = true) @PathVariable String raProfileName,
            @PathVariable String username)
            throws NotFoundException, ConnectorException {
        return clientOperationService.getEndEntity(raProfileName, username);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.UPDATE)
    public void editEndEntity(
            @LogResource(name = true) @PathVariable String raProfileName,
            @PathVariable String username,
            @RequestBody ClientEditEndEntityRequestDto request)
            throws NotFoundException, ConnectorException {
        clientOperationService.editEndEntity(raProfileName, username, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.DELETE)
    public void revokeAndDeleteEndEntity(@LogResource(name = true) @PathVariable String raProfileName, @PathVariable String username) throws NotFoundException, ConnectorException {
        clientOperationService.revokeAndDeleteEndEntity(raProfileName, username);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.RA_PROFILE, operation = Operation.UPDATE)
    public void resetPassword(@LogResource(name = true) @PathVariable String raProfileName, @PathVariable String username) throws NotFoundException, ConnectorException {
        clientOperationService.resetPassword(raProfileName, username);
    }
}
