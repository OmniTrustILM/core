package com.czertainly.core.api.v2.client;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.core.client.v2.ClientOperationController;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.v2.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

@RestController("clientOperationControllerV2")
public class ClientOperationControllerImpl implements ClientOperationController {

    private ClientOperationService clientOperationService;

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.ISSUE)
    public ClientCertificateDataResponseDto issueRequestedCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException {
        return clientOperationService.issueRequestedCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.REQUEST)
    public ClientCertificateDataResponseDto issueCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            ClientCertificateSignRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.issueCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), request, null);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.RENEW)
    public ClientCertificateDataResponseDto renewCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid,
            ClientCertificateRenewRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.renewCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.REKEY)
    public ClientCertificateDataResponseDto rekeyCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid,
            ClientCertificateRekeyRequestDto request) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException {
        return clientOperationService.rekeyCertificate(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                certificateUuid,
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.REVOKE)
    public void revokeCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid,
            ClientCertificateRevocationDto request) throws ConnectorException, AttributeException, NotFoundException {
        clientOperationService.revokeCertificate(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), certificateUuid, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "issue", affiliatedResource = Resource.RA_PROFILE, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listIssueCertificateAttributes(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws ConnectorException, NotFoundException {
        return clientOperationService.listIssueCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "issue", affiliatedResource = Resource.RA_PROFILE, operation = Operation.VALIDATE_ATTRIBUTES)
    public void validateIssueCertificateAttributes(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        clientOperationService.validateIssueCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), attributes);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "revoke", affiliatedResource = Resource.RA_PROFILE, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listRevokeCertificateAttributes(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws ConnectorException, NotFoundException {
        return clientOperationService.listRevokeCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "revoke", affiliatedResource = Resource.RA_PROFILE, operation = Operation.VALIDATE_ATTRIBUTES)
    public void validateRevokeCertificateAttributes(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        clientOperationService.validateRevokeCertificateAttributes(SecuredParentUUID.fromString(authorityUuid), SecuredUUID.fromString(raProfileUuid), attributes);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.FINALIZE_ISSUE)
    public com.czertainly.api.model.core.certificate.CertificateDetailDto manuallyIssueCertificate(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid,
            com.czertainly.api.model.client.certificate.UploadCertificateRequestDto request)
            throws NotFoundException, CertificateException, AlreadyExistException, ConnectorException, AttributeException {
        return clientOperationService.manuallyIssueCertificate(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                certificateUuid, request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.CONFIRM_REVOKE)
    public void manuallyConfirmRevoke(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid) throws NotFoundException {
        clientOperationService.manuallyConfirmRevoke(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                certificateUuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.CANCEL)
    public com.czertainly.api.model.core.certificate.CertificateDetailDto cancelPendingCertificateOperation(
            String authorityUuid,
            @LogResource(uuid = true, affiliated = true) String raProfileUuid,
            @LogResource(uuid = true) String certificateUuid,
            com.czertainly.api.model.client.certificate.CancelPendingCertificateRequestDto request) throws NotFoundException {
        return clientOperationService.cancelPendingCertificateOperation(
                SecuredParentUUID.fromString(authorityUuid),
                SecuredUUID.fromString(raProfileUuid),
                certificateUuid, request);
    }
}