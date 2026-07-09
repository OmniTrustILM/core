package com.otilm.core.service.v2;

import com.otilm.api.exception.*;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.v2.*;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.UUID;

public interface ClientOperationInternalService {

    CertificateDetailDto submitCertificateRequest(
            ClientCertificateRequestDto request, CertificateProtocolInfo protocolInfo
    ) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException;

    ClientCertificateDataResponseDto issueCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            ClientCertificateIssueRequestDto request,
            CertificateProtocolInfo protocolInfo
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException;

    void approvalCreatedAction(final UUID certificateUuid) throws NotFoundException;

    void issueCertificateAction(
            final UUID certificateUuid,
            boolean isApproved
    ) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, CertificateOperationException, NotFoundException;

    void issueCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException;

    ClientCertificateDataResponseDto renewCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRenewRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException;

    void renewCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRenewRequestDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    ClientCertificateDataResponseDto rekeyCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRekeyRequestDto request
    ) throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException;

    void rekeyCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRekeyRequestDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    void revokeCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateRevocationDto request
    ) throws ConnectorException, AttributeException, NotFoundException;

    void revokeCertificateAction(
            final UUID certificateUuid,
            ClientCertificateRevocationDto request,
            boolean isApproved
    ) throws NotFoundException, CertificateOperationException;

    void revokeCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException;
}
