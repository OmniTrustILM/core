package com.otilm.core.service.v2;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.UUID;
import java.util.function.Consumer;

public interface ClientOperationInternalService {

    CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request,
            CertificateProtocolInfo protocolInfo) throws ConnectorException, CertificateException,
            NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException;

    ClientCertificateDataResponseDto issueCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            ClientCertificateIssueRequestDto request, CertificateProtocolInfo protocolInfo)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException;

    /**
     * As
     * {@link #issueCertificate(SecuredParentUUID, SecuredUUID, ClientCertificateIssueRequestDto, CertificateProtocolInfo)},
     * running {@code beforeDispatch} with the new certificate's UUID once the request is stored and before the issue
     * action is queued. If the step fails, the certificate is marked failed and the action is not queued.
     */
    ClientCertificateDataResponseDto issueCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            ClientCertificateIssueRequestDto request, CertificateProtocolInfo protocolInfo,
            Consumer<UUID> beforeDispatch) throws NotFoundException, CertificateException, IOException,
            NoSuchAlgorithmException, InvalidKeyException, CertificateOperationException, CertificateRequestException;

    void approvalCreatedAction(final UUID certificateUuid) throws NotFoundException;

    void issueCertificateAction(final UUID certificateUuid, boolean isApproved)
            throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException,
            CertificateOperationException, NotFoundException;

    void issueCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException;

    ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRenewRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    void renewCertificateAction(final UUID certificateUuid, ClientCertificateRenewRequestDto request,
            boolean isApproved) throws NotFoundException, CertificateOperationException;

    ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRekeyRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    void rekeyCertificateAction(final UUID certificateUuid, ClientCertificateRekeyRequestDto request,
            boolean isApproved) throws NotFoundException, CertificateOperationException;

    void revokeCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid,
            ClientCertificateRevocationDto request) throws ConnectorException, AttributeException, NotFoundException;

    void revokeCertificateAction(final UUID certificateUuid, ClientCertificateRevocationDto request, boolean isApproved)
            throws NotFoundException, CertificateOperationException;

    void revokeCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException;
}
