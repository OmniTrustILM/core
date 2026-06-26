package com.otilm.core.service.v2;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.v2.*;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;

public interface ClientOperationService {

    List<BaseAttribute> listIssueCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid
    ) throws ConnectorException, NotFoundException;

    boolean validateIssueCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            List<RequestAttribute> attributes
    ) throws ConnectorException, ValidationException, NotFoundException;

    CertificateDetailDto submitCertificateRequest(
            ClientCertificateRequestDto request, CertificateProtocolInfo protocolInfo
    ) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException;

    ClientCertificateDataResponseDto issueExistingCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            ClientCertificateSignRequestDto request
    ) throws NotFoundException;

    ClientCertificateDataResponseDto issueCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            ClientCertificateSignRequestDto request,
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

    List<BaseAttribute> listRevokeCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid) throws ConnectorException, NotFoundException;

    boolean validateRevokeCertificateAttributes(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            List<RequestAttribute> attributes
    ) throws ConnectorException, ValidationException, NotFoundException;

    CertificateDetailDto manuallyIssueCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            UploadCertificateRequestDto request
    ) throws NotFoundException, CertificateException, AlreadyExistException, ConnectorException, AttributeException;

    void manuallyConfirmRevoke(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid
    ) throws NotFoundException;

    CertificateDetailDto cancelPendingCertificateOperation(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            String certificateUuid,
            CancelPendingCertificateRequestDto request
    ) throws NotFoundException;

    ClientCertificateDataResponseDto registerCertificate(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid,
            ClientCertificateRegistrationDto request
    ) throws NotFoundException, ConnectorException;

    AvailableOperationsDto listAvailableOperations(
            SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid
    ) throws NotFoundException;
}
