package com.otilm.core.service.v2;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.certificate.ManuallyIssueCertificateRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.v2.AvailableOperationsDto;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
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
import java.util.List;

public interface ClientOperationExternalService {

    List<BaseAttribute> listIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    void validateIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request,
            CertificateProtocolInfo protocolInfo) throws ConnectorException, CertificateException,
            NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException;

    ClientCertificateDataResponseDto issueExistingCertificate(SecuredParentUUID authorityUuid,
            SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateIssueRequestDto request)
            throws NotFoundException, CertificateException;

    ClientCertificateDataResponseDto issueCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            ClientCertificateIssueRequestDto request, CertificateProtocolInfo protocolInfo)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException;

    ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRenewRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRekeyRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    void revokeCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid,
            ClientCertificateRevocationDto request) throws ConnectorException, AttributeException, NotFoundException;

    List<BaseAttribute> listRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listRegisterCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listRenewCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    List<BaseAttribute> listIdentifyCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws ConnectorException, NotFoundException;

    void validateRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    CertificateDetailDto manuallyIssueCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ManuallyIssueCertificateRequestDto request) throws NotFoundException,
            CertificateException, AlreadyExistException, ConnectorException, AttributeException;

    void manuallyConfirmRevoke(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid)
            throws NotFoundException;

    CertificateDetailDto cancelPendingCertificateOperation(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, CancelPendingCertificateRequestDto request) throws NotFoundException;

    ClientCertificateDataResponseDto registerCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            ClientCertificateRegistrationDto request) throws NotFoundException, ConnectorException, AttributeException;

    AvailableOperationsDto listAvailableOperations(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid)
            throws NotFoundException;
}
