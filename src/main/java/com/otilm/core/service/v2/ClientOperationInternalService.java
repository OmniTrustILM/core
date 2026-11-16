package com.otilm.core.service.v2;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.dao.entity.ApprovalProfileVersion;
import com.otilm.core.messaging.model.ActionMessage;
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

    CertificateDetail submitCertificateRequest(ClientCertificateRequestDto request,
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

    /**
     * Requests the approval of a certificate action and moves the certificate to PENDING_APPROVAL in one transaction,
     * under the certificate's row lock. An issue action with nothing to issue requests none, so the check cannot race
     * with the undo of a completion whose queuing failed.
     */
    void requestApproval(ApprovalProfileVersion approvalProfileVersion, ActionMessage actionMessage)
            throws NotFoundException;

    /**
     * Whether an issue action not yet approved has nothing to issue: the certificate is gone, is neither a submitted
     * request nor a registration holding the request of a completion, or holds another request than the one the action
     * was queued for. Such an action arrives late after its queuing reported a failure, or is delivered again.
     *
     * @param certificateRequestUuid the request the action was queued for, or null when it names none
     */
    boolean hasNothingToIssue(UUID certificateUuid, UUID certificateRequestUuid);

    void issueCertificateAction(final UUID certificateUuid, boolean isApproved)
            throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException,
            CertificateOperationException, NotFoundException;

    /**
     * As {@link #issueCertificateAction(UUID, boolean)} for an action queued for one certificate request: a certificate
     * that holds another request by the time it is claimed is not issued.
     *
     * @param certificateRequestUuid the request the action was queued for, or null when it names none
     */
    void issueCertificateAction(UUID certificateUuid, UUID certificateRequestUuid, boolean isApproved)
            throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException,
            CertificateOperationException, NotFoundException;

    void issueCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException;

    /**
     * As {@link #issueCertificateRejectedAction(UUID)} for the rejection of an approval requested for one certificate
     * request: a certificate that holds another request by then is left as it is.
     *
     * @param certificateRequestUuid the request the approval was requested for, or null when it names none
     */
    void issueCertificateRejectedAction(UUID certificateUuid, UUID certificateRequestUuid) throws NotFoundException;

    /**
     * A failure before the action is queued marks the new certificate failed; a compliance rejection leaves it rejected
     * and queues nothing. The new certificate keeps the protocol attribution of the certificate it renews.
     */
    ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRenewRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    /**
     * As {@link #renewCertificate(SecuredParentUUID, SecuredUUID, String, ClientCertificateRenewRequestDto)},
     * attributing the new certificate to the protocol and running {@code beforeDispatch} with its UUID once its request
     * is stored and before the renewal action is queued. If the step fails, the new certificate is marked failed and
     * the action is not queued.
     *
     * @param protocolInfo the protocol the renewal is requested through, or null to attribute the new certificate to
     * the protocol and protocol profile of the certificate it renews
     * @param beforeDispatch the step to run before the action is queued, or null for none
     */
    ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRenewRequestDto request, CertificateProtocolInfo protocolInfo,
            Consumer<UUID> beforeDispatch)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    void renewCertificateAction(final UUID certificateUuid, ClientCertificateRenewRequestDto request,
            boolean isApproved) throws NotFoundException, CertificateOperationException;

    /**
     * A failure before the action is queued marks the new certificate failed; a compliance rejection leaves it rejected
     * and queues nothing. The new certificate keeps the protocol attribution of the certificate it rekeys.
     */
    ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRekeyRequestDto request)
            throws NotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException,
            CertificateOperationException, CertificateRequestException, ConnectorException, AttributeException;

    /**
     * As {@link #rekeyCertificate(SecuredParentUUID, SecuredUUID, String, ClientCertificateRekeyRequestDto)},
     * attributing the new certificate to the protocol and running {@code beforeDispatch} with its UUID once its request
     * is stored and before the rekey action is queued. If the step fails, the new certificate is marked failed and the
     * action is not queued.
     *
     * @param protocolInfo the protocol the rekey is requested through, or null to attribute the new certificate to the
     * protocol and protocol profile of the certificate it rekeys
     * @param beforeDispatch the step to run before the action is queued, or null for none
     */
    ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            String certificateUuid, ClientCertificateRekeyRequestDto request, CertificateProtocolInfo protocolInfo,
            Consumer<UUID> beforeDispatch)
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
