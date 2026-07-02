package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfileRelation;
import com.otilm.core.dao.entity.ApprovalProfileVersion;
import com.otilm.core.dao.repository.ApprovalProfileRelationRepository;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.service.ApprovalInternalService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Component
public class ActionsListener implements MessageProcessor<ActionMessage> {

    private static final Logger logger = LoggerFactory.getLogger(ActionsListener.class);

    private ApprovalProfileRelationRepository approvalProfileRelationRepository;

    private ApprovalInternalService approvalService;

    private ClientOperationInternalService clientOperationService;

    private SecretInternalService secretService;

    private final ObjectMapper mapper = new ObjectMapper();

    private NotificationProducer notificationProducer;

    private AuthHelper authHelper;

    private MessagingProperties messagingProperties;

    @Override
    public void processMessage(final ActionMessage actionMessage) throws MessageHandlingException {
        boolean hasApproval = actionMessage.getApprovalUuid() != null;
        boolean isApproved = hasApproval && actionMessage.getApprovalStatus().equals(ApprovalStatusEnum.APPROVED);

        if (!hasApproval) {
            final Optional<List<ApprovalProfileRelation>> approvalProfileRelationOptional = approvalProfileRelationRepository.findByResourceUuidAndResource(actionMessage.getApprovalProfileResourceUuid(), actionMessage.getApprovalProfileResource());
            if (approvalProfileRelationOptional.isPresent() && !approvalProfileRelationOptional.get().isEmpty()) {
                try {
                    final ApprovalProfileRelation approvalProfileRelation = approvalProfileRelationOptional.get().get(0);
                    final ApprovalProfileVersion approvalProfileVersion = approvalProfileRelation.getApprovalProfile().getTheLatestApprovalProfileVersion();
                    final Approval approval = approvalService.createApproval(approvalProfileVersion, actionMessage.getResource(), actionMessage.getResourceAction(), actionMessage.getResourceUuid(), actionMessage.getUserUuid(), actionMessage.getData());
                    logger.info("Created new Approval {} for object {}", approval.getUuid(), actionMessage.getResourceUuid());
                    processApprovalCreated(actionMessage);
                } catch (Exception e) {
                    String errorMessage = String.format("Cannot create new approval to approve %s %s action!", actionMessage.getResource().getLabel(), actionMessage.getResourceAction().getCode());
                    logger.error("{}: {}", errorMessage, e.getMessage());
                    notificationProducer.produceInternalNotificationMessage(actionMessage.getResource(), actionMessage.getResourceUuid(),
                            NotificationRecipient.buildUserNotificationRecipient(actionMessage.getUserUuid()), errorMessage, e.getMessage());
                    throw new MessageHandlingException(messagingProperties.routingKey().actions(), actionMessage, "Handling of action approval creation failed: " + e.getMessage());
                }
                return;
            }
        }

        try {
            authHelper.authenticateAsUser(actionMessage.getUserUuid());
            processAction(actionMessage, hasApproval, isApproved);
        } catch (Exception e) {
            String errorMessage = String.format("Failed to perform %s %s%s action!", actionMessage.getResource().getLabel(), actionMessage.getResourceAction().getCode(), !hasApproval || isApproved ? "" : " rejected");
            logger.error("{}: {}", errorMessage, e.getMessage());
            notificationProducer.produceInternalNotificationMessage(actionMessage.getResource(), actionMessage.getResourceUuid(),
                    NotificationRecipient.buildUserNotificationRecipient(actionMessage.getUserUuid()), errorMessage, e.getMessage());
            throw new MessageHandlingException(messagingProperties.routingKey().actions(), actionMessage, "Unable to process action: " + e.getMessage());
        }
    }

    private void processApprovalCreated(final ActionMessage actionMessage) throws NotFoundException {
        if (Objects.requireNonNull(actionMessage.getResource()) == Resource.CERTIFICATE) {
            clientOperationService.approvalCreatedAction(actionMessage.getResourceUuid());
        } else if (Objects.requireNonNull(actionMessage.getResource()) == Resource.SECRET) {
            secretService.approvalCreatedAction(actionMessage.getResourceUuid());
        } else {
            logger.error("Action listener does not support resource {}", actionMessage.getResource().getLabel());
        }
    }

    private void processAction(final ActionMessage actionMessage, boolean hasApproval, boolean isApproved) throws CertificateOperationException, ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException, JsonProcessingException, SecretOperationException {
        if (Objects.requireNonNull(actionMessage.getResource()) == Resource.CERTIFICATE) {
            processCertificateAction(actionMessage, hasApproval, isApproved);
        } else if (Objects.requireNonNull(actionMessage.getResource()) == Resource.SECRET) {
            secretService.processSecretAction(actionMessage, hasApproval, isApproved);
        } else {
            logger.error("Action listener does not support resource {}", actionMessage.getResource().getLabel());
        }
    }

    private void processCertificateAction(final ActionMessage actionMessage, boolean hasApproval, boolean isApproved) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, CertificateOperationException, NotFoundException {
        // handle rejected actions
        if (hasApproval && !isApproved) {
            switch (Objects.requireNonNull(actionMessage.getResourceAction())) {
                case ISSUE, RENEW, REKEY ->
                        clientOperationService.issueCertificateRejectedAction(actionMessage.getResourceUuid());
                case REVOKE ->
                        clientOperationService.revokeCertificateRejectedAction(actionMessage.getResourceUuid());
                default ->
                        logger.debug("Action listener does not handle reject of action {} for resource {}", actionMessage.getResourceAction().getCode(), actionMessage.getResource().getLabel());
            }
            return;
        }

        // handle
        switch (actionMessage.getResourceAction()) {
            case ISSUE -> clientOperationService.issueCertificateAction(actionMessage.getResourceUuid(), isApproved);
            case REKEY -> {
                final ClientCertificateRekeyRequestDto clientCertificateRekeyRequestDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRekeyRequestDto.class);
                clientOperationService.rekeyCertificateAction(actionMessage.getResourceUuid(), clientCertificateRekeyRequestDto, isApproved);
            }
            case RENEW -> {
                final ClientCertificateRenewRequestDto clientCertificateRenewRequestDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRenewRequestDto.class);
                clientOperationService.renewCertificateAction(actionMessage.getResourceUuid(), clientCertificateRenewRequestDto, isApproved);
            }
            case REVOKE -> {
                final ClientCertificateRevocationDto clientCertificateRevocationDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRevocationDto.class);
                clientOperationService.revokeCertificateAction(actionMessage.getResourceUuid(), clientCertificateRevocationDto, isApproved);
            }
            default ->
                    logger.error("Action listener does not support action {} for resource {}", actionMessage.getResourceAction().getCode(), actionMessage.getResource().getLabel());
        }
    }

    // SETTERs

    @Autowired
    public void setApprovalProfileRelationRepository(ApprovalProfileRelationRepository approvalProfileRelationRepository) {
        this.approvalProfileRelationRepository = approvalProfileRelationRepository;
    }

    @Autowired
    public void setApprovalService(ApprovalInternalService approvalService) {
        this.approvalService = approvalService;
    }

    @Autowired
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setMessagingProperties(MessagingProperties messagingProperties) {
        this.messagingProperties = messagingProperties;
    }

    @Autowired
    public void setSecretService(SecretInternalService secretService) {
        this.secretService = secretService;
    }
}
