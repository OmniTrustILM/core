package com.czertainly.core.service.v2.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.v2.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v2.CertificateIdentificationRequestDto;
import com.czertainly.api.exception.ConnectorClientException;
import com.czertainly.api.exception.ConnectorCommunicationException;
import com.czertainly.api.exception.ConnectorEntityNotFoundException;
import com.czertainly.api.exception.ConnectorServerException;
import com.czertainly.api.model.connector.v2.CertificateIdentificationResponseDto;
import com.czertainly.api.model.connector.v2.CertificateOperationCancelRequestDto;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.api.model.core.v2.*;
import com.czertainly.core.attribute.CsrAttributes;
import com.czertainly.core.attribute.engine.AttributeContentPurpose;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.CertificateRelationRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.events.handlers.CertificateActionPerformedEventHandler;
import com.czertainly.core.logging.LoggerWrapper;
import com.czertainly.core.messaging.jms.producers.ActionProducer;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.model.auth.CertificateProtocolInfo;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.request.CertificateRequest;
import com.czertainly.core.model.request.CrmfCertificateRequest;
import com.czertainly.core.model.request.Pkcs10CertificateRequest;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.api.model.core.v2.AvailableOperationsDto;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.api.model.core.v2.OperationSupport;
import com.czertainly.core.exception.ConnectorAcceptedButLocalFailureException;
import com.czertainly.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.service.handler.ConnectorCapabilityService;
import com.czertainly.core.service.handler.authority.AdapterOperationResult;
import com.czertainly.core.service.handler.authority.AsyncOperationCapability;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapter;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.czertainly.core.service.handler.authority.CancelResult;
import com.czertainly.core.service.handler.authority.CancelOutcome;
import com.czertainly.core.service.handler.authority.RegisterCapability;
import com.czertainly.core.service.handler.authority.lifecycle.CertificateRevocationFinalizer;
import com.czertainly.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service("clientOperationServiceImplV2")
@Transactional
public class ClientOperationServiceImpl implements ClientOperationService {
    private static final Logger logger = LoggerFactory.getLogger(ClientOperationServiceImpl.class);

    /**
     * Structured event-log surface for system-level state-transition events that are not
     * directly user-triggered, per the contributor logging guide
     * (https://docs.otilm.com/docs/contributors/logging). Distinct from the
     * {@code @AuditLogged} aspect on the controller, which captures the user invocation
     * itself — {@code eventLogger} captures the <em>outcome</em> the system observed and
     * decided to act on (e.g. "connector returned 202 → transitioned to PENDING_ISSUE",
     * "connector hard-refused cancel → state preserved"). Per-call-site comments are
     * intentionally avoided; the {@code Operation} + {@code OperationResult} +
     * description arguments at each {@code eventLogger.logEvent} site speak for themselves.
     */
    private static final LoggerWrapper eventLogger = new LoggerWrapper(
            ClientOperationServiceImpl.class, Module.CERTIFICATES, Resource.CERTIFICATE);

    private PlatformTransactionManager transactionManager;

    private CertificateStateMachine stateMachine;

    private RaProfileRepository raProfileRepository;
    private CertificateRepository certificateRepository;
    private LocationService locationService;
    private CertificateService certificateService;
    private ComplianceService complianceService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private ExtendedAttributeService extendedAttributeService;
    private ConnectorApiFactory connectorApiFactory;
    private AuthorityProviderAdapterFactory adapterFactory;
    private ConnectorService connectorService;
    private CryptographicOperationService cryptographicOperationService;
    private CryptographicKeyService keyService;
    private AttributeEngine attributeEngine;
    private CertificateRelationRepository certificateRelationRepository;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;

    private ActionProducer actionProducer;
    private EventProducer eventProducer;
    private ConnectorCapabilityService capabilityService;
    private CertificateStatusPollProducer pollProducer;
    private com.czertainly.core.events.transaction.TransactionHandler transactionHandler;
    private CertificateRevocationFinalizer revocationFinalizer;

    @Autowired
    public void setTransactionHandler(com.czertainly.core.events.transaction.TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setRevocationFinalizer(CertificateRevocationFinalizer revocationFinalizer) {
        this.revocationFinalizer = revocationFinalizer;
    }

    @Autowired
    public void setCertificateRelationRepository(CertificateRelationRepository certificateRelationRepository) {
        this.certificateRelationRepository = certificateRelationRepository;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setStateMachine(CertificateStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Autowired
    public void setActionProducer(ActionProducer actionProducer) {
        this.actionProducer = actionProducer;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setCapabilityService(ConnectorCapabilityService capabilityService) {
        this.capabilityService = capabilityService;
    }

    @Autowired
    public void setPollProducer(CertificateStatusPollProducer pollProducer) {
        this.pollProducer = pollProducer;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Lazy
    @Autowired
    public void setLocationService(LocationService locationService) {
        this.locationService = locationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setComplianceService(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setAdapterFactory(AuthorityProviderAdapterFactory adapterFactory) {
        this.adapterFactory = adapterFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCryptographicOperationService(CryptographicOperationService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Autowired
    public void setKeyService(CryptographicKeyService keyService) {
        this.keyService = keyService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws ConnectorException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.listIssueCertificateAttributes(raProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public boolean validateIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.validateIssueCertificateAttributes(raProfile, attributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request, CertificateProtocolInfo protocolInfo) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException {
        // validate custom Attributes
        boolean createCustomAttributes = !AuthHelper.isLoggedProtocolUser();
        if (createCustomAttributes) {
            attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, request.getCustomAttributes());
        }
        if ((request.getRequest() == null || request.getRequest().isEmpty()) && (request.getKeyUuid() == null || request.getTokenProfileUuid() == null)) {
            throw new ValidationException("Cannot submit certificate request without specifying key or uploaded request content");
        }

        String certificateRequest = generateBase64EncodedCsr(request.getRequest(), request.getFormat(), request.getCsrAttributes(), request.getKeyUuid(), request.getTokenProfileUuid(), request.getSignatureAttributes(), request.getAltKeyUuid(), request.getAltTokenProfileUuid(), request.getAltSignatureAttributes());
        CertificateDetailDto certificate = certificateService.submitCertificateRequest(certificateRequest, request.getFormat(), request.getSignatureAttributes(), request.getAltSignatureAttributes(), request.getCsrAttributes(), request.getIssueAttributes(), request.getKeyUuid(), request.getAltKeyUuid(), request.getRaProfileUuid(), request.getSourceCertificateUuid(),
                protocolInfo);

        // create custom Attributes
        if (createCustomAttributes) {
            certificate.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, UUID.fromString(certificate.getUuid()), request.getCustomAttributes()));
        }

        return certificate;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto issueCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final ClientCertificateSignRequestDto request, final CertificateProtocolInfo protocolInfo) throws NotFoundException, CertificateException, NoSuchAlgorithmException, CertificateOperationException, CertificateRequestException {
        // validate RA profile
        RaProfile raProfile = raProfileRepository.findByUuid(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));

        if (Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new ValidationException(String.format("Cannot issue certificate with disabled RA profile. Ra Profile: %s", raProfile.getName()));
        }

        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setCsrAttributes(request.getCsrAttributes());
        certificateRequestDto.setSignatureAttributes(request.getSignatureAttributes());
        certificateRequestDto.setRequest(request.getRequest());
        certificateRequestDto.setFormat(request.getFormat());
        certificateRequestDto.setTokenProfileUuid(request.getTokenProfileUuid());
        certificateRequestDto.setKeyUuid(request.getKeyUuid());
        certificateRequestDto.setIssueAttributes(request.getAttributes());
        certificateRequestDto.setCustomAttributes(request.getCustomAttributes());
        certificateRequestDto.setAltKeyUuid(request.getAltKeyUuid());
        certificateRequestDto.setAltTokenProfileUuid(request.getAltTokenProfileUuid());
        certificateRequestDto.setAltSignatureAttributes(request.getAltSignatureAttributes());

        CertificateDetailDto certificate;
        TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            certificate = submitCertificateRequest(certificateRequestDto, protocolInfo);
            transactionManager.commit(status);
        } catch (Exception e) {
            transactionManager.rollback(status);
            throw new CertificateOperationException("Failed to submit certificate request: " + safeMessage(e));
        }

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(certificate.getUuid());

        // check for compliance of certificate request
        if (isRequestNotCompliant(UUID.fromString(certificate.getUuid()), certificate.getCertificateRequest().getUuid(), CertificateEvent.ISSUE)) {
            logger.warn("Certificate request is not compliant, not issuing certificate {}", certificate.getUuid());
            return response;
        }

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.ISSUE);
        actionMessage.setResourceUuid(UUID.fromString(certificate.getUuid()));
        actionProducer.produceMessage(actionMessage);

        return response;
    }

    @Override
    public void approvalCreatedAction(UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        stateMachine.transition(certificate, CertificateState.PENDING_APPROVAL);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void issueCertificateAction(final UUID certificateUuid, boolean isApproved) throws CertificateOperationException, NotFoundException {
        if (!isApproved) {
            certificateService.checkIssuePermissions();
        }

        final Certificate certificate = certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.isArchived())
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate that has been archived. Certificate: %s", certificate.toStringShort())));
        if (certificate.getState() != CertificateState.REQUESTED && certificate.getState() != CertificateState.PENDING_APPROVAL) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with state %s. Certificate: %s", certificate.getState().getLabel(), certificate)));
        }
        if (certificate.getRaProfile() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with no RA Profile associated. Certificate: %s", certificate)));
        }
        if (certificate.getCertificateRequest() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with no certificate request. Certificate: %s", certificate)));
        }

        // Once the connector returns a non-error status, the upstream operation is in flight or
        // already committed. A failure in any subsequent local step MUST NOT roll back the cert
        // state — that would diverge the platform DB from an authority that has already
        // accepted (or completed) the issuance.
        boolean connectorAccepted = false;
        try {
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(
                    certificate.getRaProfile().getAuthorityInstanceReference());
            AdapterOperationResult issueResult = adapter.issue(certificate, null);
            connectorAccepted = true;
            switch (issueResult.outcome()) {
                case SYNC_OK -> {
                    if (issueResult.certificateData() == null || issueResult.certificateData().isEmpty()) {
                        throw new CertificateOperationException("Response from authority did not contain certificate data");
                    }
                    logger.info("Certificate {} was issued by authority", certificateUuid);
                    certificateService.issueRequestedCertificate(certificateUuid, issueResult.certificateData(), issueResult.meta());
                }
                case ASYNC_ACCEPTED -> {
                    transitionToPendingIssue(certificate, issueResult.meta(), ResourceAction.ISSUE);
                    pollProducer.produceMessage(new CertificateStatusPollMessage(
                            Resource.CERTIFICATE, certificate.getUuid(), CertificateOperation.ISSUE, 1));
                    return;
                }
                case SYNC_NO_CONTENT -> throw new CertificateOperationException("Unexpected SYNC_NO_CONTENT from authority on issue");
            }
        } catch (Exception e) {
            throw issueFamilyFailure(certificate, certificateUuid, null, CertificateEvent.ISSUE,
                    null, connectorAccepted, "issue", e);
        }

        // push certificate to locations
        for (CertificateLocation cl : certificate.getLocations()) {
            try {
                locationService.pushRequestedCertificateToLocationAction(cl.getId(), false);
            } catch (Exception e) {
                logger.error("Failed to push issued certificate to location: {}", e.getMessage());
            }
        }

        // raise event
        eventProducer.produceMessage(CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.ISSUE));

        logger.debug("Certificate issued: {}", certificate);
    }

    /**
     * Transitions the certificate to {@code PENDING_ISSUE}, persists any metadata the connector
     * returned in its {@code 202 Accepted} response body, and records an event-history entry.
     * The {@code originatingAction} (ISSUE / RENEW / REKEY) drives the event-log
     * {@code CERTIFICATE_ACTION_PERFORMED} message so subscribers see the operation that produced
     * this state — not always {@code ISSUE}.
     */
    private void transitionToPendingIssue(Certificate certificate, CertificateDataResponseDto acceptedBody, ResourceAction originatingAction) {
        if (acceptedBody != null && acceptedBody.getMeta() != null && !acceptedBody.getMeta().isEmpty()) {
            try {
                attributeEngine.updateMetadataAttributes(acceptedBody.getMeta(),
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid())
                                .connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid())
                                .build());
            } catch (Exception metaEx) {
                // The connector has already accepted the operation asynchronously (HTTP 202)
                // upstream — we MUST reflect that in local state, otherwise the upstream
                // operation becomes orphaned with nothing tracking it. We therefore proceed
                // with the PENDING_ISSUE transition, but record a FAILED cert-event-history
                // entry so the operator can see that metadata persistence failed: a later
                // cancel call may not be able to reconstruct the connector's original
                // request fully (it will fall back to whatever metadata is queryable via
                // the attribute engine, possibly empty).
                logger.warn("Failed to persist metadata from 202 response for cert {}: {}",
                        certificate.getUuid(), metaEx.getMessage(), metaEx);
                certificateEventHistoryService.addEventHistory(
                        certificate.getUuid(),
                        CertificateEvent.ISSUE,
                        CertificateEventStatus.FAILED,
                        "Failed to persist connector metadata returned with HTTP 202; "
                                + "cancellation of this pending operation may be limited if "
                                + "the connector requires the original metadata. Cause: "
                                + metaEx.getMessage(),
                        "");
            }
        }

        stateMachine.transition(certificate, CertificateState.PENDING_ISSUE,
                CertificateEvent.ISSUE, "Issuance accepted; awaiting asynchronous completion.");

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(
                        certificate.getUuid(), originatingAction));

        eventLogger.logEvent(
                operationForAction(originatingAction),
                OperationResult.SUCCESS,
                null,
                List.of(new ResourceObjectIdentity(certificate.getSerialNumber(), certificate.getUuid())),
                "Connector accepted asynchronously (HTTP 202); certificate transitioned to PENDING_ISSUE");

        logger.info("Certificate {} transitioned to PENDING_ISSUE (originating action: {})",
                certificate.getUuid(), originatingAction.getCode());
    }

    /**
     * Variant of {@link #transitionToPendingIssue(Certificate, CertificateDataResponseDto, ResourceAction)}
     * used by adapter-based call sites, which carry metadata as {@code List<MetadataAttribute>} directly
     * (no intermediate {@code CertificateDataResponseDto} required).
     */
    private void transitionToPendingIssue(Certificate certificate, List<MetadataAttribute> meta, ResourceAction originatingAction) {
        CertificateDataResponseDto syntheticBody = null;
        if (meta != null && !meta.isEmpty()) {
            syntheticBody = new CertificateDataResponseDto();
            syntheticBody.setMeta(meta);
        }
        transitionToPendingIssue(certificate, syntheticBody, originatingAction);
    }

    /**
     * Return the exception's message only if the exception is one we shape ourselves
     * (domain exceptions whose messages are reviewed for safe wire exposure). For any other
     * exception type — Hibernate, JPA, JMS, JDK — return a generic placeholder so SQL
     * fragments, table/column names, or upstream framework internals don't reach the
     * operator HTTP response body. The original exception is still logged for debugging.
     * Mirrors the CLAUDE.md "Don't leak runtime details to the wire" rule.
     */
    private static String safeMessage(Throwable e) {
        if (e == null) {
            return "unknown error";
        }
        if (e instanceof com.czertainly.api.exception.ConnectorException
                || e instanceof com.czertainly.api.exception.ValidationException
                || e instanceof com.czertainly.api.exception.NotFoundException
                || e instanceof com.czertainly.api.exception.AttributeException
                || e instanceof com.czertainly.api.exception.CertificateOperationException
                || e instanceof com.czertainly.api.exception.AlreadyExistException) {
            String msg = e.getMessage();
            return msg != null ? msg : e.getClass().getSimpleName();
        }
        return "internal error (see server logs)";
    }

    /**
     * Shared failure handling for the issue-family actions (issue / renew / rekey). Centralizes
     * the state-divergence decision: when the connector already accepted the operation, surface
     * the local failure WITHOUT rolling back state (audit + rethrow); otherwise run the normal
     * failure cleanup and rethrow. Returns the exception for the caller to throw so control flow
     * stays obvious at the call site.
     */
    private CertificateOperationException issueFamilyFailure(
            Certificate certificate, UUID certUuid, UUID oldCertUuid, CertificateEvent event,
            Map<String, Object> additionalInfo, boolean connectorAccepted, String noun, Exception e) {
        if (connectorAccepted) {
            String msg = "Connector accepted " + noun + " but local state update failed: " + safeMessage(e);
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), event,
                    CertificateEventStatus.FAILED, msg,
                    additionalInfo == null || additionalInfo.isEmpty() ? "" : MetaDefinitions.serialize(additionalInfo));
            logger.error("Local state update failed after connector accepted {} for cert {}: {}",
                    noun, certificate.getUuid(), e.getMessage(), e);
            return new CertificateOperationException(msg);
        }
        handleFailedOrRejectedEvent(certificate, oldCertUuid, CertificateState.FAILED, event,
                additionalInfo != null ? additionalInfo : new HashMap<>(), e.getMessage());
        return new CertificateOperationException(
                "Failed to " + noun + " certificate with UUID %s: ".formatted(certUuid) + safeMessage(e));
    }

    private static void assertCertificateBelongsToRaProfile(Certificate certificate,
                                                            SecuredParentUUID authorityUuid,
                                                            SecuredUUID raProfileUuid,
                                                            String operation) {
        UUID certRaProfileUuid = certificate.getRaProfileUuid();
        if (certRaProfileUuid == null || !certRaProfileUuid.toString().equals(raProfileUuid.toString())) {
            throw new ValidationException(String.format(
                    "Cannot %s on certificate. Existing certificate RA profile is different than the RA profile of the request. Certificate: %s",
                    operation, certificate.toStringShort()));
        }
        UUID certAuthorityUuid = certificate.getRaProfile() != null
                ? certificate.getRaProfile().getAuthorityInstanceReferenceUuid()
                : null;
        if (certAuthorityUuid == null || !certAuthorityUuid.toString().equals(authorityUuid.toString())) {
            throw new ValidationException(String.format(
                    "Cannot %s on certificate. Existing certificate authority is different than the authority of the request. Certificate: %s",
                    operation, certificate.toStringShort()));
        }
    }

    /**
     * Map a {@link ResourceAction} originating from the v2 client API to the matching
     * {@link Operation} used by the structured event-log surface. Keeps audit-log and
     * event-log operation tags consistent (ISSUE → ISSUE, RENEW → RENEW, etc.).
     */
    private static Operation operationForAction(ResourceAction action) {
        return switch (action) {
            case ISSUE -> Operation.ISSUE;
            case RENEW -> Operation.RENEW;
            case REKEY -> Operation.REKEY;
            case REVOKE -> Operation.REVOKE;
            default -> Operation.UNKNOWN;
        };
    }

    private boolean isRequestNotCompliant(UUID certificateUuid, UUID certificateRequestUuid, CertificateEvent certificateEvent) throws NotFoundException {
        // check for compliance of certificate request
        logger.debug("Checking compliance of certificate request for certificate {}", certificateUuid);
        complianceService.checkResourceObjectsComplianceValidation(Resource.CERTIFICATE, List.of(certificateUuid));
        complianceService.checkResourceObjectComplianceAsSystem(Resource.CERTIFICATE, certificateUuid);
        ComplianceCheckResultDto complianceResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE_REQUEST, certificateRequestUuid);
        if (complianceResult.getStatus() == ComplianceStatus.NOK || complianceResult.getStatus() == ComplianceStatus.FAILED) {
            Certificate newCertificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            handleFailedOrRejectedEvent(newCertificate, null, CertificateState.REJECTED, certificateEvent, null, "Certificate request is not compliant");
            return true;
        }

        return false;
    }

    private void handleFailedOrRejectedEvent(Certificate certificate, UUID oldCertificateUuid, CertificateState state, CertificateEvent event, Map<String, Object> additionalInformation, String message) {
        for (CertificateLocation location : certificate.getLocations()) {
            try {
                locationService.removeRejectedOrFailedCertificateFromLocationAction(location.getId());
            } catch (ConnectorException | NotFoundException ex) {
                logger.error("Failed to remove certificate with UUID {} from location with UUID {}: {}", certificate.getUuid(), location.getId().getLocationUuid(), message);
            }
        }
        stateMachine.transition(certificate, state);

        certificateRelationRepository.deleteAll(certificate.getPredecessorRelations());

        if (state == CertificateState.FAILED) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            if (event == CertificateEvent.RENEW)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            if (event == CertificateEvent.REKEY)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.REKEY, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
        }

        if (state == CertificateState.REJECTED && message != null) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto issueRequestedCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final String certificateUuid) throws ConnectorException, NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));
        if (certificate.getState() != CertificateState.REQUESTED) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with status %s. Certificate: %s", certificate.getState().getLabel(), certificate)));
        }

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.ISSUE);
        actionMessage.setResourceUuid(UUID.fromString(certificateUuid));
        actionProducer.produceMessage(actionMessage);

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(certificateUuid);
        return response;
    }

    @Override
    public void issueCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        handleFailedOrRejectedEvent(certificate, null, CertificateState.REJECTED, null, null, null);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRenewRequestDto request) throws NotFoundException, CertificateOperationException, CertificateRequestException {
        Certificate oldCertificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.RENEW);

        // CSR decision making
        CertificateRequest certificateRequest;
        if (request.getRequest() != null) {
            // create certificate request from CSR and parse the data
            certificateRequest = CertificateRequestUtils.createCertificateRequest(request.getRequest(), request.getFormat());
            validatePublicKeyForCsrAndCertificate(oldCertificate.getCertificateContent().getContent(), certificateRequest, true);
        } else {
            // Check if the request is for using the existing CSR
            certificateRequest = getExistingCsr(oldCertificate);
        }

        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setRequest(Base64.getEncoder().encodeToString(certificateRequest.getEncoded()));
        certificateRequestDto.setFormat(certificateRequest.getFormat());
        certificateRequestDto.setKeyUuid(oldCertificate.getKeyUuid());
        certificateRequestDto.setSourceCertificateUuid(oldCertificate.getUuid());
        certificateRequestDto.setCustomAttributes(AttributeDefinitionUtils.getClientAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, oldCertificate.getUuid())));

        CertificateDetailDto newCertificate;
        TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            newCertificate = submitCertificateRequest(certificateRequestDto, null);
            transactionManager.commit(status);
        } catch (Exception e) {
            transactionManager.rollback(status);
            throw new CertificateOperationException("Failed to submit certificate request for certificate renewal: " + safeMessage(e));
        }

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(newCertificate.getUuid());

        // check for compliance of certificate request
        if (isRequestNotCompliant(UUID.fromString(newCertificate.getUuid()), newCertificate.getCertificateRequest().getUuid(), CertificateEvent.RENEW)) {
            logger.warn("Certificate request is not compliant, not issuing certificate {} as renewal of certificate {}", newCertificate.getUuid(), oldCertificate.getUuid());
            return response;
        }

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.RENEW);
        actionMessage.setResourceUuid(UUID.fromString(newCertificate.getUuid()));

        actionProducer.produceMessage(actionMessage);
        return response;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void renewCertificateAction(final UUID certificateUuid, ClientCertificateRenewRequestDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRenewPermissions();
        }
        Certificate certificate = validateNewCertificateForOperation(certificateUuid);
        CertificateRelation certificateRelation = certificateRelationRepository.findFirstByIdSuccessorCertificateUuidAndRelationTypeOrderByCreatedAtAsc(certificateUuid, CertificateRelationType.PENDING).orElseThrow(() -> new NotFoundException("No certificate renewal relation has been found for certificate with UUID %s".formatted(certificateUuid)));
        Certificate oldCertificate = certificateRepository.findByUuid(certificateRelation.getId().getPredecessorCertificateUuid()).orElseThrow(() -> new NotFoundException(Certificate.class, certificateRelation.getId().getPredecessorCertificateUuid()));
        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Renewing Certificate: {}", oldCertificate);

        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        // State-divergence guard — see issueCertificateAction for rationale.
        boolean connectorAccepted = false;
        try {
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult renewResult = adapter.renew(oldCertificate, certificate, request);
            connectorAccepted = true;
            switch (renewResult.outcome()) {
                case ASYNC_ACCEPTED -> {
                    transitionToPendingIssue(certificate, renewResult.meta(), ResourceAction.RENEW);
                    pollProducer.produceMessage(new CertificateStatusPollMessage(
                            Resource.CERTIFICATE, certificate.getUuid(), CertificateOperation.RENEW, 1));
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW,
                            CertificateEventStatus.SUCCESS, "Renewal accepted; awaiting asynchronous completion.",
                            MetaDefinitions.serialize(additionalInformation));
                    return;
                }
                case SYNC_OK -> {
                    if (renewResult.certificateData() == null || renewResult.certificateData().isEmpty()) {
                        throw new CertificateOperationException("Response from authority did not contain certificate data");
                    }
                    logger.info("Certificate {} was renewed by authority", certificateUuid);
                    CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(
                            certificateUuid, renewResult.certificateData(), renewResult.meta());
                    additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW,
                            CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(),
                            MetaDefinitions.serialize(additionalInformation));
                }
                case SYNC_NO_CONTENT -> throw new IllegalStateException("Unexpected SYNC_NO_CONTENT from authority on renew");
            }
        } catch (Exception e) {
            throw issueFamilyFailure(certificate, certificateUuid, oldCertificate.getUuid(), CertificateEvent.RENEW,
                    additionalInformation, connectorAccepted, "renew", e);
        }

        Location location = null;
        try {
            // replace certificate in the locations if needed
            if (request.isReplaceInLocations()) {
                logger.info("Replacing certificates in locations for certificate: {}", certificate);
                for (CertificateLocation cl : oldCertificate.getLocations()) {
                    location = cl.getLocation();
                    PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
                    pushRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(cl.getPushAttributes()));

                    locationService.removeCertificateFromLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), oldCertificate.getUuid().toString());
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Removed from Location " + cl.getLocation().getName(), "");

                    locationService.pushCertificateToLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), certificate.getUuid().toString(), pushRequest);
                    certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Pushed to Location " + cl.getLocation().getName(), "");
                }
            }

        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.FAILED, String.format("Failed to replace certificate in location %s: %s", location != null ? location.getName() : "", e.getMessage()), "");
            logger.error("Failed to replace certificate in all locations during renew operation: {}", e.getMessage());
            throw new CertificateOperationException("Failed to replace certificate in all locations during renew operation: " + safeMessage(e));
        }

        if (!request.isReplaceInLocations()) {
            // push certificate to locations
            for (CertificateLocation cl : certificate.getLocations()) {
                try {
                    locationService.pushRequestedCertificateToLocationAction(cl.getId(), true);
                } catch (Exception e) {
                    logger.error("Failed to push renewed certificate to location: {}", e.getMessage());
                }
            }
        }

        // raise event
        eventProducer.produceMessage(CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.RENEW));

        logger.debug("Certificate Renewed: {}", certificate);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto rekeyCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRekeyRequestDto request) throws NotFoundException, CertificateException, CertificateOperationException, CertificateRequestException {
        Certificate oldCertificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.REKEY);

        // CSR decision making
        ClientCertificateRequestDto certificateRequestDto = new ClientCertificateRequestDto();
        if (request.getRequest() != null) {
            // create certificate request from CSR and parse the data
            CertificateRequest certificateRequest = CertificateRequestUtils.createCertificateRequest(request.getRequest(), request.getFormat());

            String certificateContent = oldCertificate.getCertificateContent().getContent();
            validatePublicKeyForCsrAndCertificate(certificateContent, certificateRequest, false);
            validateSubjectDnForCertificate(certificateContent, certificateRequest);

            certificateRequestDto.setRequest(request.getRequest());
            certificateRequestDto.setFormat(request.getFormat());
        } else {
            createRequestFromKeys(request, oldCertificate, certificateRequestDto);
        }

        certificateRequestDto.setRaProfileUuid(raProfileUuid.getValue());
        certificateRequestDto.setSourceCertificateUuid(oldCertificate.getUuid());
        certificateRequestDto.setCustomAttributes(AttributeDefinitionUtils.getClientAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, oldCertificate.getUuid())));

        CertificateDetailDto newCertificate;
        TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            newCertificate = submitCertificateRequest(certificateRequestDto, null);
            transactionManager.commit(status);
        } catch (Exception e) {
            transactionManager.rollback(status);
            throw new CertificateOperationException("Failed to submit certificate request for certificate rekey: " + safeMessage(e));
        }

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(newCertificate.getUuid());

        // check for compliance of certificate request
        if (isRequestNotCompliant(UUID.fromString(newCertificate.getUuid()), newCertificate.getCertificateRequest().getUuid(), CertificateEvent.REKEY)) {
            logger.warn("Certificate request is not compliant, not issuing certificate {} as rekey of certificate {}", newCertificate.getUuid(), oldCertificate.getUuid());
            return response;
        }

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.REKEY);
        actionMessage.setResourceUuid(UUID.fromString(newCertificate.getUuid()));

        actionProducer.produceMessage(actionMessage);
        return response;
    }

    private void createRequestFromKeys(ClientCertificateRekeyRequestDto request, Certificate oldCertificate, ClientCertificateRequestDto certificateRequestDto) throws CertificateException, NotFoundException {
        // TODO: implement support for CRMF, currently only PKCS10 is supported
        UUID keyUuid = existingKeyValidation(request.getKeyUuid(), request.getSignatureAttributes(), oldCertificate);
        X509Certificate x509Certificate = CertificateUtil.parseCertificate(oldCertificate.getCertificateContent().getContent());
        X500Principal principal = x509Certificate.getSubjectX500Principal();
        // Gather the signature attributes either provided in the request or get it from the old certificate
        List<RequestAttribute> signatureAttributes;
        if (request.getSignatureAttributes() != null) {
            signatureAttributes = request.getSignatureAttributes();
        } else {
            if (oldCertificate.getCertificateRequest() != null)
                signatureAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, oldCertificate.getCertificateRequest().getUuid()).operation(AttributeOperation.SIGN).build());
            else signatureAttributes = null;
        }

        UUID altTokenProfileUuid = null;
        List<RequestAttribute> altSignatureAttributes = null;
        if (oldCertificate.isHybridCertificate() && request.getAltKeyUuid() == null)
            throw new ValidationException("Missing alternative key for re-keying of hybrid certificate");
        if (request.getAltKeyUuid() != null) {
            existingAltKeyValidation(request.getAltKeyUuid(), request.getAltSignatureAttributes(), oldCertificate);
            if (request.getAltSignatureAttributes() != null) {
                altSignatureAttributes = request.getAltSignatureAttributes();
            } else {
                if (oldCertificate.getCertificateRequest() != null)
                    altSignatureAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, oldCertificate.getCertificateRequest().getUuid()).operation(AttributeOperation.SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build());
            }
            altTokenProfileUuid = getAltTokenProfileUuid(request.getAltTokenProfileUuid(), oldCertificate);

        }

        String requestContent = generateBase64EncodedCsr(
                keyUuid,
                getTokenProfileUuid(request.getTokenProfileUuid(), oldCertificate),
                principal,
                signatureAttributes,
                request.getAltKeyUuid(),
                altTokenProfileUuid,
                altSignatureAttributes
        );

        certificateRequestDto.setKeyUuid(keyUuid);
        certificateRequestDto.setRequest(requestContent);
        certificateRequestDto.setFormat(CertificateRequestFormat.PKCS10);
        certificateRequestDto.setSignatureAttributes(signatureAttributes);
        certificateRequestDto.setAltKeyUuid(request.getAltKeyUuid());
        certificateRequestDto.setAltTokenProfileUuid(altTokenProfileUuid);
        certificateRequestDto.setAltSignatureAttributes(altSignatureAttributes);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void rekeyCertificateAction(final UUID certificateUuid, ClientCertificateRekeyRequestDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRenewPermissions();
        }
        Certificate certificate = validateNewCertificateForOperation(certificateUuid);

        CertificateRelation certificateRelation = certificateRelationRepository.findFirstByIdSuccessorCertificateUuidAndRelationTypeOrderByCreatedAtAsc(certificateUuid, CertificateRelationType.PENDING).orElseThrow(() -> new NotFoundException("No certificate renewal relation has been found for certificate with UUID %s".formatted(certificateUuid)));
        UUID sourceCertificateUuid = certificateRelation.getId().getPredecessorCertificateUuid();
        Certificate oldCertificate = certificateRepository.findByUuid(sourceCertificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, sourceCertificateUuid));
        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Rekeying Certificate: {}", oldCertificate);

        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        // State-divergence guard — see issueCertificateAction for rationale.
        boolean connectorAccepted = false;
        try {
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult rekeyResult = adapter.renew(oldCertificate, certificate, null);
            connectorAccepted = true;
            switch (rekeyResult.outcome()) {
                case ASYNC_ACCEPTED -> {
                    transitionToPendingIssue(certificate, rekeyResult.meta(), ResourceAction.REKEY);
                    pollProducer.produceMessage(new CertificateStatusPollMessage(
                            Resource.CERTIFICATE, certificate.getUuid(), CertificateOperation.RENEW, 1));
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY,
                            CertificateEventStatus.SUCCESS, "Rekey accepted; awaiting asynchronous completion.",
                            MetaDefinitions.serialize(additionalInformation));
                    return;
                }
                case SYNC_OK -> {
                    if (rekeyResult.certificateData() == null || rekeyResult.certificateData().isEmpty()) {
                        throw new CertificateOperationException("Response from authority did not contain certificate data");
                    }
                    logger.info("Certificate {} was rekeyed by authority", certificateUuid);
                    CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(
                            certificateUuid, rekeyResult.certificateData(), rekeyResult.meta());
                    additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY,
                            CertificateEventStatus.SUCCESS, "Rekeyed using RA Profile " + raProfile.getName(),
                            MetaDefinitions.serialize(additionalInformation));
                }
                case SYNC_NO_CONTENT -> throw new IllegalStateException("Unexpected SYNC_NO_CONTENT from authority on rekey");
            }
        } catch (Exception e) {
            throw issueFamilyFailure(certificate, certificateUuid, oldCertificate.getUuid(), CertificateEvent.REKEY,
                    additionalInformation, connectorAccepted, "rekey", e);
        }

        Location location = null;
        try {
            /* replace certificate in the locations if needed */
            if (request.isReplaceInLocations()) {
                logger.info("Replacing certificates in locations for certificate: {}", certificate);
                for (CertificateLocation cl : oldCertificate.getLocations()) {
                    location = cl.getLocation();
                    PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
                    pushRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(cl.getPushAttributes()));

                    locationService.removeCertificateFromLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), oldCertificate.getUuid().toString());
                    certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Removed from Location " + cl.getLocation().getName(), "");

                    locationService.pushCertificateToLocation(SecuredParentUUID.fromUUID(cl.getLocation().getEntityInstanceReferenceUuid()), cl.getLocation().getSecuredUuid(), certificate.getUuid().toString(), pushRequest);
                    certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.SUCCESS, "Pushed to Location " + cl.getLocation().getName(), "");
                }
            }

        } catch (Exception e) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_LOCATION, CertificateEventStatus.FAILED, String.format("Failed to replace certificate in location %s: %s", location != null ? location.getName() : "", e.getMessage()), "");
            logger.error("Failed to replace certificate in all locations during rekey operation: {}", e.getMessage());
            throw new CertificateOperationException("Failed to replace certificate in all locations during rekey operation: " + safeMessage(e));
        }

        // raise event
        eventProducer.produceMessage(CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.REKEY));

        logger.debug("Certificate rekeyed: {}", certificate);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void revokeCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRevocationDto request) throws ConnectorException, AttributeException, NotFoundException {
        Certificate certificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.REVOKE);

        // validate revoke attributes
        extendedAttributeService.mergeAndValidateRevokeAttributes(certificate.getRaProfile(), request.getAttributes());

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setData(request);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserProfile().getUser().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.REVOKE);
        actionMessage.setResourceUuid(UUID.fromString(certificateUuid));

        actionProducer.produceMessage(actionMessage);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void revokeCertificateAction(final UUID certificateUuid, ClientCertificateRevocationDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRevokePermissions();
        }
        final Certificate certificate = certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.getState() != CertificateState.ISSUED && certificate.getState() != CertificateState.PENDING_APPROVAL) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate in state %s. Certificate: %s", certificate.getState().getLabel(), certificate)));
        }
        final CertificateState entryState = certificate.getState();

        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Revoking Certificate: {}", certificate);

        // Once the connector returns a non-error status, the upstream operation is in flight.
        // A failure in any subsequent local step MUST NOT roll back the cert to its entry state
        // — doing so would leave the platform DB out of sync with an authority that has already
        // accepted (or completed) the revocation.
        boolean connectorAccepted = false;
        try {
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult revokeResult = adapter.revoke(certificate, request);
            connectorAccepted = true;

            switch (revokeResult.outcome()) {
                // 204 (SYNC_NO_CONTENT) and 200 (SYNC_OK, meta-only) are both synchronous
                // successful revocations; v3 connectors return 200 to deliver metadata.
                case SYNC_NO_CONTENT, SYNC_OK -> {
                    stateMachine.transition(certificate, CertificateState.REVOKED,
                            CertificateEvent.REVOKE, "Certificate revoked. Reason: "
                                    + (request.getReason() != null ? request.getReason().getLabel() : CertificateRevocationReason.UNSPECIFIED.getLabel()));
                    attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build(), request.getAttributes());
                    persistRevokeMetadata(certificate, raProfile, revokeResult.meta());
                }
                case ASYNC_ACCEPTED -> {
                    transitionToPendingRevoke(certificate, request);
                    pollProducer.produceMessage(new CertificateStatusPollMessage(
                            Resource.CERTIFICATE, certificate.getUuid(), CertificateOperation.REVOKE, 1));
                    return;
                }
            }
        } catch (Exception e) {
            if (connectorAccepted) {
                // Connector accepted the operation (200/202) but a subsequent local step failed.
                // Leave the cert state as-is — the upstream is committed and rolling back here
                // would create state divergence between the platform and the authority. Surface
                // the local failure but do not mask the upstream success.
                String msg = "Connector accepted revoke but local state update failed: " + safeMessage(e);
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE,
                        CertificateEventStatus.FAILED, msg, "");
                logger.error("Local state update failed after connector accepted revoke for cert {}: {}",
                        certificate.getUuid(), e.getMessage(), e);
                throw new CertificateOperationException(msg);
            }
            // Connector itself failed — restore the entry state so a PENDING_APPROVAL cert
            // doesn't get silently flipped to ISSUED.
            certificate.setState(entryState);
            certificateRepository.save(certificate);
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE, CertificateEventStatus.FAILED, e.getMessage(), "");
            logger.error("Failed to revoke Certificate: {}", e.getMessage());
            throw new CertificateOperationException("Failed to revoke certificate: " + safeMessage(e));
        }

        if (certificate.getKey() != null && request.isDestroyKey()) {
            try {
                logger.debug("Certificate revoked. Proceeding to check and destroy key");
                keyService.destroyKey(List.of(certificate.getKeyUuid().toString()));
            } catch (Exception e) {
                logger.warn("Failed to destroy certificate key: {}", e.getMessage());
            }
        }

        // raise event
        eventProducer.produceMessage(CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.REVOKE));

        logger.debug("Certificate revoked: {}", certificate);
    }

    /**
     * Best-effort persistence of connector-returned revoke metadata. The terminal REVOKE
     * transition is already committed by the time this runs, so a meta-write failure must not
     * propagate (it would roll back the committed revocation and diverge from the connector,
     * which has accepted the revoke). Mirrors the post-commit meta handling in the poll listener.
     */
    private void persistRevokeMetadata(Certificate certificate, RaProfile raProfile, List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return;
        }
        try {
            attributeEngine.updateMetadataAttributes(meta,
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid())
                            .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid())
                            .build());
        } catch (Exception e) {
            logger.warn("Failed to persist revoke metadata for cert {}; revocation already applied", certificate.getUuid(), e);
        }
    }

    /**
     * Transitions the certificate to {@code PENDING_REVOKE} and preserves the parameters needed to
     * finalize the revocation later (destroy-key flag, revoke attributes). Key destruction is
     * deliberately deferred until the revocation is confirmed by the operator. The connector's
     * {@code 202 Accepted} response carries no body for revoke (per the v2 contract); the platform
     * tracks the operation by transactionId / certificate identity.
     */
    private void transitionToPendingRevoke(Certificate certificate, ClientCertificateRevocationDto request) {
        certificate.setPendingRevokeDestroyKey(request.isDestroyKey());
        certificate.setPendingRevokeAttributes(request.getAttributes());
        stateMachine.transition(certificate, CertificateState.PENDING_REVOKE,
                CertificateEvent.REVOKE, "Revocation accepted; awaiting asynchronous completion.");

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(
                        certificate.getUuid(), ResourceAction.REVOKE));

        eventLogger.logEvent(
                Operation.REVOKE,
                OperationResult.SUCCESS,
                null,
                List.of(new ResourceObjectIdentity(certificate.getSerialNumber(), certificate.getUuid())),
                "Connector accepted asynchronously (HTTP 202); certificate transitioned to PENDING_REVOKE");

        logger.info("Certificate {} transitioned to PENDING_REVOKE", certificate.getUuid());
    }

    private Certificate validateOldCertificateForOperation(String certificateUuid, String raProfileUuid, ResourceAction action) throws NotFoundException {
        Certificate oldCertificate = certificateRepository.findByUuid(UUID.fromString(certificateUuid)).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (oldCertificate.isArchived())
            throw new ValidationException("Cannot perform operation %s on archived certificate. Certificate: %s".formatted(action.getCode(), oldCertificate.toStringShort()));
        if (oldCertificate.getState() == CertificateState.PENDING_ISSUE || oldCertificate.getState() == CertificateState.PENDING_REVOKE) {
            throw new ValidationException("Cannot perform operation %s on certificate with a pending operation. Finalize or cancel the pending operation first. Certificate: %s".formatted(action.getCode(), oldCertificate.toStringShort()));
        }
        if (!oldCertificate.getState().equals(CertificateState.ISSUED)) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate in state %s. Certificate: %s", action.getCode(), oldCertificate.getState().getLabel(), oldCertificate));
        }
        if (oldCertificate.getRaProfileUuid() == null || !oldCertificate.getRaProfileUuid().toString().equals(raProfileUuid)) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate. Existing Certificate RA profile is different than RA profile of request. Certificate: %s", action.getCode(), oldCertificate));
        }
        if (Boolean.FALSE.equals(oldCertificate.getRaProfile().getEnabled())) {
            throw new ValidationException(String.format("Cannot perform operation %s on certificate with disabled RA profile. Certificate: %s", action.getCode(), oldCertificate));
        }
        extendedAttributeService.validateLegacyConnector(oldCertificate.getRaProfile().getAuthorityInstanceReference().getConnector());

        return oldCertificate;
    }

    private Certificate validateNewCertificateForOperation(UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.isArchived())
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate that has been archived. Certificate: %s", certificate.toStringShort())));
        if (certificate.getState() != CertificateState.REQUESTED && certificate.getState() != CertificateState.PENDING_APPROVAL) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate in state %s. Certificate: %s", certificate.getState().getLabel(), certificate)));
        }
        if (certificate.getRaProfile() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with no RA Profile associated. Certificate: %s", certificate)));
        }
        if (certificate.getCertificateRequest() == null) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate with no certificate request set. Certificate: %s", certificate)));
        }

        return certificate;
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws ConnectorException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.listRevokeCertificateAttributes(raProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.ANY, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public boolean validateRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        return extendedAttributeService.validateRevokeCertificateAttributes(raProfile, attributes);
    }

    /**
     * Check and get the CSR from the existing certificate
     *
     * @param certificate Old certificate
     * @return Base64 encoded CSR string
     */
    private CertificateRequest getExistingCsr(Certificate certificate) throws CertificateRequestException {
        if (certificate.getCertificateRequest() == null
                || certificate.getCertificateRequest().getContent() == null) {
            // If the CSR is not found for the existing certificate, then throw error
            throw new ValidationException(
                    ValidationError.create(
                            "CSR does not available for the existing certificate"
                    )
            );
        }

        CertificateRequestFormat certificateRequestFormat = certificate.getCertificateRequest().getCertificateRequestFormat();
        return switch (certificateRequestFormat) {
            case PKCS10 -> new Pkcs10CertificateRequest(certificate.getCertificateRequest().getContentDecoded());
            case CRMF -> new CrmfCertificateRequest(certificate.getCertificateRequest().getContentDecoded());
            default -> throw new ValidationException(
                    ValidationError.create(
                            "Invalid certificate request format"
                    )
            );
        };
    }

    private UUID getTokenProfileUuid(UUID tokenProfileUuid, Certificate certificate) {
        if (certificate.getKeyUuid() == null && tokenProfileUuid == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Token Profile cannot be empty for creating new CSR"
                    )
            );
        }
        return tokenProfileUuid != null ? tokenProfileUuid : certificate.getKey().getTokenProfile().getUuid();
    }

    private UUID getAltTokenProfileUuid(UUID tokenProfileUuid, Certificate certificate) {
        if (certificate.getAltKeyUuid() == null && tokenProfileUuid == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Alternative Token Profile cannot be empty for creating new CSR with alternative key"
                    )
            );
        }
        return tokenProfileUuid != null ? tokenProfileUuid : certificate.getAltKey().getTokenProfile().getUuid();
    }

    /**
     * Validate existing key from the old certificate
     *
     * @param keyUuid             Key UUID
     * @param signatureAttributes Signature Attributes
     * @param certificate         Existing certificate to be renewed
     * @return UUID of the key from the old certificate
     */
    private UUID existingKeyValidation(UUID keyUuid, List<RequestAttribute> signatureAttributes, Certificate certificate) {
        // If the signature attributes are not provided in the request and not available in the old certificate, then throw error
        final CertificateRequestEntity certificateRequestEntity = certificate.getCertificateRequest();
        if (signatureAttributes == null && certificateRequestEntity == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Signature Attributes are not provided in request and old certificate"
                    )
            );
        }

        // If the key UUID is not provided and if the old certificate does not contain a key UUID, then throw error
        if (keyUuid == null && certificate.getKeyUuid() == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key UUID is not provided in the request and old certificate does not have key reference"
                    )
            );
        } else if (keyUuid == null && !certificate.mapToDto().isPrivateKeyAvailability()) {
            // If the status of the private key is not valid, then throw error
            throw new ValidationException(
                    "Old certificate does not have private key or private key is in incorrect state"
            );
        } else if (keyUuid != null && keyUuid.equals(certificate.getKeyUuid())) {
            throw new ValidationException(
                    ValidationError.create(
                            "Rekey operation not permitted. Cannot use same key to rekey certificate"
                    )
            );
        } else if (keyUuid != null) {
            return keyUuid;
        } else {
            throw new ValidationException(
                    ValidationError.create(
                            "Invalid key information"
                    )
            );
        }
    }

    private void existingAltKeyValidation(UUID altKeyUuid, List<RequestAttribute> altSignatureAttributes, Certificate certificate) {
        // If the signature attributes are not provided in the request and not available in the old certificate, then throw error
        final CertificateRequestEntity certificateRequestEntity = certificate.getCertificateRequest();
        if (altSignatureAttributes == null && certificateRequestEntity == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Signature Attributes are not provided in request and old certificate"
                    )
            );
        }
        // Since altKeyUuid will not be null at this point, we only need to check if for hybrid certificate there is a different key used for rekey
        if (certificate.isHybridCertificate()) {
            if (altKeyUuid != null && altKeyUuid.equals(certificate.getAltKeyUuid())) {
                throw new ValidationException(
                        ValidationError.create(
                                "Rekey operation not permitted. Cannot use same alternative key to rekey certificate"
                        )
                );
            } else if (certificate.getAltKeyUuid() == null) {
                compareAltKeysBasedOnContent(altKeyUuid, certificate);
            }
        }
    }

    private void compareAltKeysBasedOnContent(UUID altKeyUuid, Certificate certificate) {
        try {
            X509Certificate x509Certificate = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
            byte[] altKeyEncoded = x509Certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
            if (altKeyEncoded != null) {
                PublicKey publicKey = CertificateUtil.getAltPublicKey(altKeyEncoded);
                String fingerprint = CertificateUtil.getThumbprint(publicKey.getEncoded());
                UUID keyWithSameFingerprintUuid = keyService.findKeyByFingerprint(fingerprint);
                if (altKeyUuid.equals(keyWithSameFingerprintUuid)) {
                    throw new ValidationException(ValidationError.create(
                            "Rekey operation not permitted. Cannot use same alternative key to rekey certificate"
                    ));
                }

            }
        } catch (CertificateException e) {
            throw new ValidationException(ValidationError.create(
                    "Cannot parse certificate to check key for re-key"
            ));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ValidationException(ValidationError.create(
                    "Cannot parse alternative key extension to check key for re-key"
            ));
        }
    }

    /**
     * Generate the CSR for new certificate for issuance and renew
     *
     * @param keyUuid             UUID of the key
     * @param tokenProfileUuid    Token profile UUID
     * @param principal           X500 Principal
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException When the key or tokenProfile UUID is not found
     */
    private String generateBase64EncodedCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, List<RequestAttribute> signatureAttributes, UUID altKeyUUid,
                                            UUID altTokenProfileUuid,
                                            List<RequestAttribute> altSignatureAttributes) throws NotFoundException {
        try {
            // Generate the CSR with the above-mentioned information
            return cryptographicOperationService.generateCsr(
                    keyUuid,
                    tokenProfileUuid,
                    principal,
                    signatureAttributes,
                    altKeyUUid,
                    altTokenProfileUuid,
                    altSignatureAttributes
            );
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException | AttributeException e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Failed to generate the CSR. Error: " + e.getMessage()
                    )
            );
        }
    }

    /**
     * Function to evaluate if the certificate and the key contains the same public key
     *
     * @param certificateContent Certificate Content
     * @param certificateRequest Certificate Request
     * @param shouldMatch        Public key of the certificate and CSR should match
     */
    private void validatePublicKeyForCsrAndCertificate(String certificateContent, CertificateRequest certificateRequest, boolean shouldMatch) {
        try {
            X509Certificate certificate = CertificateUtil.parseCertificate(certificateContent);
            if (shouldMatch) {
                if (!Arrays.equals(certificate.getPublicKey().getEncoded(), certificateRequest.getPublicKey().getEncoded())) {
                    throw new ValidationException("Public key of certificate and CSR does not match");
                }
                checkMatchingAlternativePublicKey(certificateRequest, certificate);
            }
            if (!shouldMatch) {
                if (Arrays.equals(certificate.getPublicKey().getEncoded(), certificateRequest.getPublicKey().getEncoded())) {
                    throw new ValidationException("Public key of certificate and CSR are same");
                }
                checkNotMatchingAlternativePublicKey(certificateRequest, certificate);
            }
        } catch (Exception e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Unable to validate the public key of CSR and certificate. Error: " + e.getMessage()
                    )
            );
        }
    }

    private static void checkMatchingAlternativePublicKey(CertificateRequest certificateRequest, X509Certificate certificate) throws NoSuchAlgorithmException, CertificateRequestException, IOException, InvalidKeySpecException {
        byte[] altKeyEncoded = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        PublicKey altKeyCsr = certificateRequest.getAltPublicKey();
        if (altKeyEncoded == null && altKeyCsr != null) {
            throw new ValidationException("Certificate request contains alternative key, but the certificate does not.");
        }
        if (altKeyEncoded != null && altKeyCsr == null) {
            throw new ValidationException("Certificate request does not contain alternative key, but the certificate does.");
        } else if (altKeyCsr != null) {
            PublicKey altPublicKey = CertificateUtil.getAltPublicKey(altKeyEncoded);
            if (!Arrays.equals(altPublicKey.getEncoded(), certificateRequest.getAltPublicKey().getEncoded())) {
                throw new ValidationException("Alternative Public keys of certificate and CSR do not match");
            }
        }
    }

    private static void checkNotMatchingAlternativePublicKey(CertificateRequest certificateRequest, X509Certificate certificate) throws NoSuchAlgorithmException, CertificateRequestException, IOException, InvalidKeySpecException {
        byte[] altKeyEncoded = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        PublicKey altKeyCsr = certificateRequest.getAltPublicKey();
        if (altKeyCsr == null && altKeyEncoded != null)
            throw new ValidationException("Certificate contains alternative key, but CSR does not.");
        if (altKeyEncoded != null) {
            PublicKey altPublicKey = CertificateUtil.getAltPublicKey(altKeyEncoded);
            if (Arrays.equals(altPublicKey.getEncoded(), certificateRequest.getAltPublicKey().getEncoded())) {
                throw new ValidationException("Alternative Public keys of certificate and CSR should not match");
            }
        }
    }


    private void validateSubjectDnForCertificate(String certificateContent, CertificateRequest certificateRequest) {
        try {
            X509Certificate certificate = CertificateUtil.parseCertificate(certificateContent);

            // convert subjects to normalized form to compare them
            String normalizedRequestSubject = X500Name.getInstance(new CzertainlyX500NameStyle(true), certificateRequest.getSubject().getEncoded()).toString();
            String normalizedCertificateSubject = X500Name.getInstance(new CzertainlyX500NameStyle(true), certificate.getSubjectX500Principal().getEncoded()).toString();

            if (!normalizedCertificateSubject.equals(normalizedRequestSubject)) {
                throw new Exception("Subject DN of certificate and CSR does not match");
            }
        } catch (Exception e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Unable to validate the Subject DN of CSR and certificate. Error: " + e.getMessage()
                    )
            );
        }
    }

    private String generateBase64EncodedCsr(String uploadedRequest, CertificateRequestFormat requestFormat, List<RequestAttribute> csrAttributes, UUID keyUUid, UUID tokenProfileUuid, List<RequestAttribute> signatureAttributes,
                                            UUID altKeyUUid, UUID altTokenProfileUuid, List<RequestAttribute> altSignatureAttributes) throws NotFoundException, CertificateException, AttributeException, CertificateRequestException {
        String requestB64;
        String csr;
        if (uploadedRequest != null && !uploadedRequest.isEmpty()) {
            csr = uploadedRequest;
        } else {
            // TODO: support for the CRMF should be handled also in case it should be generated
            if (requestFormat == CertificateRequestFormat.CRMF) {
                throw new CertificateException("CRMF format is not supported for CSR generation");
            }
            // get definitions
            List<BaseAttribute> definitions = CsrAttributes.csrAttributes();

            // validate and update definitions of certificate request attributes with attribute engine
            attributeEngine.validateUpdateDataAttributes(null, null, definitions, csrAttributes);
            // TODO: return CertificateRequest object instead of Base64 encoded CSR
            csr = generateBase64EncodedCsr(
                    keyUUid,
                    tokenProfileUuid,
                    CertificateRequestUtils.buildSubject(csrAttributes),
                    signatureAttributes,
                    altKeyUUid,
                    altTokenProfileUuid,
                    altSignatureAttributes
            );
        }
        try {
            // TODO: CRMF request should be checked and encoded, not just blindly returned
            if (requestFormat == CertificateRequestFormat.CRMF) {
                return csr;
            }
            // TODO: replace with CertificateRequest object eventually
            requestB64 = Base64.getEncoder().encodeToString(
                    (CertificateRequestUtils.createCertificateRequest(csr, CertificateRequestFormat.PKCS10)).getEncoded());
        } catch (CertificateRequestException e) {
            logger.debug("Failed to parse CSR", e);
            throw new CertificateException(e);
        }
        return requestB64;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    /**
     * Two-layer authorization. The annotation gates use of the RA profile (RA_PROFILE
     * with action DETAIL); the call to checkIssuePermissions below gates the actual
     * issuance authority on CERTIFICATE. Mirrors what issueCertificateAction does
     * before persisting in the synchronous flow.
     */
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public CertificateDetailDto manuallyIssueCertificate(
            SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid,
            UploadCertificateRequestDto request) throws NotFoundException, CertificateException, AlreadyExistException, ConnectorException, AttributeException {
        certificateService.checkIssuePermissions();

        Certificate certificate = certificateRepository.findWithAssociationsByUuid(UUID.fromString(certificateUuid))
                .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        assertCertificateBelongsToRaProfile(certificate, authorityUuid, raProfileUuid, "finalize issuance");
        assertCertificateInPendingIssueWithCsr(certificate);

        CertificateRequest storedCsr = parseStoredCsr(certificate);
        validatePublicKeyForCsrAndCertificate(request.getCertificate(), storedCsr, true);

        CertificateIdentificationResponseDto identifyResponse =
                identifyUploadedCertificateOrReject(certificate, request);

        List<MetadataAttribute> identifyMeta = identifyResponse != null && identifyResponse.getMeta() != null
                ? identifyResponse.getMeta()
                : List.of();

        // Lock + state re-check + issuance + custom attrs in one transaction so a concurrent
        // poll-listener terminal transition OR a concurrent cancelPendingCertificateOperation
        // can't race past our state check. The identify HTTP call above already ran outside
        // any tx; downstream side effects (location push, event firing, connector cancel)
        // also stay outside the lock.
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(UUID.fromString(certificateUuid))
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            entityManager.refresh(locked);
            assertCertificateInPendingIssueWithCsr(locked);
            try {
                certificateService.issueRequestedCertificate(locked.getUuid(), request.getCertificate(), identifyMeta);
            } catch (NoSuchAlgorithmException e) {
                throw new CertificateException(e);
            }
            if (request.getCustomAttributes() != null && !request.getCustomAttributes().isEmpty()) {
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE,
                        locked.getUuid(), request.getCustomAttributes());
            }
            transactionManager.commit(tx);
        } catch (RuntimeException | CertificateException | AttributeException | NotFoundException e) {
            transactionManager.rollback(tx);
            throw e;
        }

        pushFinalizedCertificateToAllLocations(certificate);

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.ISSUE));

        Certificate refreshed = certificateRepository.findByUuid(certificate.getUuid())
                .orElseThrow(() -> new NotFoundException(Certificate.class, certificate.getUuid()));

        // Best-effort: tell v3 connector to release any in-flight async tracking for this cert.
        // Failure here does NOT roll back the local issue — connector cleanup is advisory.
        AuthorityInstanceReference authority = refreshed.getRaProfile().getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);
        if (adapter instanceof AsyncOperationCapability async) {
            try {
                async.cancel(refreshed, CertificateOperation.ISSUE);
            } catch (ConnectorException e) {
                logger.warn("Cancel-after-manual-issue failed (cert {}): {}", refreshed.getUuid(), e.getMessage());
            }
        }

        return refreshed.mapToDto();
    }

    private static void assertCertificateInPendingIssueWithCsr(Certificate certificate) {
        if (certificate.getState() != CertificateState.PENDING_ISSUE) {
            throw new ValidationException("Cannot finalize issuance: certificate is not in PENDING_ISSUE. Current state: %s. Certificate: %s"
                    .formatted(certificate.getState().getLabel(), certificate.toStringShort()));
        }
        if (certificate.getCertificateRequest() == null) {
            throw new ValidationException("Cannot finalize issuance: certificate has no associated certificate request. Certificate: %s"
                    .formatted(certificate.toStringShort()));
        }
    }

    private static CertificateRequest parseStoredCsr(Certificate certificate) {
        try {
            return CertificateRequestUtils.createCertificateRequest(
                    certificate.getCertificateRequest().getContent(),
                    certificate.getCertificateRequest().getCertificateRequestFormat());
        } catch (CertificateRequestException e) {
            throw new ValidationException("Cannot parse stored certificate request: " + e.getMessage());
        }
    }

    /**
     * The connector owns the decision whether the uploaded certificate was actually issued
     * by the configured authority — call identify and surface only the user-input failure
     * mode (422 → {@link ValidationException}). Connector infrastructure failures (5xx,
     * auth, network) propagate so the client sees the appropriate upstream error and can
     * retry; the certificate stays in {@code PENDING_ISSUE} for the next attempt.
     */
    private CertificateIdentificationResponseDto identifyUploadedCertificateOrReject(
            Certificate certificate, UploadCertificateRequestDto request) throws ConnectorException, NotFoundException {
        RaProfile raProfile = certificate.getRaProfile();
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        CertificateIdentificationRequestDto idReq = new CertificateIdentificationRequestDto();
        idReq.setCertificate(request.getCertificate());
        idReq.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid())
                        .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
        try {
            return connectorApiFactory.getCertificateApiClientV2(connectorDto)
                    .identifyCertificate(connectorDto,
                            raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), idReq);
        } catch (ValidationException e) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE,
                    CertificateEventStatus.FAILED,
                    "Manual upload rejected by connector identify: " + e.getMessage(), "");
            throw new ValidationException("Manual upload rejected by connector identify: " + e.getMessage());
        }
    }

    private void pushFinalizedCertificateToAllLocations(Certificate certificate) {
        for (CertificateLocation cl : certificate.getLocations()) {
            try {
                locationService.pushRequestedCertificateToLocationAction(cl.getId(), false);
            } catch (Exception e) {
                logger.error("Failed to push manually-finalized certificate {} to location {}: {}",
                        certificate.getUuid(), cl.getId().getLocationUuid(), e.getMessage(), e);
            }
        }
    }

    @Override
    /**
     * Two-layer authorization, same shape as manuallyIssueCertificate above: the
     * annotation gates RA profile use; checkRevokePermissions gates the actual
     * revocation authority on CERTIFICATE.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void manuallyConfirmRevoke(
            SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid) throws NotFoundException {
        certificateService.checkRevokePermissions();

        // The state-transition writes run in an explicit transaction with a pessimistic
        // row lock; destroyKey is a connector-side HTTP call and runs OUTSIDE the locked
        // transaction so a slow or unresponsive key connector does not hold a SELECT … FOR
        // UPDATE on the cert row for the duration of its call (which would block every
        // other operator action on the same cert). The lock is released as soon as the
        // REVOKED state and cleared pending-revoke fields are committed.
        UUID certUuid = UUID.fromString(certificateUuid);
        CertificateRevocationFinalizer.KeyCleanup keyCleanup;
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate cert = certificateRepository.findAndLockWithAssociationsByUuid(certUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            entityManager.refresh(cert);
            assertCertificateBelongsToRaProfile(cert, authorityUuid, raProfileUuid, "confirm revocation");
            if (cert.getState() != CertificateState.PENDING_REVOKE) {
                throw new ValidationException("Cannot confirm revocation: certificate is not in PENDING_REVOKE. Current state: %s. Certificate: %s"
                        .formatted(cert.getState().getLabel(), cert.toStringShort()));
            }

            keyCleanup = revocationFinalizer.prepareRevokeFinalization(cert);
            stateMachine.transition(cert, CertificateState.REVOKED,
                    CertificateEvent.REVOKE, "Revocation confirmed manually");
            transactionManager.commit(tx);
        } catch (NotFoundException | RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }

        // Slow connector calls outside the lock — failures here are logged but do not
        // affect the already-committed state transition.
        revocationFinalizer.destroyKeyIfRequested(keyCleanup, certUuid);
        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(certUuid, ResourceAction.REVOKE));
        logger.info("Certificate {} revocation confirmed manually", certUuid);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto registerCertificate(
            SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            ClientCertificateRegistrationDto request) throws ConnectorException, NotFoundException {

        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();

        if (!capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REGISTRATION)) {
            throw new ValidationException("Authority does not support certificate pre-registration");
        }

        Certificate cert = createRegistrationPlaceholder(raProfile);

        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);
        if (!(adapter instanceof RegisterCapability reg)) {
            throw new ValidationException("Authority adapter does not implement pre-registration capability");
        }

        // Capture entry state so a hard-fail from the connector restores the cert to its
        // pre-attempt state. Without this, a connector rejection would leave the cert
        // orphaned in PENDING_REGISTRATION with no poll message scheduled.
        final CertificateState entryState = cert.getState();
        stateMachine.transition(cert, CertificateState.PENDING_REGISTRATION);
        certificateRepository.save(cert);

        AdapterOperationResult result;
        try {
            result = reg.register(cert, request);
        } catch (ConnectorException | RuntimeException e) {
            // Connector rejected the registration. Restore entry state so the cert isn't
            // stranded in PENDING_REGISTRATION. SM accepts arbitrary state assignment on
            // failure paths (see CertificateStateTransition.REQUESTED_TO_FAILED etc.); using
            // direct setState here mirrors the pattern in revokeCertificateAction's catch.
            cert.setState(entryState);
            certificateRepository.save(cert);
            throw e;
        }

        switch (result.outcome()) {
            case SYNC_OK -> completeRegistrationSync(cert, authority, result);
            case ASYNC_ACCEPTED -> scheduleRegistrationPoll(cert, authority, result);
            default -> throw new IllegalStateException("Unexpected adapter outcome for register: " + result.outcome());
        }

        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setUuid(cert.getUuid().toString());
        return response;
    }

    private Certificate createRegistrationPlaceholder(RaProfile raProfile) {
        Certificate cert = new Certificate();
        cert.setState(CertificateState.REQUESTED);
        cert.setComplianceStatus(com.czertainly.api.model.core.compliance.ComplianceStatus.NOT_CHECKED);
        cert.setValidationStatus(com.czertainly.api.model.core.certificate.CertificateValidationStatus.NOT_CHECKED);
        cert.setCertificateType(com.czertainly.api.model.core.certificate.CertificateType.X509);
        cert.setRaProfileUuid(raProfile.getUuid());
        cert.setRaProfile(raProfile);
        return certificateRepository.save(cert);
    }

    private void completeRegistrationSync(Certificate cert, AuthorityInstanceReference authority,
                                          AdapterOperationResult result) throws ConnectorAcceptedButLocalFailureException {
        if (result.certificateData() != null && !result.certificateData().isEmpty()) {
            logger.warn("Connector returned certificateData on register sync 200 for cert {} — unexpected; ignoring cert data",
                    cert.getUuid());
        }
        persistRegistrationMeta(cert, authority, result);
        stateMachine.transition(cert, CertificateState.REGISTERED);
        certificateRepository.save(cert);
        logger.info("Certificate {} registered synchronously", cert.getUuid());
    }

    private void scheduleRegistrationPoll(Certificate cert, AuthorityInstanceReference authority,
                                          AdapterOperationResult result) throws ConnectorAcceptedButLocalFailureException {
        persistRegistrationMeta(cert, authority, result);
        pollProducer.produceMessage(
                new CertificateStatusPollMessage(Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.REGISTER, 1));
        logger.info("Certificate {} accepted for async registration; poll scheduled", cert.getUuid());
    }

    private void persistRegistrationMeta(Certificate cert, AuthorityInstanceReference authority,
                                         AdapterOperationResult result) throws ConnectorAcceptedButLocalFailureException {
        if (result.meta() == null || result.meta().isEmpty()) {
            return;
        }
        try {
            attributeEngine.updateMetadataAttributes(result.meta(),
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                            .connector(authority.getConnectorUuid())
                            .build());
        } catch (Exception metaEx) {
            throw new ConnectorAcceptedButLocalFailureException(
                    "Connector accepted registration but metadata persistence failed", metaEx);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public AvailableOperationsDto listAvailableOperations(
            SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws NotFoundException {

        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);

        boolean isAsync = adapter instanceof AsyncOperationCapability;
        boolean canRegister = adapter instanceof RegisterCapability
                && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REGISTRATION);

        List<OperationSupport> ops = List.of(
                new OperationSupport("ISSUE",    true,            isAsync,              isAsync),
                new OperationSupport("RENEW",    true,            isAsync,              isAsync),
                new OperationSupport("REVOKE",   true,            isAsync,              isAsync),
                new OperationSupport("REGISTER", canRegister,     isAsync && canRegister, isAsync && canRegister)
        );
        return new AvailableOperationsDto(ops);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public CertificateDetailDto cancelPendingCertificateOperation(
            SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid,
            CancelPendingCertificateRequestDto request) throws NotFoundException {
        Certificate cert = certificateRepository.findWithAssociationsByUuid(UUID.fromString(certificateUuid))
                .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        assertCertificateBelongsToRaProfile(cert, authorityUuid, raProfileUuid, "cancel pending operation");

        CancelTarget target = determineCancelTarget(cert);
        String reason = request != null && request.getReason() != null ? request.getReason() : "";

        invokeConnectorCancelOrThrow(cert, target);

        String label = "Pending " + target.pendingOpLabel() + " cancelled";
        String msg = reason.isEmpty() ? label : (label + ". Reason: " + reason);
        commitLocalCancel(cert, target, msg);

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(cert.getUuid(), ResourceAction.UPDATE));
        logger.info("Pending {} for certificate {} cancelled (target state: {})",
                target.pendingOpLabel(), cert.getUuid(), target.targetState());

        return cert.mapToDto();
    }

    /**
     * Carries the per-state choices for {@link #cancelPendingCertificateOperation}.
     *
     * <p>{@code cleanupKind} controls which predecessor/attribute cleanup runs in
     * {@link #commitLocalCancel}: ISSUE deletes predecessor relations (to prevent dangling
     * links on a now-FAILED cert), REVOKE clears the stored revoke attributes, REGISTER
     * requires no extra cleanup.</p>
     */
    private enum CancelCleanupKind { ISSUE, REVOKE, REGISTER }

    private record CancelTarget(CertificateState expectedPendingState, CertificateState targetState,
                                CertificateEvent eventKind, CertificateOperation operation,
                                CancelCleanupKind cleanupKind, String pendingOpLabel) {}

    private CancelTarget determineCancelTarget(Certificate cert) {
        return switch (cert.getState()) {
            case PENDING_ISSUE -> {
                certificateService.checkIssuePermissions();
                yield new CancelTarget(CertificateState.PENDING_ISSUE, CertificateState.FAILED,
                        CertificateEvent.ISSUE, CertificateOperation.ISSUE, CancelCleanupKind.ISSUE, "issuance");
            }
            case PENDING_REVOKE -> {
                certificateService.checkRevokePermissions();
                yield new CancelTarget(CertificateState.PENDING_REVOKE, CertificateState.ISSUED,
                        CertificateEvent.REVOKE, CertificateOperation.REVOKE, CancelCleanupKind.REVOKE, "revocation");
            }
            case PENDING_REGISTRATION -> {
                certificateService.checkIssuePermissions();
                yield new CancelTarget(CertificateState.PENDING_REGISTRATION, CertificateState.FAILED,
                        CertificateEvent.UPDATE_STATE, CertificateOperation.REGISTER, CancelCleanupKind.REGISTER, "registration");
            }
            default -> throw new ValidationException(
                    "Cannot cancel: certificate is not in a pending state. Current state: %s. Certificate: %s"
                            .formatted(cert.getState().getLabel(), cert.toStringShort()));
        };
    }

    /**
     * Invokes the adapter cancel method. For v3 adapters ({@link AsyncOperationCapability}),
     * routes through {@code adapter.cancel(...)}. For v2 adapters (no async capability), falls
     * back to the direct v2 connector client using the pre-M3 call sites (PENDING_REGISTRATION
     * is not reachable on v2 adapters so only ISSUE/REVOKE paths land here).
     *
     * <p>Returns normally when the cancel should proceed locally (CANCELLED or NOT_TRACKED).
     * Throws {@link ValidationException} on hard connector refusal (REFUSED_PAST_POINT_OF_NO_RETURN
     * or any 4xx that is not "not found"). The cert stays in its pending state on a hard refusal.</p>
     */
    private void invokeConnectorCancelOrThrow(Certificate cert, CancelTarget target) throws NotFoundException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());

        if (adapter instanceof AsyncOperationCapability async) {
            invokeAdapterCancel(cert, target, async);
        } else {
            invokeLegacyV2Cancel(cert, target, raProfile);
        }
    }

    private void invokeAdapterCancel(Certificate cert, CancelTarget target, AsyncOperationCapability async) {
        try {
            CancelResult result = async.cancel(cert, target.operation());
            switch (result.outcome()) {
                case CANCELLED, NOT_TRACKED -> {
                    // proceed with local cancel — fall through
                }
                case REFUSED_PAST_POINT_OF_NO_RETURN -> {
                    recordCancelFailure(cert, target,
                            "Authority refused to cancel: operation past point of no return",
                            "Authority refused to cancel pending " + target.pendingOpLabel() + ": past point of no return",
                            new RuntimeException("REFUSED_PAST_POINT_OF_NO_RETURN"));
                    throw new ValidationException("Authority refused to cancel: operation past point of no return");
                }
            }
        } catch (ValidationException e) {
            throw e;
        } catch (ConnectorException e) {
            recordCancelSoftFailure(cert, target,
                    "Connector cancel call failed (proceeding with local cancel): " + e.getMessage(),
                    "Connector cancel call failed; proceeded with local cancel",
                    "Connector cancel call failed for cert {} ({}) — proceeding with local cancel",
                    e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        }
    }

    private void invokeLegacyV2Cancel(Certificate cert, CancelTarget target, RaProfile raProfile) throws NotFoundException {
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        CertificateOperationCancelRequestDto cancelReq = assembleCancelRequest(cert, raProfile);

        try {
            if (target.cleanupKind() == CancelCleanupKind.ISSUE) {
                connectorApiFactory.getCertificateApiClientV2(connectorDto).cancelIssueCertificate(connectorDto,
                        raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), cancelReq);
            } else {
                connectorApiFactory.getCertificateApiClientV2(connectorDto).cancelRevokeCertificate(connectorDto,
                        raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), cancelReq);
            }
        } catch (ValidationException upstreamRefused) {
            recordCancelFailure(cert, target,
                    "Cancel rejected by authority: " + upstreamRefused.getMessage(),
                    "Authority refused to cancel pending " + target.pendingOpLabel() + ": " + upstreamRefused.getMessage(),
                    upstreamRefused);
            throw new ValidationException("Authority refused to cancel the operation");
        } catch (ConnectorEntityNotFoundException notTracked) {
            recordCancelSoftFailure(cert, target,
                    "Connector did not track this operation (404); proceeding with local cancel: " + notTracked.getMessage(),
                    "Connector did not track the operation (404); proceeded with local cancel",
                    "Connector cancel returned 404 for cert {} — proceeding with local cancel: {}", notTracked.getMessage(), notTracked);
        } catch (ConnectorClientException badRequest) {
            int status = badRequest.getHttpStatus().value();
            recordCancelFailure(cert, target,
                    "Connector cancel rejected by " + status,
                    "Connector cancel rejected with HTTP " + status + "; certificate stays in " + cert.getState(),
                    badRequest);
            throw new ValidationException("Connector cancel rejected (" + status + ")");
        } catch (ConnectorServerException | ConnectorCommunicationException infra) {
            recordCancelSoftFailure(cert, target,
                    "Connector cancel call failed with infrastructure error (proceeding with local cancel): " + infra.getMessage(),
                    "Connector cancel call failed (" + infra.getClass().getSimpleName() + "); proceeded with local cancel",
                    "Connector cancel call failed for cert {} ({}) — proceeding with local cancel",
                    infra.getClass().getSimpleName() + ": " + infra.getMessage(), infra);
        } catch (Exception unexpected) {
            recordCancelSoftFailure(cert, target,
                    "Connector cancel call failed (proceeding with local cancel): " + unexpected.getMessage(),
                    "Connector cancel call failed (" + unexpected.getClass().getSimpleName() + "); proceeded with local cancel",
                    "Connector cancel call failed for cert {} ({}) — proceeding with local cancel",
                    unexpected.getClass().getSimpleName() + ": " + unexpected.getMessage(), unexpected);
        }
    }

    private CertificateOperationCancelRequestDto assembleCancelRequest(Certificate cert, RaProfile raProfile) {
        CertificateOperationCancelRequestDto cancelReq = new CertificateOperationCancelRequestDto();
        try {
            cancelReq.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid())
                            .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
            cancelReq.setMeta(attributeEngine.getMetadataAttributesDefinitionContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                            .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
        } catch (Exception attrEx) {
            logger.warn("Failed to assemble cancel request attributes for cert {}: {}",
                    cert.getUuid(), attrEx.getMessage(), attrEx);
        }
        return cancelReq;
    }

    private void recordCancelFailure(Certificate cert, CancelTarget target,
                                     String historyMsg, String eventLogMsg, Exception cause) {
        certificateEventHistoryService.addEventHistory(cert.getUuid(), target.eventKind(),
                CertificateEventStatus.FAILED, historyMsg, "");
        logger.warn("Cancel failed for cert {} ({}): {}", cert.getUuid(), target.pendingOpLabel(), cause.getMessage(), cause);
        eventLogger.logEvent(Operation.CANCEL, OperationResult.FAILURE, null,
                List.of(new ResourceObjectIdentity(cert.getSerialNumber(), cert.getUuid())), eventLogMsg);
    }

    private void recordCancelSoftFailure(Certificate cert, CancelTarget target,
                                         String historyMsg, String eventLogMsg,
                                         String logFormat, String logDetail, Exception cause) {
        certificateEventHistoryService.addEventHistory(cert.getUuid(), target.eventKind(),
                CertificateEventStatus.FAILED, historyMsg, "");
        logger.warn(logFormat, cert.getUuid(), logDetail, cause);
        eventLogger.logEvent(Operation.CANCEL, OperationResult.SUCCESS, null,
                List.of(new ResourceObjectIdentity(cert.getSerialNumber(), cert.getUuid())), eventLogMsg);
    }

    /**
     * Local cancel transition. The connector call ran with no transaction held (the method
     * is {@code @Transactional(NOT_SUPPORTED)}); this brackets the cleanup writes — predecessor
     * relation deletion + state save — in an explicit transaction so they commit or roll back
     * atomically. Mirrors {@code renewCertificate}.
     *
     * <p>Cancel-issue terminates the certificate as {@code FAILED}; like the other failure
     * paths in this class ({@code handleFailedOrRejectedEvent}) it deletes predecessor
     * relations to prevent dangling {@code PENDING} relations on the predecessor — a
     * renew/rekey predecessor would otherwise still link to a now-{@code FAILED}
     * successor.</p>
     */
    private void commitLocalCancel(Certificate cert, CancelTarget target, String cancelMsg) {
        // Rollback-on-RuntimeException semantics match TransactionHandler's declarative default
        // (the only checked exception here, NotFoundException, isn't thrown). The race-guard
        // throws ValidationException (a RuntimeException) which rolls the tx back as before.
        transactionHandler.runInNewTransaction(() -> {
            // Re-read under a pessimistic write lock so a concurrent operator action
            // (manuallyConfirmRevoke, manuallyIssueCertificate) cannot commit between our
            // reload and our save. State is re-verified after acquiring the lock.
            Certificate fresh = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                    .orElseThrow(() -> new ValidationException(
                            "Certificate disappeared during cancel: " + cert.getUuid()));
            // Belt-and-suspenders against Hibernate L1 cache returning a stale entity even
            // after lock acquisition (observed flake in V3RaceConditionITest before this).
            // Refresh forces a re-read from the DB after the FOR UPDATE has been granted.
            entityManager.refresh(fresh);
            if (fresh.getState() != target.expectedPendingState()) {
                throw new ValidationException(
                        "Cancel raced with another operation: certificate " + cert.getUuid()
                                + " is in state " + fresh.getState() + " (expected " + target.expectedPendingState()
                                + "); refusing to overwrite. The connector cancel call may have completed"
                                + " upstream — verify and reconcile manually if needed.");
            }
            switch (target.cleanupKind()) {
                case ISSUE -> {
                    certificateRelationRepository.deleteAll(fresh.getPredecessorRelations());
                    fresh.getPredecessorRelations().clear();
                }
                case REVOKE -> {
                    fresh.setPendingRevokeDestroyKey(null);
                    fresh.setPendingRevokeAttributes(null);
                }
                case REGISTER -> { /* no additional cleanup for registration cancellation */ }
            }
            stateMachine.transition(fresh, target.targetState(), target.eventKind(), cancelMsg);
        });
    }
}
