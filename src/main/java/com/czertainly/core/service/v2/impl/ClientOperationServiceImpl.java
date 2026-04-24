package com.czertainly.core.service.v2.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.v2.CertRevocationDto;
import com.czertainly.api.model.connector.v2.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v2.CertificateRenewRequestDto;
import com.czertainly.api.model.connector.v2.CertificateSignRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
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
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
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
    private PlatformTransactionManager transactionManager;

    private RaProfileRepository raProfileRepository;
    private CertificateRepository certificateRepository;
    private LocationService locationService;
    private CertificateService certificateService;
    private ComplianceService complianceService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private ExtendedAttributeService extendedAttributeService;
    private ConnectorApiFactory connectorApiFactory;
    private CryptographicOperationService cryptographicOperationService;
    private CryptographicKeyService keyService;
    private AttributeEngine attributeEngine;
    private CertificateRelationRepository certificateRelationRepository;

    private ActionProducer actionProducer;
    private EventProducer eventProducer;

    @Autowired
    public void setCertificateRelationRepository(CertificateRelationRepository certificateRelationRepository) {
        this.certificateRelationRepository = certificateRelationRepository;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
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
            throw new CertificateOperationException("Failed to submit certificate request: " + e.getMessage());
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
        certificate.setState(CertificateState.PENDING_APPROVAL);
        certificateRepository.save(certificate);
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

        CertificateSignRequestDto caRequest = new CertificateSignRequestDto();
        caRequest.setRequest(certificate.getCertificateRequest().getContent());
        caRequest.setFormat(certificate.getCertificateRequest().getCertificateRequestFormat());
        caRequest.setAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build()));
        caRequest.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, certificate.getRaProfile().getUuid()).connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).build()));

        try {
            var connectorDto = certificate.getRaProfile().getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
            CertificateDataResponseDto issueCaResponse = connectorApiFactory.getCertificateApiClientV2(connectorDto).issueCertificate(
                    connectorDto,
                    certificate.getRaProfile().getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            if (issueCaResponse.getCertificateData() == null || issueCaResponse.getCertificateData().isEmpty()) {
                throw new CertificateOperationException("Response from authority did not contain certificate data");
            }

            logger.info("Certificate {} was issued by authority", certificateUuid);

            certificateService.issueRequestedCertificate(certificateUuid, issueCaResponse.getCertificateData(), issueCaResponse.getMeta());
        } catch (Exception e) {
            handleFailedOrRejectedEvent(certificate, null, CertificateState.FAILED, CertificateEvent.ISSUE, new HashMap<>(), e.getMessage());
            throw new CertificateOperationException("Failed to issue certificate with UUID %s: ".formatted(certificateUuid) + e.getMessage());
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
        CertificateState oldState = certificate.getState();
        certificate.setState(state);
        certificateRepository.save(certificate);

        certificateRelationRepository.deleteAll(certificate.getPredecessorRelations());

        if (state == CertificateState.FAILED) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            if (event == CertificateEvent.RENEW)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            if (event == CertificateEvent.REKEY)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.REKEY, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
        }

        if (state == CertificateState.REJECTED) {
            if (message == null) {
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_STATE, CertificateEventStatus.SUCCESS, "Certificate state changed from %s to %s.".formatted(oldState.getLabel(), CertificateState.REJECTED.getLabel()), "");
            } else {
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            }
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
            throw new CertificateOperationException("Failed to submit certificate request for certificate renewal: " + e.getMessage());
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

        CertificateRenewRequestDto caRequest = new CertificateRenewRequestDto();
        caRequest.setRequest(certificate.getCertificateRequest().getContent());
        caRequest.setFormat(certificate.getCertificateRequest().getCertificateRequestFormat());
        caRequest.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
        caRequest.setCertificate(oldCertificate.getCertificateContent().getContent());
        // TODO: check if retrieved correctly, just metadata with null source object
        caRequest.setMeta(attributeEngine.getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, oldCertificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));

        CertificateDataResponseDto renewCaResponse;
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        try {
            var connectorDto = raProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
            renewCaResponse = connectorApiFactory.getCertificateApiClientV2(connectorDto).renewCertificate(
                    connectorDto,
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            if (renewCaResponse.getCertificateData() == null || renewCaResponse.getCertificateData().isEmpty()) {
                throw new CertificateOperationException("Response from authority did not contain certificate data");
            }

            logger.info("Certificate {} was renewed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(certificateUuid, renewCaResponse.getCertificateData(), renewCaResponse.getMeta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW, CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation));
        } catch (Exception e) {
            handleFailedOrRejectedEvent(certificate, oldCertificate.getUuid(), CertificateState.FAILED, CertificateEvent.RENEW, additionalInformation, e.getMessage());
            throw new CertificateOperationException("Failed to renew certificate with UUID %s: ".formatted(certificateUuid) + e.getMessage());
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
            throw new CertificateOperationException("Failed to replace certificate in all locations during renew operation: " + e.getMessage());
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
            throw new CertificateOperationException("Failed to submit certificate request for certificate rekey: " + e.getMessage());
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
                signatureAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, oldCertificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build());
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
                    altSignatureAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, oldCertificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build());
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
        CertificateRenewRequestDto caRequest = new CertificateRenewRequestDto();
        caRequest.setRequest(certificate.getCertificateRequest().getContent());
        caRequest.setFormat(certificate.getCertificateRequest().getCertificateRequestFormat());
        caRequest.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
        caRequest.setCertificate(oldCertificate.getCertificateContent().getContent());
        // TODO: check if retrieved correctly, just metadata with null source object
        caRequest.setMeta(attributeEngine.getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, oldCertificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));

        CertificateDataResponseDto renewCaResponse = null;
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        try {
            var connectorDto = raProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
            renewCaResponse = connectorApiFactory.getCertificateApiClientV2(connectorDto).renewCertificate(
                    connectorDto,
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            if (renewCaResponse.getCertificateData() == null || renewCaResponse.getCertificateData().isEmpty()) {
                throw new CertificateOperationException("Response from authority did not contain certificate data");
            }

            logger.info("Certificate {} was rekeyed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(certificateUuid, renewCaResponse.getCertificateData(), renewCaResponse.getMeta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY, CertificateEventStatus.SUCCESS, "Rekeyed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation));
        } catch (Exception e) {
            handleFailedOrRejectedEvent(certificate, oldCertificate.getUuid(), CertificateState.FAILED, CertificateEvent.REKEY, additionalInformation, e.getMessage());
            throw new CertificateOperationException("Failed to rekey certificate with UUID %s: ".formatted(certificateUuid) + e.getMessage());
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
            throw new CertificateOperationException("Failed to replace certificate in all locations during rekey operation: " + e.getMessage());
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
    public void revokeCertificateAction(final UUID certificateUuid, ClientCertificateRevocationDto request, boolean isApproved) throws NotFoundException, CertificateOperationException {
        if (!isApproved) {
            certificateService.checkRevokePermissions();
        }
        final Certificate certificate = certificateRepository.findWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.getState() != CertificateState.ISSUED && certificate.getState() != CertificateState.PENDING_APPROVAL) {
            throw new ValidationException(ValidationError.create(String.format("Cannot issue requested certificate in state %s. Certificate: %s", certificate.getState().getLabel(), certificate)));
        }

        RaProfile raProfile = certificate.getRaProfile();

        logger.debug("Revoking Certificate: {}", certificate);

        try {
            CertRevocationDto caRequest = new CertRevocationDto();
            caRequest.setReason(request.getReason());
            if (request.getReason() == null) {
                caRequest.setReason(CertificateRevocationReason.UNSPECIFIED);
            }
            caRequest.setAttributes(request.getAttributes());
            caRequest.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
            caRequest.setCertificate(certificate.getCertificateContent().getContent());

            var connectorDto = raProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
            connectorApiFactory.getCertificateApiClientV2(connectorDto).revokeCertificate(
                    connectorDto,
                    raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                    caRequest);

            certificate.setState(CertificateState.REVOKED);
            certificateRepository.save(certificate);

            attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build(), request.getAttributes());
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE, CertificateEventStatus.SUCCESS, "Certificate revoked. Reason: " + caRequest.getReason().getLabel(), "");
        } catch (Exception e) {
            certificate.setState(CertificateState.ISSUED);
            certificateRepository.save(certificate);

            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE, CertificateEventStatus.FAILED, e.getMessage(), "");
            logger.error("Failed to revoke Certificate: {}", e.getMessage());
            throw new CertificateOperationException("Failed to revoke certificate: " + e.getMessage());
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

    private Certificate validateOldCertificateForOperation(String certificateUuid, String raProfileUuid, ResourceAction action) throws NotFoundException {
        Certificate oldCertificate = certificateRepository.findByUuid(UUID.fromString(certificateUuid)).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (oldCertificate.isArchived())
            throw new ValidationException("Cannot perform operation %s on archived certificate. Certificate: %s".formatted(action.getCode(), oldCertificate.toStringShort()));
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
}
