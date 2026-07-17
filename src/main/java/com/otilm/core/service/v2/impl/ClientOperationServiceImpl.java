package com.otilm.core.service.v2.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;
import com.otilm.api.model.client.location.PushToLocationRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRequestContent;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.model.connector.v2.CertificateOperationCancelRequestDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.certificate.*;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.v2.*;
import com.otilm.core.attribute.CertificateRequestAttributeProjector;
import com.otilm.core.certificate.request.IssuanceDefinitionResolver;
import com.otilm.core.certificate.request.ProtocolRequestAttributeValidator;
import com.otilm.core.certificate.request.RegisterWireBuilder;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.util.X509RequestContentRenderer;
import com.otilm.core.attribute.engine.AttributeContentPurpose;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.events.handlers.CertificateActionPerformedEventHandler;
import com.otilm.core.events.handlers.CertificateRegisteredEventHandler;
import com.otilm.core.logging.LoggerWrapper;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.handler.authority.AdapterOperationOutcome;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CancelOutcome;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.registration.CertificateRegistrationDefaults;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.service.writer.registration.CertificateRegistrationAuthorizationWriter;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.service.*;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.util.*;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
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
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.BooleanSupplier;

@Service("clientOperationServiceImplV2")
@Transactional
public class ClientOperationServiceImpl implements ClientOperationExternalService, ClientOperationInternalService {
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

    private RaProfileRepository raProfileRepository;
    private CertificateRepository certificateRepository;
    private LocationExternalService locationService;
    private LocationInternalService locationInternalService;
    private CertificateInternalService certificateService;
    private ComplianceInternalService complianceService;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private ExtendedAttributeService extendedAttributeService;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorInternalService connectorService;
    private CryptographicOperationInternalService cryptographicOperationService;
    private CryptographicKeyExternalService keyService;
    private CryptographicKeyInternalService keyInternalService;
    private AttributeEngine attributeEngine;
    private CertificateRelationRepository certificateRelationRepository;

    private ActionProducer actionProducer;
    private EventProducer eventProducer;
    private CertificateStatusPollWriter pollWriter;
    private CertificateRegistrationWriter certificateRegistrationWriter;
    private CertificateRegistrationRepository certificateRegistrationRepository;
    private AuthorityProviderAdapterFactory adapterFactory;
    private CertificateStateMachine stateMachine;
    private ConnectorCapabilityService capabilityService;
    private ProtocolRequestAttributeValidator protocolRequestAttributeValidator;
    private IssuanceDefinitionResolver issuanceDefinitionResolver;
    private RegistrationChallengeStore registrationChallengeStore;
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private CertificateRegistrationAuthorizationWriter registrationAuthorizationWriter;
    private ResourceObjectAssociationService objectAssociationService;

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setProtocolRequestAttributeValidator(ProtocolRequestAttributeValidator protocolRequestAttributeValidator) {
        this.protocolRequestAttributeValidator = protocolRequestAttributeValidator;
    }

    @Autowired
    public void setRegistrationChallengeStore(RegistrationChallengeStore registrationChallengeStore) {
        this.registrationChallengeStore = registrationChallengeStore;
    }

    @Autowired
    public void setRegistrationAuthorizationRepository(CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository) {
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
    }

    @Autowired
    public void setRegistrationAuthorizationWriter(CertificateRegistrationAuthorizationWriter registrationAuthorizationWriter) {
        this.registrationAuthorizationWriter = registrationAuthorizationWriter;
    }

    @Autowired
    public void setIssuanceDefinitionResolver(IssuanceDefinitionResolver issuanceDefinitionResolver) {
        this.issuanceDefinitionResolver = issuanceDefinitionResolver;
    }

    @Autowired
    public void setPollWriter(CertificateStatusPollWriter pollWriter) {
        this.pollWriter = pollWriter;
    }

    @Autowired
    public void setCertificateRegistrationWriter(CertificateRegistrationWriter certificateRegistrationWriter) {
        this.certificateRegistrationWriter = certificateRegistrationWriter;
    }

    @Autowired
    public void setCertificateRegistrationRepository(CertificateRegistrationRepository certificateRegistrationRepository) {
        this.certificateRegistrationRepository = certificateRegistrationRepository;
    }

    @Autowired
    public void setAdapterFactory(AuthorityProviderAdapterFactory adapterFactory) {
        this.adapterFactory = adapterFactory;
    }

    @Autowired
    public void setStateMachine(CertificateStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Autowired
    public void setCapabilityService(ConnectorCapabilityService capabilityService) {
        this.capabilityService = capabilityService;
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
    public void setLocationService(LocationExternalService locationService) {
        this.locationService = locationService;
    }

    @Lazy
    @Autowired
    public void setLocationInternalService(LocationInternalService locationInternalService) {
        this.locationInternalService = locationInternalService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setComplianceService(ComplianceInternalService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryInternalService certificateEventHistoryService) {
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
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCryptographicOperationService(CryptographicOperationInternalService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Autowired
    public void setKeyService(CryptographicKeyExternalService keyService) {
        this.keyService = keyService;
    }

    @Autowired
    public void setKeyInternalService(CryptographicKeyInternalService keyInternalService) {
        this.keyInternalService = keyInternalService;
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
    public void validateIssueCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        extendedAttributeService.validateIssueCertificateAttributes(raProfile, attributes);
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

        RaProfile raProfile = request.getRaProfileUuid() != null
                ? raProfileRepository.findByUuid(request.getRaProfileUuid()).orElse(null)
                : null;
        if (raProfile != null && Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new ValidationException(String.format("Cannot submit certificate request with disabled RA profile. RA Profile: %s", raProfile.getName()));
        }

        String certificateRequest = generateBase64EncodedCsr(request.getRequest(), request.getFormat(), request.getCsrAttributes(), request.getKeyUuid(), request.getTokenProfileUuid(), request.getSignatureAttributes(), request.getAltKeyUuid(), request.getAltTokenProfileUuid(), request.getAltSignatureAttributes(), raProfile);
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
    public ClientCertificateDataResponseDto issueCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final ClientCertificateIssueRequestDto request, final CertificateProtocolInfo protocolInfo) throws NotFoundException, CertificateException, NoSuchAlgorithmException, CertificateOperationException, CertificateRequestException {
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
        } catch (RequestAttributePolicyViolationException e) {
            transactionManager.rollback(status);
            // A client-facing validation failure; must reach the protocol unchanged.
            throw e;
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
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto registerCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
                                                                ClientCertificateRegistrationDto request) throws NotFoundException, ConnectorException, AttributeException {
        if (request == null) {
            throw new ValidationException("A certificate registration request is required.");
        }

        boolean createCustomAttributes = !AuthHelper.isLoggedProtocolUser();

        if (createCustomAttributes) {
            attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, request.getCustomAttributes());
        }
        rejectAmbiguousRegistrationIdentity(request);
        rejectPastRegistrationWindow(request);
        // Connector call below holds no transaction (NOT_SUPPORTED), so load the authority graph eagerly —
        // every association the adapter dereferences must be initialized before the session closes.
        RaProfile raProfile = raProfileRepository.findWithAuthorityByUuid(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        if (Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new ValidationException("Cannot register certificate with disabled RA profile. Ra Profile: %s".formatted(raProfile.getName()));
        }
        assertRaProfileUnderAuthority(raProfile, authorityUuid);

        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);

        // Project structured csrAttributes once (validated) so the placeholder DN and the connector wire derive
        // from the same content; a flat request yields null here and the adapter builds its identity itself.
        X509RequestContent registrationContent = buildStructuredRegistrationContent(raProfile, request);
        String effectiveSubjectDn = registrationContent != null
                ? RegisterWireBuilder.renderSubjectDn(registrationContent)
                : request.getSubjectDn();

        // No connector-backed registration for this authority (not a RegisterCapability, or the flag is not
        // advertised) -> platform-level pre-registration (see registerPlatformLevel); otherwise connector-backed below.
        if (!(adapter instanceof RegisterCapability registerCapability)
                || !capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REGISTRATION)) {
            return registerPlatformLevel(raProfile, request, effectiveSubjectDn, createCustomAttributes);
        }

        Certificate placeholder = certificateService.createRegistrationPlaceholder(raProfile, effectiveSubjectDn);
        // Re-load with the full adapter graph for the transaction-less connector call, as the poll listener does.
        // No pessimistic lock here (unlike the cancel/poll paths): the placeholder was just created and its UUID
        // is not yet known to any concurrent actor, so the read-modify-write below cannot race.
        Certificate certificate = certificateRepository.findForPollingByUuid(placeholder.getUuid())
                .orElseThrow(() -> new NotFoundException(Certificate.class, placeholder.getUuid()));
        stateMachine.transition(certificate, CertificateState.PENDING_REGISTRATION);

        AdapterOperationResult result;
        try {
            // Custom attributes were already validated up front (before the placeholder existed); persisting them
            // here can still fail (e.g. a definition removed concurrently), and no upstream work is in flight yet,
            // so a failure here must fail the placeholder via the catch below rather than orphan it silently
            // attribute-less in PENDING_REGISTRATION.
            if (createCustomAttributes && request.getCustomAttributes() != null && !request.getCustomAttributes().isEmpty()) {
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), request.getCustomAttributes());
            }
            // Apply owner/groups before the connector call, alongside custom attributes: an invalid owner/group
            // UUID fails the placeholder here (pre-acceptance) rather than after a connector has already accepted.
            applyRegistrationAssociations(certificate, request);
            // Persist the challenge authorization before the connector call — on every arc that can leave the
            // certificate reconcilable to REGISTERED (see the method) — but inside the try, so a store/save
            // failure fails the placeholder via the catch below rather than orphaning it in PENDING_REGISTRATION.
            maybeCreateRegistrationAuthorization(certificate, request);
            result = registerCapability.register(certificate, request, registrationContent);
        } catch (ConnectorAcceptedButLocalFailureException e) {
            // Connector already accepted the registration (2xx/202); per the state-divergence rule local state
            // must NOT roll back — leave the cert PENDING_REGISTRATION so the poll or operator reconciles it.
            // Record the divergence to cert-event history (as the sibling meta/issue/revoke paths do) so the
            // audit trail explains why the cert is left PENDING_REGISTRATION.
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_STATE,
                    CertificateEventStatus.FAILED,
                    "Connector accepted the registration but a local step failed; left in PENDING_REGISTRATION for reconciliation. Cause: " + e.getMessage(), "");
            throw e;
        } catch (ConnectorException | RuntimeException | AttributeException | NotFoundException e) {
            // Pre-acceptance failure — either an explicit connector rejection, a custom-attribute persistence
            // failure, or (per the RegisterCapability.register contract, under which any post-acceptance failure
            // must surface as ConnectorAcceptedButLocalFailureException, caught above) a raw RuntimeException.
            // No upstream work is in flight, so fail the placeholder rather than orphaning it in PENDING_REGISTRATION.
            stateMachine.transition(certificate, CertificateState.FAILED, null, "Registration failed: " + safeMessage(e, "registration setup failed"));
            // The authorization row (if the challenge opt-in created one) was committed before the connector call;
            // this registration never became effective, so remove it rather than leave an encrypted secret on a
            // dead certificate. Best-effort: a cleanup failure must not mask the registration failure below.
            deleteRegistrationAuthorizationBestEffort(certificate.getUuid());
            throw e;
        }

        persistRegistrationMeta(certificate, result.meta());
        persistRegistrationBinding(certificate, result.meta());
        if (result.isAsync()) {
            // Log on the actual scheduling outcome, not just instanceof: an async-capable adapter that does not
            // advertise CERTIFICATE_STATUS_POLLING is NOT polled, so "awaiting completion" would be misleading.
            if (scheduleStatusPoll(certificate, adapter, authority, CertificateOperation.REGISTER)) {
                logger.info("Certificate {} registration accepted by authority; awaiting asynchronous completion", certificate.getUuid());
            } else {
                logger.warn("Certificate {} registration accepted asynchronously but status polling is not available "
                        + "(authority is not v3 or does not advertise CERTIFICATE_STATUS_POLLING); "
                        + "left in PENDING_REGISTRATION for manual/out-of-band completion", certificate.getUuid());
            }
        } else {
            stateMachine.transition(certificate, CertificateState.REGISTERED);
            logger.info("Certificate {} registered by authority", certificate.getUuid());
            fireRegistrationEventIfChallengeProtected(certificate.getUuid());
        }

        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setUuid(certificate.getUuid().toString());
        response.setCertificateData(result.certificateData() != null ? result.certificateData() : "");
        return response;
    }

    /**
     * Platform-level pre-registration, used when connector-backed registration is not available for the authority.
     *
     * <p><b>When.</b> The adapter is not a {@code RegisterCapability}, or the authority does not advertise the
     * {@code CERTIFICATE_REGISTRATION} flag.</p>
     *
     * <p><b>Behaviour.</b> The placeholder, its register-&gt;issue binding, and (when a secret is supplied) its
     * challenge authorization are created and owned entirely by the platform, with no connector {@code /register}
     * call. The certificate reaches {@code REGISTERED} directly.</p>
     *
     * <p><b>Completion.</b> Runs later through the normal issue path; {@code issueCertificateAction} routes to the
     * register-bound path only for a {@code RegisterCapability} adapter that advertises the flag, so a platform-level
     * placeholder issues plainly. The binding is the placeholder marker the approval-reject restore keys on, so a
     * no-secret placeholder is restorable too.</p>
     *
     * <p>Nothing here implies a CA-side end-entity exists.</p>
     */
    private ClientCertificateDataResponseDto registerPlatformLevel(RaProfile raProfile,
                                                                   ClientCertificateRegistrationDto request,
                                                                   String effectiveSubjectDn,
                                                                   boolean createCustomAttributes) throws NotFoundException, AttributeException {
        Certificate placeholder = certificateService.createRegistrationPlaceholder(raProfile, effectiveSubjectDn);
        Certificate certificate = certificateRepository.findForPollingByUuid(placeholder.getUuid())
                .orElseThrow(() -> new NotFoundException(Certificate.class, placeholder.getUuid()));
        stateMachine.transition(certificate, CertificateState.PENDING_REGISTRATION);
        try {
            // See the connector-backed path above: custom attributes were already validated up front, but
            // persisting them can still fail, and no upstream work is in flight, so a failure here must fail
            // the placeholder rather than orphan it silently attribute-less in PENDING_REGISTRATION.
            if (createCustomAttributes && request.getCustomAttributes() != null && !request.getCustomAttributes().isEmpty()) {
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), request.getCustomAttributes());
            }
            applyRegistrationAssociations(certificate, request);
            maybeCreateRegistrationAuthorization(certificate, request);
            // Write the register->issue binding (no connector meta) so a platform-level placeholder carries the same
            // marker as a connector-backed one — the discriminator both the issue routing and the approval-reject
            // restore key on, which makes a no-secret placeholder restorable.
            certificateRegistrationWriter.upsert(certificate.getUuid(), List.of());
        } catch (RuntimeException | AttributeException | NotFoundException e) {
            // A challenge store/save, binding-write, or custom-attribute persistence failure must fail the
            // placeholder rather than orphan it in PENDING_REGISTRATION.
            stateMachine.transition(certificate, CertificateState.FAILED, null, "Registration failed: " + safeMessage(e, "registration setup failed"));
            deleteRegistrationAuthorizationBestEffort(certificate.getUuid());
            throw e;
        }
        stateMachine.transition(certificate, CertificateState.REGISTERED);
        logger.info("Certificate {} pre-registered at the platform level (connector-backed registration not advertised for this authority)", certificate.getUuid());
        fireRegistrationEventIfChallengeProtected(certificate.getUuid());

        ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setUuid(certificate.getUuid().toString());
        response.setCertificateData("");
        return response;
    }

    /**
     * Applies the optional owner and groups from the registration request onto the placeholder certificate.
     *
     * <p>An explicit {@code ownerUuid} is set as the owner; when it is absent the registering user becomes the
     * owner (mirroring the plain issue path). {@code groupUuids}, when supplied, replace the certificate's group
     * set. Both associations are set through {@link ResourceObjectAssociationService}, which validates that the
     * owner and each group exist and throws {@link NotFoundException} otherwise.</p>
     *
     * <p>Called before the connector call (alongside custom attributes) so an invalid owner/group UUID fails the
     * placeholder pre-acceptance rather than diverging from a connector that has already accepted the
     * registration. The values are preserved when the pre-registered certificate is later issued, because the
     * register-&gt;issue path reuses the same entity and does not reset owner or groups.</p>
     */
    private void applyRegistrationAssociations(Certificate certificate, ClientCertificateRegistrationDto request)
            throws NotFoundException {
        UUID certificateUuid = certificate.getUuid();
        if (request.getOwnerUuid() != null && !request.getOwnerUuid().isBlank()) {
            objectAssociationService.setOwner(Resource.CERTIFICATE, certificateUuid, UUID.fromString(request.getOwnerUuid()));
        } else {
            objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, certificateUuid);
        }
        if (request.getGroupUuids() != null && !request.getGroupUuids().isEmpty()) {
            objectAssociationService.setGroups(Resource.CERTIFICATE, certificateUuid, request.getGroupUuids());
        }
    }

    /**
     * The pre-registration identity may be supplied structured (via {@code csrAttributes}) or flat (via
     * subjectDn/subjectAltName/extensions), never both — the register handling owns this precedence
     * (see the {@code ClientCertificateRegistrationDto} schema).
     */
    private static void rejectAmbiguousRegistrationIdentity(ClientCertificateRegistrationDto request) {
        if (hasStructuredIdentity(request.getCsrAttributes()) && hasFlatIdentity(request)) {
            throw new ValidationException(
                    "Provide the pre-registration identity either via csrAttributes or the flat subjectDn/subjectAltName/extensions, not both");
        }
    }

    /**
     * Projects a structured pre-registration request ({@code csrAttributes}) into the register identity content,
     * once and validated, so the placeholder DN and the connector wire derive from the same projection. Returns
     * null for a flat request, whose identity the adapter builds from subjectDn/subjectAltName/extensions.
     */
    private X509RequestContent buildStructuredRegistrationContent(RaProfile raProfile, ClientCertificateRegistrationDto request)
            throws ConnectorException, NotFoundException {
        if (!hasStructuredIdentity(request.getCsrAttributes())) {
            return null;
        }
        // The gate tolerates null elements (anyMatch); drop them before validation/projection so a
        // partially-null list projects the real attributes instead of NPE-ing in the projector.
        List<RequestAttribute> csrAttributes = request.getCsrAttributes().stream().filter(Objects::nonNull).toList();
        List<DataAttributeV3> definitions = issuanceDefinitionResolver.resolve(raProfile);
        try {
            attributeEngine.validateUpdateDataAttributes(null, null, definitions, csrAttributes);
        } catch (AttributeException e) {
            throw new ValidationException("Invalid csrAttributes for certificate registration: " + e.getMessage());
        }
        X509RequestContent content = CertificateRequestAttributeProjector.project(definitions, csrAttributes);
        boolean hasSubject = content.getSubject() != null && !content.getSubject().isEmpty();
        boolean hasSan = content.getSubjectAltNames() != null && !content.getSubjectAltNames().isEmpty();
        if (!hasSubject && !hasSan) {
            // Optional/unmapped/extension-only csrAttributes can project to no subject and no SAN; reject
            // locally rather than create a placeholder and register an identity-less certificate.
            throw new ValidationException(
                    "csrAttributes did not yield a subject or subjectAltName for the pre-registration identity");
        }
        // A connector without CERTIFICATE_REQUEST_STRUCTURED carries only the flat wire; content it cannot
        // represent (a non-DER extension or non-UTF8 otherName that only structured csrAttributes can produce)
        // is rejected here, before the placeholder, so a purely-local rejection leaves no row — uniform with the
        // sibling rejectAmbiguousRegistrationIdentity and empty-projection validations. The adapter re-checks
        // when it builds the flat wire, so this hoist is a consistency guard, not the sole enforcement.
        if (!capabilityService.supports(raProfile.getAuthorityInstanceReference(), FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)) {
            RegisterWireBuilder.assertFlatRepresentable(content);
        }
        return content;
    }

    /**
     * Rejects a past issuance window at the registration boundary, before any placeholder is created — a past
     * {@code expiresAt} would produce an instantly-dead registration. Validated here (alongside
     * rejectAmbiguousRegistrationIdentity) rather than at row creation so the rejection leaves no orphaned
     * placeholder.
     */
    private static void rejectPastRegistrationWindow(ClientCertificateRegistrationDto request) {
        String secret = request.getAuthorizationSecret();
        OffsetDateTime expiresAt = request.getExpiresAt();
        if (secret != null && !secret.isBlank() && expiresAt != null && !expiresAt.isAfter(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new ValidationException("The registration issuance window (expiresAt) must be in the future.");
        }
    }

    /**
     * Creates the durable challenge authorization for a self-service pre-registration when the operator supplied an
     * {@code authorizationSecret}. Created before the connector call, not after: a connector-accepted-but-local
     * failure leaves the certificate reconcilable to REGISTERED, and a row written only on the success path would be
     * missing there — the later issue gate would then treat a secret-protected registration as unprotected and issue
     * with no challenge. Absent secret means no row, so the operator register→issue flow is unchanged.
     */
    private CertificateRegistrationSettingsDto registrationSettings() {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        return platformSettings != null && platformSettings.getCertificates() != null
                ? platformSettings.getCertificates().getRegistration() : null;
    }

    // The fallbacks below use the single canonical defaults (the value the settings API reports and persists) so
    // the value applied on a cache miss cannot drift from the operator-visible default.
    private int registrationWindowDays() {
        CertificateRegistrationSettingsDto settings = registrationSettings();
        return settings != null && settings.getDefaultIssuanceWindowDays() != null
                ? settings.getDefaultIssuanceWindowDays() : CertificateRegistrationDefaults.ISSUANCE_WINDOW_DAYS;
    }

    private int maxFailedRegistrationAttempts() {
        CertificateRegistrationSettingsDto settings = registrationSettings();
        return settings != null && settings.getMaxFailedAttempts() != null
                ? settings.getMaxFailedAttempts() : CertificateRegistrationDefaults.MAX_FAILED_ATTEMPTS;
    }

    private void maybeCreateRegistrationAuthorization(Certificate certificate, ClientCertificateRegistrationDto request) {
        String secret = request.getAuthorizationSecret();
        if (secret == null || secret.isBlank()) {
            return;
        }
        OffsetDateTime expiresAt = request.getExpiresAt();
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(certificate.getUuid());
        authorization.setState(RegistrationState.ACTIVE);
        authorization.setFailedAttempts(0);
        authorization.setExpiresAt(expiresAt != null ? expiresAt : OffsetDateTime.now(ZoneOffset.UTC).plus(Duration.ofDays(registrationWindowDays())));
        registrationChallengeStore.store(authorization, secret);
        registrationAuthorizationRepository.save(authorization);
    }

    private void deleteRegistrationAuthorizationBestEffort(UUID certificateUuid) {
        // The writer opens its own transaction (registerCertificate is NOT_SUPPORTED). Best-effort: swallow a
        // cleanup failure so it never masks the caller's registration failure. A no-op when there is no
        // authorization row (e.g. a registration with no challenge).
        try {
            registrationAuthorizationWriter.deleteByCertificateUuid(certificateUuid);
        } catch (RuntimeException e) {
            logger.warn("Failed to remove the registration authorization for failed certificate {}: {}", certificateUuid, e.getMessage());
        }
    }

    private void fireRegistrationEventIfChallengeProtected(UUID certificateUuid) {
        // Fire the Certificate Registered event only for challenge-protected pre-registrations (those with an
        // authorization row); an operator registration without a challenge has no credential to deliver.
        // Best-effort: the certificate is already committed REGISTERED, so neither the authorization lookup nor the
        // produce may fail the caller (a false failure could drive a re-registration). Delivery durability is
        // tracked separately. The whole side effect — lookup included — is inside the guard.
        try {
            if (registrationAuthorizationRepository.existsByCertificateUuid(certificateUuid)) {
                eventProducer.produceMessage(CertificateRegisteredEventHandler.constructEventMessage(certificateUuid));
            }
        } catch (RuntimeException e) {
            logger.warn("Failed to produce CERTIFICATE_REGISTERED event for cert {}", certificateUuid, e);
        }
    }

    /**
     * Challenge gate for completing a pre-registered certificate. Issue is the only challenge-verified completion
     * path; renew and rekey of a registered certificate are fail-closed instead (see
     * rejectRenewOrRekeyOfActiveRegistration). A certificate with no authorization row is not self-service and
     * passes untouched. On an ACTIVE authorization it
     * enforces, under a per-row pessimistic lock, the issuance window then the operator challenge; LOCKED/EXPIRED
     * deny; CLOSED passes as unregistered. The failed-attempt increment and lockout are committed before the caller
     * rejects the request, so the counter survives the rejection — a rollback would erase it and lockout could never
     * trigger.
     */
    private void verifyRegistrationChallenge(UUID certificateUuid, String presentedSecret) {
        if (registrationAuthorizationRepository.findByCertificateUuid(certificateUuid).isEmpty()) {
            return;
        }
        String denial = evaluateRegistrationChallengeUnderLock(certificateUuid, presentedSecret);
        if (denial != null) {
            throw new ValidationException(ValidationError.create(denial));
        }
    }

    private String evaluateRegistrationChallengeUnderLock(UUID certificateUuid, String presentedSecret) {
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            String denial = registrationAuthorizationRepository.findAndLockByCertificateUuid(certificateUuid)
                    .map(authorization -> evaluateLockedAuthorization(authorization, presentedSecret))
                    // Raced with a delete/close between the peek and the lock — treat as non-self-service.
                    .orElse(null);
            transactionManager.commit(tx);
            return denial;
        } catch (RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }
    }

    private String evaluateLockedAuthorization(CertificateRegistrationAuthorization authorization, String presentedSecret) {
        UUID certificateUuid = authorization.getCertificateUuid();
        RegistrationState state = authorization.getState();
        if (state == RegistrationState.CLOSED) {
            return null;
        }
        if (state == RegistrationState.LOCKED) {
            // Record every attempt against an already-locked authorization — persistent hammering is exactly when
            // the audit trail matters most.
            certificateEventHistoryService.addEventHistory(certificateUuid, CertificateEvent.ISSUE, CertificateEventStatus.FAILED,
                    "Certificate registration challenge attempted against a locked authorization", "");
            return "The certificate registration authorization is locked after too many failed attempts.";
        }
        if (state == RegistrationState.EXPIRED) {
            return "The certificate registration issuance window has expired.";
        }
        OffsetDateTime expiresAt = authorization.getExpiresAt();
        if (expiresAt != null && !OffsetDateTime.now(ZoneOffset.UTC).isBefore(expiresAt)) {
            authorization.setState(RegistrationState.EXPIRED);
            registrationAuthorizationRepository.save(authorization);
            certificateEventHistoryService.addEventHistory(certificateUuid, CertificateEvent.ISSUE, CertificateEventStatus.FAILED,
                    "Certificate registration issuance window expired", "");
            return "The certificate registration issuance window has expired.";
        }
        if (registrationChallengeStore.verify(authorization, presentedSecret)) {
            if (authorization.getFailedAttempts() != 0) {
                authorization.setFailedAttempts(0);
                registrationAuthorizationRepository.save(authorization);
            }
            return null;
        }
        int attempts = authorization.getFailedAttempts() + 1;
        authorization.setFailedAttempts(attempts);
        if (attempts >= maxFailedRegistrationAttempts()) {
            authorization.setState(RegistrationState.LOCKED);
        }
        registrationAuthorizationRepository.save(authorization);
        certificateEventHistoryService.addEventHistory(certificateUuid, CertificateEvent.ISSUE, CertificateEventStatus.FAILED,
                "Certificate registration challenge verification failed (attempt %d)".formatted(attempts), "");
        return "The certificate registration challenge is invalid.";
    }

    /**
     * Fail-closed guard: a certificate with an ACTIVE registration authorization must not be renewed or rekeyed
     * until those paths are challenge-gated (together with copying the authorization to the successor), so neither
     * can silently exit the challenge regime. This also denies platform-automation renewals (locations, workflows,
     * scheduled renew) of such certificates. Issue completion remains the challenge-verified path
     * (verifyRegistrationChallenge).
     */
    private void rejectRenewOrRekeyOfActiveRegistration(UUID certificateUuid) {
        registrationAuthorizationRepository.findByCertificateUuid(certificateUuid)
                .filter(authorization -> authorization.getState() == RegistrationState.ACTIVE)
                .ifPresent(authorization -> {
                    throw new ValidationException(ValidationError.create(
                            "This certificate has an active registration; renew and rekey of registered certificates are not supported yet."));
                });
    }

    private static boolean hasStructuredIdentity(List<RequestAttribute> csrAttributes) {
        return csrAttributes != null && csrAttributes.stream().anyMatch(Objects::nonNull);
    }

    private static boolean hasFlatIdentity(ClientCertificateRegistrationDto request) {
        return isNotBlank(request.getSubjectDn())
                || isNotBlank(request.getSubjectAltName())
                || (request.getExtensions() != null && !request.getExtensions().isEmpty());
    }

    private static boolean isNotBlank(String value) {
        return value != null && !value.isBlank();
    }

    /**
     * Persists connector-returned tracking metadata against the certificate so a later status poll or
     * cancel can replay it. Registration has already been accepted upstream by the time this runs, so a
     * persistence failure must not roll local state back (state-divergence rule): it is recorded to
     * cert-event history and the flow proceeds, with later tracking falling back to queryable metadata.
     */
    private void persistRegistrationMeta(Certificate certificate, List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return;
        }
        try {
            attributeEngine.updateMetadataAttributes(meta,
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid())
                            .connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid())
                            .build());
        } catch (Exception metaEx) {
            logger.warn("Failed to persist registration metadata for cert {}: {}", certificate.getUuid(), metaEx.getMessage(), metaEx);
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_STATE,
                    CertificateEventStatus.FAILED,
                    "Failed to persist connector registration metadata; later status tracking may be limited. Cause: " + metaEx.getMessage(), "");
        }
    }

    /**
     * Persists the register->issue binding carrying the CA handle the later issue replays. Registration is
     * already accepted upstream, so a failure is surfaced (state-divergence rule) rather than rolled back.
     */
    private void persistRegistrationBinding(Certificate certificate, List<MetadataAttribute> meta) throws ConnectorAcceptedButLocalFailureException {
        try {
            certificateRegistrationWriter.upsert(certificate.getUuid(), meta);
        } catch (RuntimeException e) {
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_STATE,
                    CertificateEventStatus.FAILED,
                    "Connector accepted the registration but persisting the register->issue binding failed; left in "
                            + certificate.getState().getLabel() + " for reconciliation. Cause: "
                            + safeMessage(e, "persisting the registration binding failed"), "");
            throw new ConnectorAcceptedButLocalFailureException(
                    "Connector accepted the registration but persisting the register->issue binding failed", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public AvailableOperationsDto listAvailableOperations(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid) throws NotFoundException {
        RaProfile raProfile = raProfileRepository.findWithAuthorityByUuid(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        assertRaProfileUnderAuthority(raProfile, authorityUuid);
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);

        // Capability-derived support flags, gated defense-in-depth — protocol-level (instanceof) AND the
        // opt-in FeatureFlag advertised by the connector interface: register needs RegisterCapability +
        // CERTIFICATE_REGISTRATION; async completion + cancellation need AsyncOperationCapability +
        // CERTIFICATE_STATUS_POLLING.
        boolean register = adapter instanceof RegisterCapability
                && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REGISTRATION);
        boolean async = adapter instanceof AsyncOperationCapability
                && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_STATUS_POLLING);
        List<OperationSupport> operations = List.of(
                new OperationSupport(CertificateOperationKind.ISSUE, true, async, async),
                new OperationSupport(CertificateOperationKind.RENEW, true, async, async),
                new OperationSupport(CertificateOperationKind.REVOKE, true, async, async),
                // REGISTER cancel is not advertised: determineCancelTarget handles only PENDING_ISSUE /
                // PENDING_REVOKE, so cancelling a PENDING_REGISTRATION cert is not yet implemented.
                new OperationSupport(CertificateOperationKind.REGISTER, register, register && async, false)
        );
        return new AvailableOperationsDto(operations);
    }

    @Override
    public void approvalCreatedAction(UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        // Only REQUESTED (issue approval), REGISTERED (issue approval for a registered placeholder)
        // and ISSUED (revoke approval) can enter PENDING_APPROVAL.
        // A redelivered approval-created message for a certificate that already advanced past those
        // states is a no-op: without this guard the SM would reject the now-illegal transition and
        // fail the message. The APPROVAL_REQUEST history entry is owned by ApprovalRequestedEventHandler,
        // so the SM only gates and mutates the state here — transitionAuditedExternally avoids a
        // duplicate history row.
        if (certificate.getState() != CertificateState.REQUESTED
                && certificate.getState() != CertificateState.REGISTERED
                && certificate.getState() != CertificateState.ISSUED) {
            logger.debug("Certificate {} is in state {}, not awaiting an approval request; skipping PENDING_APPROVAL transition",
                    certificateUuid, certificate.getState().getLabel());
            return;
        }
        stateMachine.transitionAuditedExternally(certificate, CertificateState.PENDING_APPROVAL);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void issueCertificateAction(final UUID certificateUuid, boolean isApproved) throws CertificateOperationException, NotFoundException {
        if (!isApproved) {
            certificateService.checkIssuePermissions();
        }

        // A pre-registered placeholder (binding present) issues register-bound only when its authority actually
        // does connector-backed registration — a RegisterCapability adapter advertising CERTIFICATE_REGISTRATION.
        // A platform-level placeholder carries a binding too but no such connector support, so it issues plainly.
        // The register-bound path re-locks and re-asserts state; this only picks the route.
        if (certificateRegistrationRepository.findByCertificateUuid(certificateUuid).isPresent()) {
            Certificate placeholder = certificateRepository.findWithAuthorityAssociationsByUuid(certificateUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            AuthorityInstanceReference authority = placeholder.getRaProfile() != null
                    ? placeholder.getRaProfile().getAuthorityInstanceReference() : null;
            if (authority != null
                    && adapterFactory.forAuthority(authority) instanceof RegisterCapability registerCapability
                    && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REGISTRATION)) {
                issueRegisteredCertificateAction(placeholder, registerCapability);
                return;
            }
        }
        issuePlainCertificateAction(certificateUuid);
    }

    private void issuePlainCertificateAction(final UUID certificateUuid) throws CertificateOperationException, NotFoundException {
        // Claim the certificate under a pessimistic row lock, committing before the connector call so the lock never spans HTTP.
        // Two ISSUE actions can race; serializing the claim lets one win the PENDING_ISSUE transition and the loser skip.
        // Post-commit code uses data captured here because the entity detaches on commit.
        Certificate certificate;
        AuthorityInstanceReference authority;
        ClientCertificateIssueRequestDto req = new ClientCertificateIssueRequestDto();
        List<CertificateLocationId> locationIds;
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            certificate = certificateRepository.findAndLockWithAssociationsByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            if (certificate.isArchived())
                throw new ValidationException(ValidationError.create(String.format("Cannot issue certificate that has been archived. Certificate: %s", certificate.toStringShort())));

            // If the state is no longer claimable, a concurrent ISSUE already claimed this certificate to PENDING_ISSUE (or it reached a terminal state).
            // Commit and return rather than letting it fall into the connector catch, because PENDING_ISSUE -> FAILED is a *legal* transition.
            if (certificate.getState() != CertificateState.REQUESTED && certificate.getState() != CertificateState.PENDING_APPROVAL && certificate.getState() != CertificateState.REGISTERED) {
                logger.info("Certificate {} is in state {} and no longer claimable for issuance; a concurrent ISSUE action likely won the claim — skipping", certificateUuid, certificate.getState().getLabel());
                transactionManager.commit(tx);
                return;
            }
            if (certificate.getRaProfile() == null) {
                throw new ValidationException(ValidationError.create(String.format("Cannot issue certificate with no RA Profile associated. Certificate: %s", certificate)));
            }
            if (certificate.getCertificateRequest() == null) {
                throw new ValidationException(ValidationError.create(String.format("Cannot issue certificate with no certificate request. Certificate: %s", certificate)));
            }

            authority = certificate.getRaProfile().getAuthorityInstanceReference();

            // Force-load the CSR content while the session is still open.
            certificate.getCertificateRequest().getContent();

            // Materialize location ids for the post-commit push loop while the collection is still attached to the session.
            locationIds = certificate.getLocations().stream().map(CertificateLocation::getId).toList();

            // Move to PENDING_ISSUE before calling the connector so every path (sync 200 or async
            // 202) reaches issueRequestedCertificate / the poll cycle from a uniform PENDING_ISSUE
            // state via the state machine. The sync path creates no poll row, so a crash before the
            // terminal transition leaves the cert in PENDING_ISSUE until PendingIssueReaper reaps it.
            stateMachine.transition(certificate, CertificateState.PENDING_ISSUE, CertificateEvent.ISSUE,
                    "Issuance in progress");
            transactionManager.commit(tx);
        } catch (NotFoundException | RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }

        callConnectorAndFinalizeIssue(certificateUuid, certificate, req, authority, locationIds);
    }

    /**
     * Post-commit issuance phase: dispatch through the adapter factory after the claim tx has released its lock
     * (the certificate is now detached), then finalize.
     */
    private void callConnectorAndFinalizeIssue(final UUID certificateUuid, Certificate certificate,
            ClientCertificateIssueRequestDto req, AuthorityInstanceReference authority,
            List<CertificateLocationId> locationIds) throws CertificateOperationException, NotFoundException {
        AdapterOperationResult result;
        try {
            result = adapterFactory.forAuthority(authority).issue(certificate, req);
        } catch (ConnectorAcceptedButLocalFailureException e) {
            // Connector accepted (v3 acceptance guard) but a local step failed: honour the state-divergence rule.
            String pendingIssueLabel = CertificateState.PENDING_ISSUE.getLabel();
            certificateEventHistoryService.addEventHistory(certificateUuid, CertificateEvent.ISSUE,
                    CertificateEventStatus.FAILED,
                    "Connector accepted the issue but a local step failed; left %s for reconciliation. Cause: %s"
                            .formatted(pendingIssueLabel, safeMessage(e, "issuance failed")), "");
            throw new CertificateOperationException(
                    "Connector accepted the issue for certificate %s but a local step failed; left %s for reconciliation."
                            .formatted(certificateUuid, pendingIssueLabel));
        } catch (Exception e) {
            logger.warn("Pre-acceptance issuance failure for certificate {}; failing the claimed placeholder", certificateUuid, e);
            failClaimedCertificate(certificateUuid, e);
            throw new CertificateOperationException(
                    "Failed to issue certificate with UUID %s: ".formatted(certificateUuid) + safeMessage(e, "issuance failed"));
        }

        try {
            finalizeIssuance(certificateUuid, certificate, result, locationIds);
        } catch (CertificateOperationException e) {
            certificateEventHistoryService.addEventHistory(certificateUuid, CertificateEvent.ISSUE,
                    CertificateEventStatus.FAILED,
                    "Certificate was issued by the authority but completing local state failed; reconcile manually. Cause: "
                            + safeMessage(e, "issuance completion failed"), "");
            throw e;
        }
    }

    private void finalizeIssuance(final UUID certificateUuid, Certificate certificate, AdapterOperationResult result,
            List<CertificateLocationId> locationIds) throws CertificateOperationException, NotFoundException {
        if (result.isAsync() || result.outcome() == AdapterOperationOutcome.SYNC_NO_CONTENT) {
            onAsyncAccepted(certificate, result.meta(), ResourceAction.ISSUE);
            return;
        }
        if (result.certificateData() == null || result.certificateData().isEmpty()) {
            throw new CertificateOperationException(
                    "Response from authority did not contain certificate data; certificate %s left in %s for reconciliation."
                            .formatted(certificateUuid, CertificateState.PENDING_ISSUE.getLabel()));
        }
        logger.info("Certificate {} was issued by authority", certificateUuid);
        try {
            // The connector already returned the certificate synchronously (post-acceptance).
            certificateService.issueRequestedCertificate(certificateUuid, result.certificateData(), result.meta());
        } catch (Exception e) {
            logger.warn("Certificate {} was issued by the authority but completing local state failed; reconcile manually", certificateUuid, e);
            throw new CertificateOperationException(
                    "Certificate %s was issued by the authority but completing local state failed; reconcile manually. Cause: "
                            .formatted(certificateUuid) + safeMessage(e, "issuance completion failed"));
        }
        afterSynchronousIssue(certificateUuid, locationIds);
    }

    /** Re-reads the claimed cert under a short row lock and transitions PENDING_ISSUE -> FAILED. */
    private void failClaimedCertificate(final UUID certificateUuid, Exception cause) {
        failClaimedCertificate(certificateUuid, cause, "issuance failed");
    }

    /**
     * As {@link #failClaimedCertificate(UUID, Exception)}, but with the fallback reason recorded when {@code cause}
     * is not one of our shaped domain exceptions (so its raw message must not be exposed).
     */
    private void failClaimedCertificate(final UUID certificateUuid, Exception cause, String fallbackReason) {
        TransactionStatus failTx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate managed = certificateRepository.findAndLockWithAssociationsByUuid(certificateUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            handleFailedOrRejectedEvent(managed, null, CertificateState.FAILED, CertificateEvent.ISSUE, new HashMap<>(),
                    safeMessage(cause, fallbackReason));
            transactionManager.commit(failTx);
        } catch (Exception failEx) {
            transactionManager.rollback(failTx);
            logger.error("Failed to record issuance failure for certificate {}: {}", certificateUuid, failEx.getMessage(), failEx);
        }
    }

    /**
     * Issues against a prior registration. The phases keep the pessimistic lock off the connector call and honour
     * the state-divergence rule once the connector has accepted.
     */
    private void issueRegisteredCertificateAction(Certificate certificate, RegisterCapability registerCapability)
            throws CertificateOperationException, NotFoundException {
        RegisterReplayContext replay = captureRegisterReplayContext(certificate);
        AdapterOperationResult result = callRegisterBoundIssue(certificate, registerCapability, replay);
        completeAcceptedRegisterBoundIssue(certificate, result);
        clearBindingBestEffort(certificate.getUuid());
    }

    /** The binding's replayable CA handle plus the optional identity-override content, captured under the lock. */
    private record RegisterReplayContext(List<MetadataAttribute> replayMeta, CertificateRequestContent identityContent) {
    }

    /**
     * Phase 1 of register-bound issuance: prepare the connector call under a short pessimistic-write lock.
     *
     * <p>Holding the lock, this captures the replay handle and identity-override content, then re-asserts that
     * the certificate is still in an issuable state ({@code REGISTERED} or {@code PENDING_APPROVAL}). Any other
     * state means a concurrent operation won the race, and this throws. On success it claims the placeholder
     * into {@code PENDING_ISSUE} and releases the lock before the connector call in Phase 2.
     */
    private RegisterReplayContext captureRegisterReplayContext(Certificate certificate)
            throws CertificateOperationException, NotFoundException {
        final UUID certUuid = certificate.getUuid();
        final AuthorityInstanceReference authority = certificate.getRaProfile().getAuthorityInstanceReference();
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            CertificateRegistration binding = certificateRegistrationRepository.findAndLockByCertificateUuid(certUuid)
                    .orElseThrow(() -> new CertificateOperationException(
                            "Certificate %s has no registration binding; cannot issue against a missing registration (reconcile manually)."
                                    .formatted(certUuid)));
            // Lock the certificate row too: the binding lock alone does not stop concurrent certificate mutators.
            Certificate managed = certificateRepository.findAndLockWithAssociationsByUuid(certUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certUuid));
            CertificateState state = managed.getState();
            if (state != CertificateState.REGISTERED && state != CertificateState.PENDING_APPROVAL) {
                throw new CertificateOperationException(
                        "Register-bound issue for certificate %s raced with another operation; state is now %s."
                                .formatted(certUuid, state.getLabel()));
            }
            List<MetadataAttribute> replayMeta = binding.getMeta() == null || binding.getMeta().isBlank()
                    ? List.of()
                    : AttributeDefinitionUtils.deserialize(binding.getMeta(), MetadataAttribute.class);
            CertificateRequestContent identityContent =
                    capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)
                            && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_IDENTITY_OVERRIDE)
                            ? RegisterWireBuilder.buildIdentityContent(certificate.getSubjectDn())
                            : null;
            stateMachine.transition(managed, CertificateState.PENDING_ISSUE, CertificateEvent.ISSUE,
                    "Issuance in progress");
            transactionManager.commit(tx);
            return new RegisterReplayContext(replayMeta, identityContent);
        } catch (RuntimeException | NotFoundException | CertificateOperationException e) {
            if (!tx.isCompleted()) {
                transactionManager.rollback(tx);
            }
            throw e;   // pre-acceptance, local — nothing upstream in flight
        }
    }

    /**
     * Phase 2 — call the connector with no tx/lock held.
     */
    private AdapterOperationResult callRegisterBoundIssue(Certificate certificate,
                                                          RegisterCapability registerCapability,
                                                          RegisterReplayContext replay)
            throws CertificateOperationException {
        final UUID certUuid = certificate.getUuid();
        final String pendingIssueLabel = CertificateState.PENDING_ISSUE.getLabel();
        try {
            return registerCapability.issueRegistered(certificate, replay.replayMeta(), replay.identityContent());
        } catch (ConnectorAcceptedButLocalFailureException e) {
            logger.warn("Connector accepted the register-bound issue for cert {} but a local adapter step failed; "
                    + "left {} for reconciliation", certUuid, pendingIssueLabel, e);
            certificateEventHistoryService.addEventHistory(certUuid, CertificateEvent.ISSUE,
                    CertificateEventStatus.FAILED,
                    "Connector accepted the register-bound issue but a local step failed; left %s for reconciliation. Cause: %s"
                            .formatted(pendingIssueLabel, safeMessage(e, "register-bound issuance failed")), "");
            throw new CertificateOperationException(
                    "Connector accepted the register-bound issue for certificate %s but a local step failed; left %s for reconciliation."
                            .formatted(certUuid, pendingIssueLabel));
        } catch (ConnectorException | RuntimeException e) {
            String reason = safeMessage(e, "register-bound issuance failed");
            failClaimedCertificate(certUuid, e, "register-bound issuance failed");
            clearBindingBestEffort(certUuid);
            throw new CertificateOperationException(
                    "Failed to issue register-bound certificate %s: %s".formatted(certUuid, reason));
        }
    }

    /**
     * Phase 3 — the connector has accepted, so this phase only finalizes.
     */
    private void completeAcceptedRegisterBoundIssue(Certificate certificate, AdapterOperationResult result)
            throws CertificateOperationException {
        final UUID certUuid = certificate.getUuid();
        try {
            finalizeIssuance(certUuid, certificate, result, List.of());
        } catch (Exception e) {
            logger.warn("Connector accepted the register-bound issue for cert {} but completing local state failed; "
                    + "reconcile manually", certUuid, e);
            certificateEventHistoryService.addEventHistory(certUuid, CertificateEvent.ISSUE,
                    CertificateEventStatus.FAILED,
                    "Connector accepted the register-bound issue but completing local state failed; reconcile manually. Cause: "
                            + safeMessage(e, "register-bound issuance failed"), "");
            throw new CertificateOperationException(
                    "Connector accepted the register-bound issue for certificate %s but completing local state failed; reconcile manually."
                            .formatted(certUuid));
        }
    }

    /**
     * Phase 4 — clear the binding. Best-effort: a lingering row is harmless (the state guard prevents re-issue),
     * so a failure is logged, not surfaced.
     */
    private void clearBindingBestEffort(UUID certUuid) {
        try {
            certificateRegistrationWriter.clear(certUuid);
        } catch (RuntimeException e) {
            logger.warn("Connector accepted the register-bound issue for cert {} but clearing the binding failed: {}", certUuid, e.getMessage());
        }
    }

    /**
     * Post-issuance side effects shared by the v2 and sync register-bound paths: push to the certificate's
     * locations (best-effort), then raise {@code CERTIFICATE_ACTION_PERFORMED}. Takes ids captured while the
     * entity was attached, so it stays safe after the claim transaction commits and detaches the entity.
     */
    private void afterSynchronousIssue(UUID certificateUuid, List<CertificateLocationId> locationIds) {
        for (CertificateLocationId locationId : locationIds) {
            try {
                locationInternalService.pushRequestedCertificateToLocationAction(locationId, false);
            } catch (Exception e) {
                logger.error("Failed to push issued certificate to location: {}", e.getMessage());
            }
        }
        eventProducer.produceMessage(CertificateActionPerformedEventHandler.constructEventMessage(certificateUuid, ResourceAction.ISSUE));
    }

    /** Includes the message only from our shaped domain exceptions (connector/operation/validation); other causes (e.g. JPA) fall back to {@code fallback}. */
    private static String safeMessage(Exception e, String fallback) {
        return (e instanceof ConnectorException || e instanceof CertificateOperationException || e instanceof ValidationException)
                && e.getMessage() != null
                ? e.getMessage()
                : fallback;
    }

    /** Delegates with the metadata from the connector's {@code 202 Accepted} response body. */
    private void onAsyncAccepted(Certificate certificate, AdapterOperationResult result, ResourceAction originatingAction) {
        onAsyncAccepted(certificate,
                result != null ? result.meta() : null,
                originatingAction);
    }

    /**
     * Records the connector's async acceptance ({@code 202}) of an issue/renew/rekey: persists returned metadata,
     * schedules the status poll, raises the action-performed event, and writes the event-log entry. The cert is
     * already in {@code PENDING_ISSUE}, so the state is unchanged; {@code originatingAction} drives
     * {@code CERTIFICATE_ACTION_PERFORMED} so subscribers see the actual operation.
     */
    private void onAsyncAccepted(Certificate certificate, List<MetadataAttribute> meta, ResourceAction originatingAction) {
        if (meta != null && !meta.isEmpty()) {
            try {
                attributeEngine.updateMetadataAttributes(meta,
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid())
                                .connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid())
                                .build());
            } catch (Exception metaEx) {
                // Metadata persistence failed, but the connector has already accepted the operation
                // asynchronously (HTTP 202): the async operation is real, so the certificate stays in
                // PENDING_ISSUE. Record a FAILED cert-event-history entry so the operator sees the
                // metadata gap — a later cancel may not fully reconstruct the connector's original
                // request (it falls back to whatever the attribute engine can still return).
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

        scheduleStatusPoll(certificate, pollOperationFor(originatingAction));

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(
                        certificate.getUuid(), originatingAction));

        eventLogger.logEvent(
                operationForAction(originatingAction),
                OperationResult.SUCCESS,
                null,
                List.of(new ResourceObjectIdentity(certificate.getSerialNumber(), certificate.getUuid())),
                "Connector accepted asynchronously (HTTP 202); certificate is in PENDING_ISSUE, awaiting poll completion");

        logger.info("Certificate {} accepted asynchronously by connector; parked in PENDING_ISSUE (originating action: {})",
                certificate.getUuid(), originatingAction.getCode());
    }

    /** Rejects a request whose RA profile does not belong to the authority named in the path. The RA profile's
     *  authorityInstanceReferenceUuid is an eager column, so this is safe to call with no transaction held. */
    private static void assertRaProfileUnderAuthority(RaProfile raProfile, SecuredParentUUID authorityUuid) {
        if (!authorityUuid.getValue().equals(raProfile.getAuthorityInstanceReferenceUuid())) {
            throw new ValidationException(String.format(
                    "RA profile %s does not belong to the requested authority.", raProfile.getName()));
        }
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
        complianceService.checkResourceObjectsComplianceValidationAsSystem(Resource.CERTIFICATE, List.of(certificateUuid));
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
        // Idempotent on redelivery / state races: if the certificate can no longer transition to the
        // target state (e.g. a redelivered reject for an already-REJECTED cert — REJECTED->REJECTED
        // has no row), skip rather than letting the SM throw and fail the JMS message. Mirrors the
        // guards on approvalCreatedAction and revokeCertificateRejectedAction.
        if (!stateMachine.canTransition(certificate.getState(), state)) {
            logger.debug("Certificate {} is in state {}; no transition to {} — skipping failed/rejected handling",
                    certificate.getUuid(), certificate.getState().getLabel(), state.getLabel());
            return;
        }
        for (CertificateLocation location : certificate.getLocations()) {
            try {
                locationInternalService.removeRejectedOrFailedCertificateFromLocationAction(location.getId());
            } catch (ConnectorException | NotFoundException ex) {
                logger.error("Failed to remove certificate with UUID {} from location with UUID {}: {}", certificate.getUuid(), location.getId().getLocationUuid(), ex.getMessage(), ex);
            }
        }
        CertificateState oldState = certificate.getState();

        // The SM writes the state-change audit; its status comes from the transition row (FAILED
        // for both the failed-issue and the rejected rows). Preserve the original event, message,
        // and detail: a rejection with no caller message keeps the UPDATE_STATE "state changed"
        // wording with no detail; every other case records an ISSUE event with the failure message
        // and the serialized additional information.
        final CertificateEvent auditEvent;
        final String auditMessage;
        final String auditDetail;
        if (state == CertificateState.REJECTED && message == null) {
            auditEvent = CertificateEvent.UPDATE_STATE;
            auditMessage = "Certificate state changed from %s to %s.".formatted(oldState.getLabel(), CertificateState.REJECTED.getLabel());
            auditDetail = "";
        } else {
            auditEvent = CertificateEvent.ISSUE;
            auditMessage = message;
            auditDetail = additionalInformation != null ? MetaDefinitions.serialize(additionalInformation) : "";
        }
        stateMachine.transition(certificate, state, auditEvent, auditMessage, auditDetail);

        // Fate-coupling: a pre-registered certificate that reached a terminal FAILED/REJECTED verdict no longer has
        // a live registration — close its authorization in the same transaction (guarded, so it is a no-op for
        // non-self-service certs and for renew/rekey successors that carry no authorization).
        if (registrationAuthorizationRepository.existsByCertificateUuid(certificate.getUuid())) {
            registrationAuthorizationWriter.close(certificate.getUuid());
        }

        certificateRelationRepository.deleteAll(certificate.getPredecessorRelations());

        // A failed renew/rekey also records the failure against the predecessor certificate so its
        // history reflects the abandoned operation (the SM call above only audits the new cert).
        if (state == CertificateState.FAILED) {
            if (event == CertificateEvent.RENEW)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
            if (event == CertificateEvent.REKEY)
                certificateEventHistoryService.addEventHistory(oldCertificateUuid, CertificateEvent.REKEY, CertificateEventStatus.FAILED, message, MetaDefinitions.serialize(additionalInformation));
        }
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto issueExistingCertificate(final SecuredParentUUID authorityUuid, final SecuredUUID raProfileUuid, final String certificateUuid, final ClientCertificateIssueRequestDto request) throws NotFoundException {
        // NOT_SUPPORTED so the CSR attach below commits in its own transaction before the ISSUE action is
        // enqueued; otherwise the async consumer could read the placeholder before the CSR is visible and fail it.
        RaProfile raProfile = raProfileRepository.findByUuid(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        if (Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new ValidationException("Cannot issue certificate with disabled RA profile. Ra Profile: %s".formatted(raProfile.getName()));
        }
        assertRaProfileUnderAuthority(raProfile, authorityUuid);
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));
        if (!raProfileUuid.getValue().equals(certificate.getRaProfileUuid())) {
            throw new ValidationException("Cannot issue a certificate that belongs to a different RA profile. Certificate: %s".formatted(certificate.toStringShort()));
        }
        CertificateState state = certificate.getState();
        boolean hasCsr = request != null && request.getRequest() != null && !request.getRequest().isBlank();

        // State-keyed, body-optional contract: a REQUESTED cert already carries its (protocol-attached) CSR
        // and must not be given another; a REGISTERED placeholder has no CSR yet and requires the operator's.
        if (state != CertificateState.REGISTERED && state != CertificateState.REQUESTED) {
            throw new ValidationException(ValidationError.create("Cannot issue certificate with state %s. Certificate: %s".formatted(state.getLabel(), certificate.toStringShort())));
        }
        boolean registered = state == CertificateState.REGISTERED;
        if (registered && !hasCsr) {
            throw new ValidationException(ValidationError.create("A certificate signing request is required to issue a registered certificate. Certificate: %s".formatted(certificate.toStringShort())));
        }
        if (!registered && hasCsr) {
            throw new ValidationException(ValidationError.create("This certificate already has a signing request and cannot accept another. Certificate: %s".formatted(certificate.toStringShort())));
        }

        // Self-service gate: verify the operator challenge before the CSR attach and the async enqueue, so a bad
        // challenge rejects the caller synchronously and the secret never rides the ActionMessage. No-op when the
        // certificate carries no registration authorization.
        verifyRegistrationChallenge(certificate.getUuid(),
                request != null ? request.getAuthorizationSecret() : null);

        if (registered) {
            try {
                certificateService.addCertificateRequestToExisting(certificate.getUuid(), request);
            } catch (CertificateRequestException | NoSuchAlgorithmException e) {
                throw new ValidationException(ValidationError.create("Invalid certificate signing request: " + e.getMessage()));
            }
        }

        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.RA_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(raProfileUuid.getValue());
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.CERTIFICATE);
        actionMessage.setResourceAction(ResourceAction.ISSUE);
        actionMessage.setResourceUuid(certificate.getUuid());
        actionProducer.produceMessage(actionMessage);

        final ClientCertificateDataResponseDto response = new ClientCertificateDataResponseDto();
        response.setCertificateData("");
        response.setUuid(certificateUuid);
        return response;
    }

    @Override
    @Transactional
    public void issueCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException {
        // Transactional so the reject transition and the fate-coupling auto-CLOSE (or the approval-reject
        // restore) commit atomically — this entry point (invoked by ActionsListener) has no ambient transaction
        // of its own, unlike the failClaimedCertificate / poll-listener FAILED paths. The pessimistic lock
        // satisfies the state-machine contract: re-assert state under SELECT ... FOR UPDATE before transitioning,
        // so a concurrent issuance claim cannot be clobbered by a stale read.
        final Certificate certificate = certificateRepository.findAndLockWithAssociationsByUuid(certificateUuid)
                .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        // A pre-registered placeholder whose issuance approval was rejected is restored to REGISTERED so the holder
        // can retry, rather than terminally rejected. Every pre-registration — connector-backed or platform-level —
        // carries a register->issue binding, so that is the marker; any challenge authorization stays ACTIVE.
        // Non-registered certs (no binding) keep the terminal REJECTED behaviour.
        if (certificate.getState() == CertificateState.PENDING_APPROVAL
                && certificateRegistrationRepository.findByCertificateUuid(certificateUuid).isPresent()) {
            stateMachine.transition(certificate, CertificateState.REGISTERED, CertificateEvent.APPROVAL_CLOSE,
                    "Issuance approval was rejected; certificate restored to " + CertificateState.REGISTERED.getLabel() + ".");
            return;
        }
        handleFailedOrRejectedEvent(certificate, null, CertificateState.REJECTED, null, null, null);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public ClientCertificateDataResponseDto renewCertificate(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, String certificateUuid, ClientCertificateRenewRequestDto request) throws NotFoundException, CertificateOperationException, CertificateRequestException {
        Certificate oldCertificate = validateOldCertificateForOperation(certificateUuid, raProfileUuid.toString(), ResourceAction.RENEW);

        // Fail-closed: renew is not challenge-gated yet, so refuse to renew a certificate whose registration is
        // still ACTIVE rather than let a secretless renew silently exit the challenge regime.
        rejectRenewOrRekeyOfActiveRegistration(oldCertificate.getUuid());

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
        } catch (RequestAttributePolicyViolationException e) {
            transactionManager.rollback(status);
            // a client-facing validation failure
            throw e;
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

        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("New Certificate UUID", certificate.getUuid());
        boolean connectorAccepted = false;
        try {
            // Move the new certificate to PENDING_ISSUE before calling the connector so every path
            // (sync 200 or async 202) reaches issueRequestedCertificate / the poll cycle from a
            // uniform PENDING_ISSUE state via the state machine.
            stateMachine.transition(certificate, CertificateState.PENDING_ISSUE, CertificateEvent.ISSUE,
                    "Issuance in progress");

            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult renewResult = adapter.renew(oldCertificate, certificate, request);
            connectorAccepted = true;

            if (renewResult.isAsync()) {
                // The connector accepted the renewal but completion is asynchronous; the new
                // certificate stays in PENDING_ISSUE while the predecessor remains ISSUED.
                onAsyncAccepted(certificate, renewResult, ResourceAction.RENEW);
                certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW,
                        CertificateEventStatus.SUCCESS, "Renewal accepted; awaiting asynchronous completion.",
                        MetaDefinitions.serialize(additionalInformation));
                return;
            }

            if (StringUtils.isBlank(renewResult.certificateData())) {
                throw new CertificateOperationException("Response from authority did not contain certificate data");
            }

            logger.info("Certificate {} was renewed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(certificateUuid, renewResult.certificateData(), renewResult.meta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW, CertificateEventStatus.SUCCESS, "Renewed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation));
        } catch (Exception e) {
            // Once the connector has accepted (2xx) — whether reported as a returned result or surfaced as a
            // ConnectorAcceptedButLocalFailureException from the adapter's own response mapping — a subsequent
            // local failure (mapping, persistence, event history) must NOT drive the successor to FAILED. Leave it
            // in PENDING_ISSUE so reconciliation/polling can resolve it against the authority that already accepted;
            // record the failure against the predecessor and surface it. (state-divergence rule)
            if (connectorAccepted || e instanceof ConnectorAcceptedButLocalFailureException) {
                certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.RENEW, CertificateEventStatus.FAILED, "Connector accepted renewal but local update failed: " + e.getMessage(), MetaDefinitions.serialize(additionalInformation));
                throw new CertificateOperationException("Connector accepted renewal but local update failed for certificate %s: ".formatted(certificateUuid) + e.getMessage());
            }
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
                    locationInternalService.pushRequestedCertificateToLocationAction(cl.getId(), true);
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

        // Fail-closed: rekey is not challenge-gated yet (its verification and successor copy come later), so
        // refuse to rekey a certificate whose registration is still ACTIVE.
        rejectRenewOrRekeyOfActiveRegistration(oldCertificate.getUuid());

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
        } catch (RequestAttributePolicyViolationException e) {
            transactionManager.rollback(status);
            // a client-facing validation failure
            throw e;
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
                null,
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
        boolean connectorAccepted = false;
        try {
            // Move the new certificate to PENDING_ISSUE before calling the connector so every path
            // (sync 200 or async 202) reaches issueRequestedCertificate / the poll cycle from a
            // uniform PENDING_ISSUE state via the state machine.
            stateMachine.transition(certificate, CertificateState.PENDING_ISSUE, CertificateEvent.ISSUE,
                    "Issuance in progress");

            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult rekeyResult = adapter.renew(oldCertificate, certificate, null);
            connectorAccepted = true;

            if (rekeyResult.isAsync()) {
                // The connector accepted the rekey but completion is asynchronous; the new
                // certificate stays in PENDING_ISSUE while the predecessor remains ISSUED.
                onAsyncAccepted(certificate, rekeyResult, ResourceAction.REKEY);
                certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY,
                        CertificateEventStatus.SUCCESS, "Rekey accepted; awaiting asynchronous completion.",
                        MetaDefinitions.serialize(additionalInformation));
                return;
            }

            if (StringUtils.isBlank(rekeyResult.certificateData())) {
                throw new CertificateOperationException("Response from authority did not contain certificate data");
            }

            logger.info("Certificate {} was rekeyed by authority", certificateUuid);

            CertificateDetailDto certificateDetailDto = certificateService.issueRequestedCertificate(certificateUuid, rekeyResult.certificateData(), rekeyResult.meta());

            additionalInformation.put("New Certificate Serial Number", certificateDetailDto.getSerialNumber());
            certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY, CertificateEventStatus.SUCCESS, "Rekeyed using RA Profile " + raProfile.getName(), MetaDefinitions.serialize(additionalInformation));
        } catch (Exception e) {
            // Once the connector has accepted (2xx) — whether reported as a returned result or surfaced as a
            // ConnectorAcceptedButLocalFailureException from the adapter's own response mapping — a subsequent
            // local failure (mapping, persistence, event history) must NOT drive the successor to FAILED. Leave it
            // in PENDING_ISSUE so reconciliation/polling can resolve it against the authority that already accepted;
            // record the failure against the predecessor and surface it. (state-divergence rule)
            if (connectorAccepted || e instanceof ConnectorAcceptedButLocalFailureException) {
                certificateEventHistoryService.addEventHistory(oldCertificate.getUuid(), CertificateEvent.REKEY, CertificateEventStatus.FAILED, "Connector accepted rekey but local update failed: " + e.getMessage(), MetaDefinitions.serialize(additionalInformation));
                throw new CertificateOperationException("Connector accepted rekey but local update failed for certificate %s: ".formatted(certificateUuid) + e.getMessage());
            }
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

        // Once the connector returns a non-error status, the upstream operation is in flight
        // (200 = revoked, 202 = will revoke asynchronously). A failure in any subsequent local
        // step (entity save, attribute persistence, event history) MUST NOT roll back the cert
        // to its entry state — doing so would leave the platform DB out of sync with an authority
        // that has already accepted (or completed) the revocation.
        boolean connectorAccepted = false;
        try {
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
            AdapterOperationResult revokeResult = adapter.revoke(certificate, request);
            connectorAccepted = true;

            if (revokeResult.isAsync()) {
                transitionToPendingRevoke(certificate, request);
                return;
            }

            // Connector revoked synchronously (200). Drive state to REVOKED before the fallible
            // attribute write so a later local failure cannot leave the cert out of sync with an
            // authority that has already revoked it (state-divergence rule). The SM gates the
            // transition but writes no audit here; the REVOKE/SUCCESS history is recorded only after
            // the attribute write succeeds, so an attribute failure surfaces as the single
            // connector-accepted-but-local-failure entry below, not a misleading SUCCESS+FAILED pair.
            stateMachine.transitionAuditedExternally(certificate, CertificateState.REVOKED);

            attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build(), request.getAttributes());
            String reason = request.getReason() == null ? CertificateRevocationReason.UNSPECIFIED.getLabel() : request.getReason().getLabel();
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE, CertificateEventStatus.SUCCESS, "Certificate revoked. Reason: " + reason, "");
        } catch (ConnectorAcceptedButLocalFailureException e) {
            // The adapter reports the connector accepted the revoke (2xx) but its local response mapping failed,
            // so connectorAccepted was never set. Treat it as connector-accepted: do NOT roll the certificate back
            // to its entry state — the upstream is committed — and surface the local failure for reconciliation.
            String msg = "Connector accepted revoke but local state update failed: " + e.getMessage();
            certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE, CertificateEventStatus.FAILED, msg, "");
            logger.error("Local mapping failed after connector accepted revoke for cert {}: {}", certificate.getUuid(), e.getMessage(), e);
            throw new CertificateOperationException(msg);
        } catch (Exception e) {
            if (connectorAccepted) {
                // Connector accepted the operation (200/202) but a subsequent local step failed.
                // Leave the cert state as-is — the upstream is committed and rolling back here
                // would create state divergence between the platform and the authority. Surface
                // the local failure but do not mask the upstream success.
                String msg = "Connector accepted revoke but local state update failed: " + e.getMessage();
                certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.REVOKE,
                        CertificateEventStatus.FAILED, msg, "");
                logger.error("Local state update failed after connector accepted revoke for cert {}: {}",
                        certificate.getUuid(), e.getMessage(), e);
                throw new CertificateOperationException(msg);
            }
            // Connector itself failed. Nothing transitioned the cert before the connector call, so
            // this restores it to its entry state — a defensive no-op, not a real transition, and so
            // intentionally not routed through the SM (there is no self-transition row, and the SM
            // governs state changes rather than idempotent restores). The FAILED audit below is the
            // meaningful record of the failed revoke attempt.
            certificate.setState(entryState);
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

    @Override
    public void revokeCertificateRejectedAction(final UUID certificateUuid) throws NotFoundException {
        final Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.getState() != CertificateState.PENDING_APPROVAL) {
            logger.debug("Certificate {} is in state {}, not PENDING_APPROVAL; skipping revoke-rejection state restore", certificateUuid, certificate.getState().getLabel());
            return;
        }
        stateMachine.transition(certificate, CertificateState.ISSUED, CertificateEvent.REVOKE,
                "Revocation approval was rejected; certificate restored to " + CertificateState.ISSUED.getLabel() + ".");
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
        stateMachine.transition(certificate, CertificateState.PENDING_REVOKE, CertificateEvent.REVOKE,
                "Revocation accepted; awaiting asynchronous completion.");

        scheduleStatusPoll(certificate, CertificateOperation.REVOKE);

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

    /** Schedules an async status poll, reloading the certificate with the polling entity graph — for callers
     *  whose own load did not fetch the authority's connector interface (issue/renew/rekey/revoke).
     *  @return {@code true} iff a poll was scheduled. */
    private boolean scheduleStatusPoll(Certificate certificate, CertificateOperation operation) {
        return scheduleStatusPoll(certificate, operation, () -> isAsyncPollable(certificate.getUuid()));
    }

    /** Schedules an async status poll using an already-resolved adapter and authority (no reload) — for callers
     *  that loaded the certificate with the polling graph and resolved the adapter already (registration).
     *  @return {@code true} iff a poll was scheduled. */
    private boolean scheduleStatusPoll(Certificate certificate, AuthorityProviderAdapter adapter,
                                       AuthorityInstanceReference authority, CertificateOperation operation) {
        return scheduleStatusPoll(certificate, operation, () -> isAsyncPollable(adapter, authority));
    }

    /**
     * Defense-in-depth gate: schedule a poll only when the authority is v3 (the status endpoint exists —
     * instanceof AsyncOperationCapability) AND advertises CERTIFICATE_STATUS_POLLING ("poll me"). A v2 or
     * non-advertising v3 authority (e.g. an out-of-band / manual-completion connector that 202s then 404s its
     * status endpoint) is left PENDING with no poll row, no queue message and no listener WARN.
     *
     * <p>Best-effort: the connector has already accepted the operation, so neither the gate evaluation nor the
     * scheduling may roll it back (state-divergence rule). Any failure degrades to "no poll".
     *
     * @return {@code true} iff a poll was scheduled.
     */
    private boolean scheduleStatusPoll(Certificate certificate, CertificateOperation operation, BooleanSupplier pollable) {
        try {
            if (!pollable.getAsBoolean()) {
                logger.debug("Authority for certificate {} is not pollable (not v3, or does not advertise "
                        + "CERTIFICATE_STATUS_POLLING); no poll scheduled (left PENDING for manual/out-of-band completion)",
                        certificate.getUuid());
                return false;
            }
            pollWriter.schedule(certificate.getUuid(), operation, OffsetDateTime.now(ZoneOffset.UTC));
            return true;
        } catch (Exception e) {
            logger.warn("Failed to evaluate or schedule async status poll for certificate {} (operation {}): {}",
                    certificate.getUuid(), operation, e.getMessage(), e);
            return false;
        }
    }

    /** Whether the authority should be polled for asynchronous completion: it is v3 (the status endpoint
     *  exists — instanceof AsyncOperationCapability) AND advertises {@code CERTIFICATE_STATUS_POLLING}. */
    private boolean isAsyncPollable(AuthorityProviderAdapter adapter, AuthorityInstanceReference authority) {
        return adapter instanceof AsyncOperationCapability
                && capabilityService.supports(authority, FeatureFlag.CERTIFICATE_STATUS_POLLING);
    }

    /** Reloads with the polling entity graph so the authority's connector interface is initialized in this
     *  tx-less path, resolves the adapter, then applies the gate. */
    private boolean isAsyncPollable(UUID certificateUuid) {
        return certificateRepository.findForPollingByUuid(certificateUuid)
                .map(cert -> {
                    AuthorityInstanceReference authority = cert.getRaProfile().getAuthorityInstanceReference();
                    return isAsyncPollable(adapterFactory.forAuthority(authority), authority);
                })
                .orElse(false);
    }

    private static CertificateOperation pollOperationFor(ResourceAction originatingAction) {
        return originatingAction == ResourceAction.ISSUE ? CertificateOperation.ISSUE : CertificateOperation.RENEW;
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
    public void validateRevokeCertificateAttributes(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue())
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        extendedAttributeService.validateRevokeCertificateAttributes(raProfile, attributes);
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
                UUID keyWithSameFingerprintUuid = keyInternalService.findKeyByFingerprint(fingerprint);
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
     * @param extensions          Extensions
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException When the key or tokenProfile UUID is not found
     */
    private String generateBase64EncodedCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, Extensions extensions, List<RequestAttribute> signatureAttributes, UUID altKeyUUid,
                                            UUID altTokenProfileUuid,
                                            List<RequestAttribute> altSignatureAttributes) throws NotFoundException {
        try {
            // Generate the CSR with the above-mentioned information
            return cryptographicOperationService.generateCsr(
                    keyUuid,
                    tokenProfileUuid,
                    principal,
                    extensions,
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
            String normalizedRequestSubject = X500Name.getInstance(new PlatformX500NameStyle(true), certificateRequest.getSubject().getEncoded()).toString();
            String normalizedCertificateSubject = X500Name.getInstance(new PlatformX500NameStyle(true), certificate.getSubjectX500Principal().getEncoded()).toString();

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

    /**
     * Parse the uploaded CSR into typed content and delegate request-attribute policy validation to the shared
     * {@link ProtocolRequestAttributeValidator}. A policy violation propagates as {@link RequestAttributePolicyViolationException} unchanged.
     */
    private void validateUploadedRequestAttributes(String csr, CertificateRequestFormat requestFormat, RaProfile raProfile)
            throws CertificateException {
        if (raProfile == null) {
            return;
        }
        try {
            CertificateRequest request = CertificateRequestUtils.createCertificateRequest(csr, requestFormat);
            protocolRequestAttributeValidator.validate(request, raProfile);
        } catch (CertificateRequestException | IllegalArgumentException e) {
            logger.debug("Failed to parse uploaded CSR for request-attribute validation", e);
            throw new CertificateException("Uploaded certificate request could not be parsed for validation", e);
        }
    }

    private String generateBase64EncodedCsr(String uploadedRequest, CertificateRequestFormat requestFormat, List<RequestAttribute> csrAttributes, UUID keyUUid, UUID tokenProfileUuid, List<RequestAttribute> signatureAttributes,
                                            UUID altKeyUUid, UUID altTokenProfileUuid, List<RequestAttribute> altSignatureAttributes, RaProfile raProfile) throws NotFoundException, CertificateException, AttributeException, ConnectorException {
        String requestB64;
        String csr;
        if (uploadedRequest != null && !uploadedRequest.isEmpty()) {
            csr = uploadedRequest;
            validateUploadedRequestAttributes(csr, requestFormat, raProfile);
        } else {
            // TODO: support for the CRMF should be handled also in case it should be generated
            if (requestFormat == CertificateRequestFormat.CRMF) {
                throw new CertificateException("CRMF format is not supported for CSR generation");
            }
            // The platform-built (key generation) path needs an RA profile to resolve issuance attributes.
            if (raProfile == null) {
                throw new ValidationException("Cannot generate certificate request without specifying RA profile");
            }
            List<DataAttributeV3> definitions = issuanceDefinitionResolver.resolve(raProfile);

            // validate and update definitions of certificate request attributes with the attribute engine
            attributeEngine.validateUpdateDataAttributes(null, null, definitions, csrAttributes);

            X509RequestContent requestContent = CertificateRequestAttributeProjector.project(definitions, csrAttributes);
            Extensions extensions;
            try {
                extensions = X509RequestContentRenderer.toExtensions(requestContent);
            } catch (IOException e) {
                logger.error("Failed to build CSR extensions for RA profile {}", raProfile.getName(), e);
                throw new CertificateException("Failed to build CSR extensions", e);
            }

            X500Principal principal;
            try {
                 principal = X509RequestContentRenderer.toX500Principal(requestContent);
            } catch (IOException e) {
                logger.error("Failed to build CSR subject for RA profile {}", raProfile.getName(), e);
                throw new CertificateException("Failed to build CSR subject", e);
            }

            csr = generateBase64EncodedCsr(
                    keyUUid,
                    tokenProfileUuid,
                    principal,
                    extensions,
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

        List<MetadataAttribute> identifyMeta = identifyUploadedCertificateOrReject(certificate, request);

        // The PENDING_ISSUE -> ISSUED finalize runs in a short transaction under a pessimistic row lock
        // so two concurrent uploads of the same certificate cannot both finalize it. The connector
        // identify above ran before this lock; the location pushes and best-effort async cancel below run
        // after it commits — the lock is never held across a connector call. PENDING_ISSUE is re-asserted
        // under the lock: the losing upload blocks here, re-reads ISSUED, and is rejected rather than
        // driving a second finalize (duplicate location pushes / events). Mirrors issueCertificateAction /
        // manuallyConfirmRevoke.
        UUID certUuid = certificate.getUuid();
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(certUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certUuid));
            assertCertificateInPendingIssueWithCsr(locked);
            certificateService.issueRequestedCertificate(certUuid, request.getCertificate(), identifyMeta);
            transactionManager.commit(tx);
        } catch (NoSuchAlgorithmException e) {
            transactionManager.rollback(tx);
            throw new CertificateException(e);
        } catch (NotFoundException | CertificateException | AlreadyExistException | AttributeException | RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }

        if (request.getCustomAttributes() != null && !request.getCustomAttributes().isEmpty()) {
            attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE,
                    certUuid, request.getCustomAttributes());
        }

        pushFinalizedCertificateToAllLocations(certificate);

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(certUuid, ResourceAction.ISSUE));

        cancelInFlightAsyncIssueBestEffort(certUuid);

        Certificate refreshed = certificateRepository.findByUuid(certUuid)
                .orElseThrow(() -> new NotFoundException(Certificate.class, certUuid));
        return refreshed.mapToDto();
    }

    /**
     * Operator finalized issuance out-of-band; if a v3 connector still has an in-flight asynchronous issue
     * for this certificate, best-effort tell it to cancel so the upstream operation is not left orphaned.
     * Reloads with the full adapter graph (the manual-issue finder omits the authority interface) and runs
     * with no transaction held. Failures are swallowed — the certificate is already issued locally.
     */
    private void cancelInFlightAsyncIssueBestEffort(UUID certificateUuid) {
        try {
            Certificate certificate = certificateRepository.findForPollingByUuid(certificateUuid).orElse(null);
            if (certificate == null) {
                return;
            }
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(certificate.getRaProfile().getAuthorityInstanceReference());
            if (adapter instanceof AsyncOperationCapability async) {
                async.cancel(certificate, CertificateOperation.ISSUE);
            }
        } catch (Exception e) {
            logger.warn("Best-effort cancel of in-flight async issue after manual issue failed (cert {}): {}", certificateUuid, e.getMessage(), e);
        }
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
     * by the configured authority — call identify (version-dispatched via the authority
     * adapter) and surface only the user-input failure mode (422 → {@link ValidationException}).
     * Connector infrastructure failures (5xx, auth, network) propagate so the client sees the
     * appropriate upstream error and can retry; the certificate stays in {@code PENDING_ISSUE}
     * for the next attempt. Returns the connector's identification meta, never {@code null}.
     */
    private List<MetadataAttribute> identifyUploadedCertificateOrReject(
            Certificate certificate, UploadCertificateRequestDto request) throws ConnectorException, NotFoundException {
        // The caller's finder omits the authority's connectorInterface (lazy) and the caller
        // holds no session — reload with the full adapter graph for adapter dispatch.
        Certificate certForAdapter = certificateRepository.findForPollingByUuid(certificate.getUuid())
                .orElseThrow(() -> new NotFoundException(Certificate.class, certificate.getUuid()));
        RaProfile raProfile = certForAdapter.getRaProfile();
        try {
            return adapterFactory.forAuthority(raProfile.getAuthorityInstanceReference())
                    .identify(raProfile, request.getCertificate());
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
                locationInternalService.pushRequestedCertificateToLocationAction(cl.getId(), false);
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
        boolean destroyKey;
        UUID keyUuid;
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate cert = certificateRepository.findAndLockWithAssociationsByUuid(certUuid)
                    .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
            assertCertificateBelongsToRaProfile(cert, authorityUuid, raProfileUuid, "confirm revocation");
            if (cert.getState() != CertificateState.PENDING_REVOKE) {
                throw new ValidationException("Cannot confirm revocation: certificate is not in PENDING_REVOKE. Current state: %s. Certificate: %s"
                        .formatted(cert.getState().getLabel(), cert.toStringShort()));
            }

            applyPreservedRevokeAttributes(cert);

            destroyKey = Boolean.TRUE.equals(cert.getPendingRevokeDestroyKey());
            keyUuid = cert.getKey() != null ? cert.getKeyUuid() : null;
            cert.setPendingRevokeDestroyKey(null);
            cert.setPendingRevokeAttributes(null);
            stateMachine.transition(cert, CertificateState.REVOKED, CertificateEvent.REVOKE,
                    "Revocation confirmed manually");
            transactionManager.commit(tx);
        } catch (NotFoundException | RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }

        // Slow connector calls outside the lock — failures here are logged but do not
        // affect the already-committed state transition.
        if (destroyKey && keyUuid != null) {
            destroyKeyBestEffort(certUuid, keyUuid);
        }
        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(certUuid, ResourceAction.REVOKE));
        logger.info("Certificate {} revocation confirmed manually", certUuid);
    }

    /**
     * Re-apply the revoke-attributes captured when the cert entered PENDING_REVOKE so the
     * cert detail reflects the revocation parameters. Best-effort: a failure here does not
     * block the state transition (the connector revoke already succeeded upstream).
     */
    private void applyPreservedRevokeAttributes(Certificate cert) throws NotFoundException {
        if (cert.getPendingRevokeAttributes() == null || cert.getPendingRevokeAttributes().isEmpty()) {
            return;
        }
        RaProfile raProfile = cert.getRaProfile();
        try {
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                            .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid())
                            .operation(AttributeOperation.CERTIFICATE_REVOKE).build(),
                    cert.getPendingRevokeAttributes());
        } catch (AttributeException e) {
            logger.warn("Failed to apply preserved revoke attributes on manual revoke confirm for cert {}: {}",
                    cert.getUuid(), e.getMessage(), e);
        }
    }

    private void destroyKeyBestEffort(UUID certUuid, UUID keyUuid) {
        try {
            logger.debug("Manual revoke confirm: destroying key for cert {}", certUuid);
            keyService.destroyKey(List.of(keyUuid.toString()));
        } catch (Exception e) {
            logger.warn("Failed to destroy certificate key on manual revoke confirm for cert {}: {}",
                    certUuid, e.getMessage(), e);
        }
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
        CertificateDetailDto result = commitLocalCancel(cert, target, reason);

        eventProducer.produceMessage(
                CertificateActionPerformedEventHandler.constructEventMessage(cert.getUuid(), ResourceAction.UPDATE));
        logger.info("Pending {} for certificate {} cancelled (target state: {})",
                target.pendingOpLabel(), cert.getUuid(), target.targetState());

        return result;
    }

    /**
     * Carries the per-state choices for {@link #cancelPendingCertificateOperation}: which
     * connector cancel endpoint to call, what local target state to transition the
     * certificate to, which {@link CertificateEvent} kind to record, and the human-readable
     * label for log/event messages. {@code pendingOpLabel} is the single source of truth
     * for "issuance" / "revocation" — kept consistent across all log lines and event-log
     * descriptions.
     */
    private record CancelTarget(boolean isCancelIssue, CertificateState targetState,
                                CertificateEvent eventKind, String pendingOpLabel) {}

    private CancelTarget determineCancelTarget(Certificate cert) {
        if (cert.getState() == CertificateState.PENDING_ISSUE) {
            certificateService.checkIssuePermissions();
            return new CancelTarget(true, CertificateState.FAILED, CertificateEvent.ISSUE, "issuance");
        }
        if (cert.getState() == CertificateState.PENDING_REVOKE) {
            certificateService.checkRevokePermissions();
            return new CancelTarget(false, CertificateState.ISSUED, CertificateEvent.REVOKE, "revocation");
        }
        throw new ValidationException("Cannot cancel: certificate is not in a pending state. Current state: %s. Certificate: %s"
                .formatted(cert.getState().getLabel(), cert.toStringShort()));
    }

    /**
     * Connector cancel dispatch: resolves the authority's adapter and, when it exposes
     * {@link AsyncOperationCapability} (v3), uses the outcome-mapped {@code cancel} operation —
     * {@code CANCELLED} proceeds, {@code NOT_TRACKED} is a soft failure (proceed locally),
     * {@code REFUSED_PAST_POINT_OF_NO_RETURN} is a hard refusal. Adapters without the
     * capability (v2) call the dedicated v2 cancel endpoints directly.
     *
     * <p>Shared error contract (both paths):
     * <ul>
     *   <li>Cancelled upstream (v2 {@code 204}, v3 {@code CANCELLED}) — proceed with local transition.</li>
     *   <li>Operation not tracked (v2 {@code 404}, v3 {@code NOT_TRACKED}) — soft failure,
     *       proceed locally.</li>
     *   <li>Refusal (v2 {@code 422}, v3 {@code REFUSED_PAST_POINT_OF_NO_RETURN}) →
     *       {@link ValidationException} — HARD refusal, surface the upstream reason and abort
     *       the local cancel (cert stays in PENDING_*).</li>
     *   <li>{@code 5xx} / network / timeout — infrastructure error, soft failure, proceed
     *       locally (the connector may recover and we can reconcile via status).</li>
     *   <li>Other {@code 4xx} (400, 401, 403) → {@link ConnectorClientException} — request
     *       was wrong or unauthorised. NOT a soft failure: silently transitioning the cert
     *       state would be incorrect because the connector never cancelled the upstream
     *       operation.</li>
     *   <li>Any other {@link ConnectorException} subtype — defensive soft failure path so
     *       a future {@code ConnectorXxxException} doesn't crash the cancel flow.</li>
     * </ul>
     *
     * <p>Throws {@link ValidationException} on hard refusal (422 or other 4xx). Returns
     * normally on every soft-failure path so the caller can proceed with the local
     * transition.</p>
     */
    private void invokeConnectorCancelOrThrow(Certificate cert, CancelTarget target) throws NotFoundException {
        RaProfile raProfile = cert.getRaProfile();
        try {
            // The caller's finder omits the authority's connectorInterface (lazy) and this method
            // holds no session — reload with the full adapter graph for adapter dispatch,
            // mirroring cancelInFlightAsyncIssueBestEffort.
            Certificate certForAdapter = certificateRepository.findForPollingByUuid(cert.getUuid())
                    .orElseThrow(() -> new NotFoundException(Certificate.class, cert.getUuid()));
            AuthorityProviderAdapter adapter = adapterFactory.forAuthority(certForAdapter.getRaProfile().getAuthorityInstanceReference());
            if (adapter instanceof AsyncOperationCapability asyncCapable) {
                CancelOutcome outcome = asyncCapable.cancel(certForAdapter,
                        target.isCancelIssue() ? CertificateOperation.ISSUE : CertificateOperation.REVOKE).outcome();
                if (outcome == CancelOutcome.REFUSED_PAST_POINT_OF_NO_RETURN) {
                    // Routed through the ValidationException handler below — same hard-refusal
                    // recording and rethrow as a v2 connector 422.
                    throw new ValidationException("operation is past the point of no return");
                }
                if (outcome == CancelOutcome.NOT_TRACKED) {
                    recordCancelSoftFailure(cert, target,
                            "Connector does not track this operation; proceeding with local cancel",
                            "Connector did not track the operation; proceeded with local cancel",
                            "Connector cancel reported operation not tracked for cert {} — proceeding with local cancel ({})",
                            "adapter outcome NOT_TRACKED", null);
                }
            } else {
                ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
                CertificateOperationCancelRequestDto cancelReq = assembleCancelRequest(cert, raProfile);
                if (target.isCancelIssue()) {
                    connectorApiFactory.getCertificateApiClientV2(connectorDto).cancelIssueCertificate(connectorDto,
                            raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), cancelReq);
                } else {
                    connectorApiFactory.getCertificateApiClientV2(connectorDto).cancelRevokeCertificate(connectorDto,
                            raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), cancelReq);
                }
            }
        } catch (ValidationException upstreamRefused) {
            recordCancelFailure(cert, target,
                    "Cancel rejected by authority: " + upstreamRefused.getMessage(),
                    "Authority refused to cancel pending " + target.pendingOpLabel() + ": " + upstreamRefused.getMessage(),
                    upstreamRefused);
            throw new ValidationException("Authority refused to cancel the operation: " + upstreamRefused.getMessage());
        } catch (ConnectorEntityNotFoundException notTracked) {
            recordCancelSoftFailure(cert, target,
                    "Connector did not track this operation (404); proceeding with local cancel: " + notTracked.getMessage(),
                    "Connector did not track the operation (404); proceeded with local cancel",
                    "Connector cancel returned 404 for cert {} — proceeding with local cancel: {}", notTracked.getMessage(), notTracked);
        } catch (ConnectorClientException badRequest) {
            int status = badRequest.getHttpStatus().value();
            recordCancelFailure(cert, target,
                    "Connector cancel rejected by " + status + ": " + badRequest.getMessage(),
                    "Connector cancel rejected with HTTP " + status + "; certificate stays in " + cert.getState(),
                    badRequest);
            throw new ValidationException("Connector cancel rejected (" + status + "): " + badRequest.getMessage());
        } catch (ConnectorServerException | ConnectorCommunicationException infra) {
            recordCancelSoftFailure(cert, target,
                    "Connector cancel call failed with infrastructure error (proceeding with local cancel): " + infra.getMessage(),
                    "Connector cancel call failed (" + infra.getClass().getSimpleName() + "); proceeded with local cancel",
                    "Connector cancel call failed for cert {} ({}: {}) — proceeding with local cancel",
                    infra.getClass().getSimpleName() + ": " + infra.getMessage(), infra);
        } catch (NotFoundException entityMissing) {
            // A local lookup failed — either the certificate vanished on the adapter-graph reload, or the
            // connector record is missing (getConnectorForApiClient). Both are local/configuration problems,
            // not connector responses, so propagate unchanged instead of softening into a local cancel.
            throw entityMissing;
        } catch (Exception unexpected) {
            // Defensive catch-all. Covers any ConnectorException subtype not handled above
            // (e.g. ConnectorProblemException or future additions) plus any unchecked
            // exception leaking from the connector client / API layer. We intentionally widen
            // to Exception rather than ConnectorException so a NPE / IllegalState from the
            // client stack does not silently propagate as an HTTP 500 to the caller —
            // cancel is a local-state operation and a connector hiccup should not strand
            // the cert in PENDING_*.
            recordCancelSoftFailure(cert, target,
                    "Connector cancel call failed (proceeding with local cancel): " + unexpected.getMessage(),
                    "Connector cancel call failed (" + unexpected.getClass().getSimpleName() + "); proceeded with local cancel",
                    "Connector cancel call failed for cert {} ({}: {}) — proceeding with local cancel",
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
    private CertificateDetailDto commitLocalCancel(Certificate cert, CancelTarget target, String reason) {
        TransactionStatus cleanupTx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            // Re-read the cert under the new transaction. The method runs as
            // @Transactional(NOT_SUPPORTED) and the connector cancel call between the initial
            // read at the top of cancelPendingCertificateOperation and this point holds no
            // database lock — a concurrent operator action (e.g. manuallyConfirmRevoke
            // committing REVOKED, manuallyIssueCertificate committing ISSUED) could have
            // transitioned the cert in the meantime. Without this re-read + state assertion
            // we would blindly overwrite a valid concurrent transition with the cancel's
            // target state, producing a state divergence between the platform and the
            // operator's intent. The expected pre-cancel state is recorded on the
            // CancelTarget (PENDING_ISSUE for cancel-issue, PENDING_REVOKE for cancel-revoke).
            CertificateState expectedPendingState = target.isCancelIssue()
                    ? CertificateState.PENDING_ISSUE
                    : CertificateState.PENDING_REVOKE;
            // findAndLockWithAssociationsByUuid issues SELECT ... FOR UPDATE inside this
            // transaction. A concurrent manuallyConfirmRevoke / manuallyIssueCertificate
            // attempting to update the same row blocks until this transaction commits or
            // rolls back, so the state assertion below cannot be defeated by an interleaving
            // commit between our reload and our save.
            Certificate fresh = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                    .orElseThrow(() -> new ValidationException(
                            "Certificate disappeared during cancel: " + cert.getUuid()));
            if (fresh.getState() != expectedPendingState) {
                throw new ValidationException(
                        "Cancel raced with another operation: certificate " + cert.getUuid()
                                + " is in state " + fresh.getState() + " (expected " + expectedPendingState
                                + "); refusing to overwrite. The connector cancel call may have completed"
                                + " upstream — verify and reconcile manually if needed.");
            }
            if (target.isCancelIssue()) {
                certificateRelationRepository.deleteAll(fresh.getPredecessorRelations());
                fresh.getPredecessorRelations().clear();
            } else {
                fresh.setPendingRevokeDestroyKey(null);
                fresh.setPendingRevokeAttributes(null);
            }
            // Cancelling a pending operation is a non-success outcome. Routing through the SM records
            // the audit with the transition row's status — FAILED for both PENDING_ISSUE→FAILED and
            // the PENDING_REVOKE→ISSUED restore — so a cancelled issue is no longer logged SUCCESS.
            String label = target.isCancelIssue() ? "Pending issue cancelled" : "Pending revocation cancelled";
            String auditMessage = reason.isEmpty() ? label : (label + ". Reason: " + reason);
            stateMachine.transition(fresh, target.targetState(), target.eventKind(), auditMessage);
            // Build the response DTO while the session is open so it reflects the committed
            // post-cancel state (the locked `fresh`, not the stale pre-cancel `cert`) and its lazy
            // associations resolve here rather than after the session closes.
            CertificateDetailDto dto = fresh.mapToDto();
            transactionManager.commit(cleanupTx);
            return dto;
        } catch (RuntimeException e) {
            transactionManager.rollback(cleanupTx);
            throw e;
        }
    }
}
