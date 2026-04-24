package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.client.dashboard.StatisticsDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.czertainly.api.model.connector.v2.CertificateIdentificationRequestDto;
import com.czertainly.api.model.connector.v2.CertificateIdentificationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.certificate.group.GroupDto;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.oid.OidCategory;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.settings.CertificateValidationSettingsDto;
import com.czertainly.api.model.core.settings.PlatformSettingsDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.core.attribute.CsrAttributes;
import com.czertainly.core.attribute.engine.AttributeContentPurpose;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.acme.AcmeAccountRepository;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.handlers.CertificateExpiringEventHandler;
import com.czertainly.core.events.handlers.CertificateStatusChangedEventHandler;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.events.transaction.UpdateCertificateHistoryEvent;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.messaging.jms.producers.ValidationProducer;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.model.ValidationMessage;
import com.czertainly.core.model.auth.CertificateProtocolInfo;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.request.CertificateRequest;
import com.czertainly.core.oid.OidHandler;
import com.czertainly.core.oid.OidRecord;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.*;
import com.czertainly.core.validation.certificate.ICertificateValidator;
import jakarta.persistence.criteria.*;
import org.apache.commons.lang3.function.TriFunction;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

@Service(Resource.Codes.CERTIFICATE)
@Transactional
public class CertificateServiceImpl implements CertificateService, AttributeResourceService {

    // batch size will prevent bloating size of enqueued message and better utilize parallel processing
    // NOTE: improve handling of large batches vs many produced messages to queue
    private static final int VALIDATION_BATCH_SIZE = 10;
    private static final String UNDEFINED_CERTIFICATE_OBJECT_NAME = "undefined";
    private static final Logger logger = LoggerFactory.getLogger(CertificateServiceImpl.class);

    @Value("${spring.jpa.properties.hibernate.jdbc.batch_size:500}")
    private int bulkDeleteBatchSize;

    @Value("${certificate.chain.max-depth:20}")
    private int certificateChainMaxDepth;

    private PlatformTransactionManager transactionManager;

    private CertificateRepository certificateRepository;
    private CertificateRequestRepository certificateRequestRepository;
    private RaProfileRepository raProfileRepository;
    private RaProfileService raProfileService;
    private GroupRepository groupRepository;
    private GroupAssociationRepository groupAssociationRepository;
    private LocationRepository locationRepository;
    private CertificateContentRepository certificateContentRepository;
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    private ComplianceService complianceService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private LocationService locationService;
    private CryptographicKeyService cryptographicKeyService;
    private PermissionEvaluator permissionEvaluator;
    private EventProducer eventProducer;
    private NotificationProducer notificationProducer;
    private ConnectorApiFactory connectorApiFactory;
    private UserManagementApiClient userManagementApiClient;
    private CrlService crlService;
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;
    private CertificateRelationRepository certificateRelationRepository;
    private AcmeProfileRepository acmeProfileRepository;
    private ScepProfileRepository scepProfileRepository;
    private CmpProfileRepository cmpProfileRepository;
    private AcmeAccountRepository acmeAccountRepository;

    private AttributeEngine attributeEngine;
    private ExtendedAttributeService extendedAttributeService;
    private ResourceObjectAssociationService objectAssociationService;
    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;
    private ApplicationEventPublisher applicationEventPublisher;
    private ValidationProducer validationProducer;

    /**
     * A map that contains ICertificateValidator implementations mapped to their corresponding certificate type code
     */
    private Map<String, ICertificateValidator> certificateValidatorMap;

    @Autowired
    public void setValidationProducer(ValidationProducer validationProducer) {
        this.validationProducer = validationProducer;
    }

    @Autowired
    public void setAcmeAccountRepository(AcmeAccountRepository acmeAccountRepository) {
        this.acmeAccountRepository = acmeAccountRepository;
    }

    @Autowired
    public void setGroupAssociationRepository(GroupAssociationRepository groupAssociationRepository) {
        this.groupAssociationRepository = groupAssociationRepository;
    }

    @Autowired
    public void setCmpProfileRepository(CmpProfileRepository cmpProfileRepository) {
        this.cmpProfileRepository = cmpProfileRepository;
    }

    @Autowired
    public void setScepProfileRepository(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setAcmeProfileRepository(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Autowired
    public void setCertificateRelationRepository(CertificateRelationRepository certificateRelationRepository) {
        this.certificateRelationRepository = certificateRelationRepository;
    }

    @Autowired
    public void setProtocolCertificateAssociationsRepository(ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository) {
        this.protocolCertificateAssociationsRepository = protocolCertificateAssociationsRepository;
    }

    @Lazy
    @Autowired
    public void setLocationService(LocationService locationService) {
        this.locationService = locationService;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCertificateRequestRepository(CertificateRequestRepository certificateRequestRepository) {
        this.certificateRequestRepository = certificateRequestRepository;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setLocationRepository(LocationRepository locationRepository) {
        this.locationRepository = locationRepository;
    }

    @Autowired
    public void setCertificateContentRepository(CertificateContentRepository certificateContentRepository) {
        this.certificateContentRepository = certificateContentRepository;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Autowired
    public void setComplianceService(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Lazy
    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setCertificateProtocolAssociationRepository(CertificateProtocolAssociationRepository certificateProtocolAssociationRepository) {
        this.certificateProtocolAssociationRepository = certificateProtocolAssociationRepository;
    }

    @Autowired
    public void setCrlService(CrlService crlService) {
        this.crlService = crlService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setCertificateValidatorMap(Map<String, ICertificateValidator> certificateValidatorMap) {
        this.certificateValidatorMap = certificateValidatorMap;
    }

    @Autowired
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.MEMBERS)
    public CertificateResponseDto listCertificates(SecurityFilter filter, CertificateSearchRequestDto request) {
        setupSecurityFilter(filter);
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = getAdditionalWhereClause(request.getFilters(), request.isIncludeArchived());
        List<UUID> certificateUuids = certificateRepository.findUuidsUsingSecurityFilter(filter, additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")));

        // We use DTO projection instead of Hibernate entities for performance reasons.
        List<CertificateDto> certificates;
        if (certificateUuids.isEmpty()) {
            certificates = Collections.emptyList();
        } else {
            certificates = certificateRepository.findCertificateDtosByUuidsIn(certificateUuids);
            List<GroupAssociation> groupAssociations = groupAssociationRepository.findWithAssociationsByResourceAndObjectUuidIn(Resource.CERTIFICATE, certificateUuids);
            Map<String, List<GroupDto>> groupsByCert = groupAssociations.stream().collect(Collectors.groupingBy(ga -> ga.getObjectUuid().toString(),
                    Collectors.mapping(ga -> ga.getGroup().mapToDto(), Collectors.toList())));
            certificates.forEach(c -> {
                c.setCommonName(CertificateUtil.formatCommonName(c.getCommonName()));
                c.setGroups(groupsByCert.getOrDefault(c.getUuid(), List.of()));
            });
        }

        Long maxItems = certificateRepository.countUsingSecurityFilter(filter, additionalWhereClause);
        CertificateResponseDto responseDto = new CertificateResponseDto();
        responseDto.setCertificates(certificates);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));

        return responseDto;
    }

    private static TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> getAdditionalWhereClause(List<SearchFilterRequestDto> filters, boolean includeArchived) {
        return (root, cb, cr) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, filters));
            if (!includeArchived) {
                predicates.add(cb.isFalse(root.get(Certificate_.ARCHIVED)));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateDetailDto getCertificate(SecuredUUID uuid) throws NotFoundException, CertificateException, IOException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);
        CertificateDetailDto dto = certificate.mapToDto();
        if (dto.getExtendedKeyUsage() != null) {
            Map<String, OidRecord> oidToName = OidHandler.getOidCache(OidCategory.EXTENDED_KEY_USAGE);
            List<String> extendedKeyUsageNames = dto.getExtendedKeyUsage().stream().map(oid -> oidToName.get(oid) != null ? oidToName.get(oid).displayName() : oid).toList();
            dto.setExtendedKeyUsage(extendedKeyUsageNames);
        }

        if (certificate.getComplianceResult() != null) {
            ComplianceCheckResultDto complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificate.getUuid(), certificate.getComplianceResult());
            dto.setNonCompliantRules(complianceCheckResult.getFailedRules().stream().filter(rule -> rule.getConnectorUuid() != null).map(failedRule -> {
                CertificateComplianceResultDto resultDto = new CertificateComplianceResultDto();
                resultDto.setConnectorName(failedRule.getConnectorName());
                resultDto.setRuleName(failedRule.getName());
                resultDto.setRuleDescription(failedRule.getDescription());
                resultDto.setStatus(failedRule.getStatus());
                resultDto.setAttributes(failedRule.getAttributes());
                return resultDto;
            }).toList());
        }
        if (dto.getCertificateRequest() != null) {
            dto.getCertificateRequest().setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).build()));
            dto.getCertificateRequest().setSignatureAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build()));
            dto.getCertificateRequest().setAltSignatureAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build()));
        }
        // if has RA profile with authority and connector
        if (certificate.getRaProfile() != null && certificate.getRaProfile().getAuthorityInstanceReference() != null && certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid() != null) {
            dto.setIssueAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build()));
            dto.setRevokeAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build()));
        }
        // TODO: originally showing only metadata from discovery resource, should it be like that?
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).build()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid()));
        dto.setRelatedCertificates(certificate.getSuccessorRelations().stream().map(r -> r.getSuccessorCertificate().mapToListDto()).toList());
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public Certificate getCertificateEntity(SecuredUUID uuid) throws NotFoundException {
        Certificate entity = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        raProfileService.evaluateCertificateRaProfilePermissions(uuid, SecuredParentUUID.fromUUID(entity.getRaProfileUuid()));

        return entity;
    }

    private Certificate getCertificateEntityWithAssociations(SecuredUUID uuid) throws NotFoundException {
        Certificate entity = certificateRepository.findWithAssociationsByUuid(uuid.getValue()).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        raProfileService.evaluateCertificateRaProfilePermissions(uuid, SecuredParentUUID.fromUUID(entity.getRaProfileUuid()));

        return entity;
    }

    private Certificate getCertificateEntityWithChainAssociations(SecuredUUID uuid) throws NotFoundException {
        Certificate entity = certificateRepository.findChainWithAssociationsByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        raProfileService.evaluateCertificateRaProfilePermissions(uuid, SecuredParentUUID.fromUUID(entity.getRaProfileUuid()));
        return entity;
    }

    @Override
    // This method does not need security as it is not exposed by the controllers. This method also does not use uuid
    public Certificate getCertificateEntityByContent(String content) {
        CertificateContent certificateContent = certificateContentRepository.findByContent(content);
        return certificateRepository.findByCertificateContent(certificateContent);
    }

    @Override
    //This method does not need security as it is used only by the internal services for certificate related operations
    public Certificate getCertificateEntityByFingerprint(String fingerprint) throws NotFoundException {
        return certificateRepository.findByFingerprint(fingerprint).orElseThrow(() -> new NotFoundException(Certificate.class, fingerprint));
    }

    @Override
    public Certificate getCertificateEntityByIssuerDnNormalizedAndSerialNumber(String issuerDn, String serialNumber) throws NotFoundException {
        return certificateRepository.findByIssuerDnNormalizedAndSerialNumber(issuerDn, serialNumber).orElseThrow(() -> new NotFoundException(Certificate.class, issuerDn + " " + serialNumber));
    }

    @Override
    public boolean checkCertificateExistsByFingerprint(String fingerprint) {
        try {
            return certificateRepository.findByFingerprint(fingerprint).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DELETE)
    public void deleteCertificate(SecuredUUID uuid) throws NotFoundException {
        Certificate certificate = getCertificateEntity(uuid);
        if (certificate.getUserUuid() != null) {
            applicationEventPublisher.publishEvent(new UpdateCertificateHistoryEvent(certificate.getUuid(), CertificateEvent.DELETE, CertificateEventStatus.FAILED, "Certificate is currently used by some user", null));
            throw new ValidationException("Could not delete certificate %s with UUID %s: Certificate is used by some user.".formatted(certificate.getCommonName(), certificate.getUuid().toString()));
        }

        locationService.removeCertificatesFromLocationsOnDelete(List.of(uuid));

        // If there is some CRL for this certificate, clear its CA certificate UUID.
        crlService.clearCrlsForCaCertificate(List.of(uuid.getValue()));

        certificate.setOwner(null);
        certificate.getGroups().clear();
        objectAssociationService.removeObjectAssociations(Resource.CERTIFICATE, uuid.getValue());
        attributeEngine.deleteObjectAttributeContent(Resource.CERTIFICATE, uuid.getValue());

        scepProfileRepository.clearCaCertificateReference(certificate.getUuid());
        cmpProfileRepository.clearSigningCertificateReference(certificate.getUuid());

        CertificateContent content = (certificate.getCertificateContent() != null && discoveryCertificateRepository.findByCertificateContent(certificate.getCertificateContent()).isEmpty()) ? certificateContentRepository.findById(certificate.getCertificateContent().getId()).orElse(null) : null;
        certificateRepository.delete(certificate);
        if (content != null) {
            certificateContentRepository.delete(content);
            certificate.setCertificateContent(null);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateCertificateObjects(SecuredUUID uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException {
        logger.debug("Updating certificate objects: RA {} groups {} owner {}", request.getRaProfileUuid(), request.getGroupUuids(), request.getOwnerUuid());
        if (request.getRaProfileUuid() != null) {
            switchRaProfile(uuid, request.getRaProfileUuid().isEmpty() ? null : SecuredUUID.fromString(request.getRaProfileUuid()));
        }
        if (request.getGroupUuids() != null) {
            this.updateCertificateGroups(uuid, request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet()));
        }
        if (request.getOwnerUuid() != null) {
            updateOwner(uuid, request.getOwnerUuid().isEmpty() ? null : request.getOwnerUuid());
        }
        if (request.getTrustedCa() != null) {
            updateTrustedCaMark(uuid, request.getTrustedCa());
        }
    }

    private void updateTrustedCaMark(SecuredUUID uuid, Boolean trustedCa) throws NotFoundException {
        Certificate certificate = getCertificateEntity(uuid);
        if (certificate.isArchived()) {
            throw new ValidationException("Certificate with UUID %s is archived and its trusted CA mark cannot be updated.".formatted(uuid));
        }
        if (certificate.getTrustedCa() == null) {
            throw new ValidationException("Trying to mark certificate as trusted CA when certificate is not CA.");
        }
        certificate.setTrustedCa(trustedCa);
    }

    @Async
    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void bulkUpdateCertificatesObjects(SecurityFilter filter, MultipleCertificateObjectUpdateDto request) throws NotFoundException, NotSupportedException {
        logger.info("Bulk updating certificate objects: RA {} groups {} owner {}", request.getRaProfileUuid(), request.getGroupUuids(), request.getOwnerUuid());
        setupSecurityFilter(filter);
        Set<UUID> groupUuids = null;
        if (request.getGroupUuids() != null)
            groupUuids = request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet());
        String ownerUuid = null;
        if (request.getOwnerUuid() != null && !request.getOwnerUuid().isEmpty()) {
            ownerUuid = request.getOwnerUuid();
        }

        boolean removeRaProfile = false;
        if (request.getRaProfileUuid() != null) removeRaProfile = request.getRaProfileUuid().isEmpty();

        if (request.getFilters() != null && !request.getFilters().isEmpty() && (request.getCertificateUuids() == null || request.getCertificateUuids().isEmpty())) {
            throw new NotSupportedException("Bulk updating of certificates by filters is not supported.");
        }

        UUID loggedUserUuid = null;
        for (String certificateUuidString : request.getCertificateUuids()) {
            SecuredUUID certificateUuid = SecuredUUID.fromString(certificateUuidString);
            TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
            try {
                bulkUpdateCertificateObjects(request, certificateUuid, groupUuids, ownerUuid, removeRaProfile);
                transactionManager.commit(status);
            } catch (Exception e) {
                transactionManager.rollback(status);
                logger.error("Error occurred when updating certificate with UUID {}: {}", certificateUuidString, e.getMessage());
                if (loggedUserUuid == null) {
                    loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
                }
                notificationProducer.produceInternalNotificationMessage(Resource.CERTIFICATE, certificateUuid.getValue(), NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid), "Unable to update properties of the certificate " + certificateUuid, e.getMessage());
            }
        }
    }

    private void bulkUpdateCertificateObjects(MultipleCertificateObjectUpdateDto request, SecuredUUID certificateUuid, Set<UUID> groupUuids, String ownerUuid, boolean removeRaProfile) throws NotFoundException, CertificateOperationException, AttributeException {
        permissionEvaluator.certificate(certificateUuid);
        if (groupUuids != null) updateCertificateGroups(certificateUuid, groupUuids);
        if (request.getOwnerUuid() != null) updateOwner(certificateUuid, ownerUuid);
        if (request.getRaProfileUuid() != null)
            switchRaProfile(certificateUuid, removeRaProfile ? null : SecuredUUID.fromString(request.getRaProfileUuid()));
    }

    @Override
    @Async
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DELETE, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void bulkDeleteCertificate(SecurityFilter filter, RemoveCertificateDto request) throws NotSupportedException {
        setupSecurityFilter(filter);

        if (request.getFilters() == null || request.getFilters().isEmpty() || (request.getUuids() != null && !request.getUuids().isEmpty())) {
            UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
            List<String> requestedUuids = request.getUuids() != null ? request.getUuids() : Collections.emptyList();
            int totalToDelete = requestedUuids.size();
            int deletedCount = 0;

            // Process bulk deletion in batches. Every batch gets its own transaction.
            for (int i = 0; i < totalToDelete; i += bulkDeleteBatchSize) {
                int end = Math.min(i + bulkDeleteBatchSize, totalToDelete);
                List<UUID> batchUuids = requestedUuids.subList(i, end).stream().map(UUID::fromString).toList();

                TransactionStatus txStatus = transactionManager.getTransaction(new DefaultTransactionDefinition());
                try {
                    deletedCount += bulkDeleteCertificateBatch(filter, batchUuids, loggedUserUuid);
                    transactionManager.commit(txStatus);
                } catch (Exception e) {
                    transactionManager.rollback(txStatus);
                    logger.error("Failed to process bulk deletion batch: {}", e.getMessage(), e);
                    notificationProducer.produceInternalNotificationMessage(Resource.CERTIFICATE,
                            batchUuids.getFirst(),
                            NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                            "Batch certificate deletion failed for " + batchUuids.size() + " certificates",
                            e.getMessage());
                }
            }
            logger.debug("Bulk deleted {} of {} certificates.", deletedCount, totalToDelete);
        } else {
            throw new NotSupportedException("Bulk delete of certificates by filters is not supported.");
        }
    }

    private int bulkDeleteCertificateBatch(SecurityFilter filter, List<UUID> batchUuids, UUID loggedUserUuid) {
        // 1. Check permissions.
        TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = createAdditionalWhereClauseForBulkDeleteBatch(batchUuids);
        List<UUID> permittedUuids = certificateRepository.findUuidsUsingSecurityFilter(filter, additionalWhereClause, null, null);
        List<UUID> nonPermittedUuids = new ArrayList<>(batchUuids);
        nonPermittedUuids.removeAll(permittedUuids);

        for (UUID nonPermitted : nonPermittedUuids) {
            logger.error("Unable to delete certificate {}. The certificate cannot be found or cannot be authorized for deletion.", nonPermitted);
            notificationProducer.produceInternalNotificationMessage(Resource.CERTIFICATE, nonPermitted,
                    NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                    "Unable to delete certificate " + nonPermitted,
                    "The certificate cannot be found or cannot be authorized for deletion.");
        }

        if (permittedUuids.isEmpty()) {
            return 0;
        }

        // 2. Fetch certificates.
        List<SecuredUUID> permittedSecuredUuids = permittedUuids.stream().map(SecuredUUID::fromUUID).toList();
        List<Certificate> certificates = certificateRepository.findAllWithAssociationsByUuidIn(permittedUuids);

        // 3. Do the work.
        locationService.removeCertificatesFromLocationsOnDelete(permittedSecuredUuids);

        scepProfileRepository.clearCaCertificateReferenceIn(permittedUuids);
        cmpProfileRepository.clearSigningCertificateReferenceIn(permittedUuids);

        crlService.clearCrlsForCaCertificate(permittedUuids);

        certificates.forEach(c -> {
            c.setOwner(null);
            c.getGroups().clear();
        });
        objectAssociationService.bulkRemoveObjectAssociations(Resource.CERTIFICATE, permittedUuids);
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CERTIFICATE, permittedUuids);

        certificateRepository.deleteAllInBatch(certificates);
        certificateContentRepository.deleteUnusedCertificateContents();

        return certificates.size();
    }

    private static TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> createAdditionalWhereClauseForBulkDeleteBatch(List<UUID> batchUuids) {
        return ((root, cb, cr) -> {
            var in = cb.in(root.get(Certificate_.uuid));
            batchUuids.forEach(in::value);
            return in;
        });
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CERTIFICATE, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.COMMON_NAME),
                SearchHelper.prepareSearch(FilterField.SERIAL_NUMBER),
                SearchHelper.prepareSearch(FilterField.ISSUER_SERIAL_NUMBER),
                SearchHelper.prepareSearch(FilterField.RA_PROFILE_NAME, raProfileRepository.findAll().stream().map(RaProfile::getName).toList()),
                SearchHelper.prepareSearch(FilterField.GROUP_NAME, groupRepository.findAll().stream().map(Group::getName).toList()),
                SearchHelper.prepareSearch(FilterField.CERT_LOCATION_NAME, locationRepository.findAll().stream().map(Location::getName).toList()),
                SearchHelper.prepareSearch(FilterField.OWNER, userManagementApiClient.getUsers().getData().stream().map(UserDto::getUsername).toList()),
                SearchHelper.prepareSearch(FilterField.CERTIFICATE_STATE, Arrays.stream(CertificateState.values()).map(CertificateState::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CERTIFICATE_VALIDATION_STATUS, Arrays.stream(CertificateValidationStatus.values()).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.COMPLIANCE_STATUS, Arrays.stream(ComplianceStatus.values()).map(ComplianceStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.ISSUER_COMMON_NAME),
                SearchHelper.prepareSearch(FilterField.FINGERPRINT),
                SearchHelper.prepareSearch(FilterField.SIGNATURE_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctSignatureAlgorithm())),
                SearchHelper.prepareSearch(FilterField.ALT_SIGNATURE_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctAltSignatureAlgorithm())),
                SearchHelper.prepareSearch(FilterField.NOT_AFTER),
                SearchHelper.prepareSearch(FilterField.NOT_BEFORE),
                SearchHelper.prepareSearch(FilterField.SUBJECTDN),
                SearchHelper.prepareSearch(FilterField.ISSUERDN),
                SearchHelper.prepareSearch(FilterField.SUBJECT_ALTERNATIVE_NAMES),
                SearchHelper.prepareSearch(FilterField.OCSP_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CRL_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.SIGNATURE_VALIDATION, Arrays.stream((CertificateValidationStatus.values())).map(CertificateValidationStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.PUBLIC_KEY_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctPublicKeyAlgorithm())),
                SearchHelper.prepareSearch(FilterField.ALT_PUBLIC_KEY_ALGORITHM, new ArrayList<>(certificateRepository.findDistinctAltPublicKeyAlgorithm())),
                SearchHelper.prepareSearch(FilterField.KEY_SIZE, new ArrayList<>(certificateRepository.findDistinctKeySize())),
                SearchHelper.prepareSearch(FilterField.ALT_KEY_SIZE, new ArrayList<>(certificateRepository.findDistinctAltKeySize())),
                SearchHelper.prepareSearch(FilterField.KEY_USAGE, Arrays.stream((CertificateKeyUsage.values())).map(CertificateKeyUsage::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.PRIVATE_KEY),
                SearchHelper.prepareSearch(FilterField.SUBJECT_TYPE, Arrays.stream(CertificateSubjectType.values()).map(CertificateSubjectType::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.TRUSTED_CA),
                SearchHelper.prepareSearch(FilterField.HYBRID_CERTIFICATE),
                SearchHelper.prepareSearch(FilterField.ARCHIVED),
                SearchHelper.prepareSearch(FilterField.CERTIFICATE_PROTOCOL),
                SearchHelper.prepareSearch(FilterField.PRECEDING_CERTIFICATES, Arrays.stream(CertificateRelationType.values()).map(CertificateRelationType::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.SUCCEEDING_CERTIFICATES, Arrays.stream(CertificateRelationType.values()).map(CertificateRelationType::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.ACME_PROFILE, acmeProfileRepository.findAll().stream().map(AcmeProfile::getName).toList()),
                SearchHelper.prepareSearch(FilterField.SCEP_PROFILE, scepProfileRepository.findAll().stream().map(ScepProfile::getName).toList()),
                SearchHelper.prepareSearch(FilterField.CMP_PROFILE, cmpProfileRepository.findAll().stream().map(CmpProfile::getName).toList()),
                SearchHelper.prepareSearch(FilterField.ACME_ACCOUNT, acmeAccountRepository.findAll().stream().map(AcmeAccount::getAccountId).toList())
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    // @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    // Auth is not required for this method. It is used only internally by other services to update the certificate chain
    private void updateCertificateChain(Certificate certificate) throws CertificateException {
        if (certificate.getCertificateContent() == null) {
            return;
        }
        X509Certificate subCert;
        try {
            subCert = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
        } catch (Exception e) {
            // We do not need to handle exceptions here because if subject certificate cannot be parsed, we cannot update its certificate chain
            return;
        }
        updateCertificateChain(certificate, subCert);
    }

    private void updateCertificateChain(Certificate certificate, X509Certificate subCert) throws CertificateException {
        // Check if the certificate is self-signed
        if (isSelfSigned(subCert, certificate.getUuid())) {
            return;
        }
        boolean issuerInInventory = false;
        // Try to find issuer certificate in repository
        for (Certificate issuer : certificateRepository.findBySubjectDnNormalized(certificate.getIssuerDnNormalized())) {
            X509Certificate issCert;
            try {
                issCert = CertificateUtil.parseCertificate(issuer.getCertificateContent().getContent());
            } catch (Exception e) {
                // We do not need to handle exceptions here because if certificate cannot be parsed, we ignore it as a
                // candidate for issuer and continue with next candidate
                continue;
            }
            // Verify signature for a certificate with matching Subject DN, if it matches, the issuer is found
            if (verifySignature(subCert, issCert)) {
                certificate.setIssuerSerialNumber(issuer.getSerialNumber());
                certificate.setIssuerCertificateUuid(issuer.getUuid());
                certificateRepository.save(certificate);
                issuerInInventory = true;
                // If the issuer of certificate doesn't have its issuer, try to update issuer for this certificate as well
                if (issuer.getIssuerCertificateUuid() == null) {
                    updateCertificateChain(issuer);
                }
                break;
            }
        }
        // If the issuer isn't in inventory, try to download it from AIA extension of the certificate
        if (!issuerInInventory) {
            int downloadedCertificates = 0;
            List<String> aiaChain = downloadChainFromAia(certificate, subCert);
            Certificate previousCertificate = certificate;
            for (String chainCertificate : aiaChain) {
                Certificate nextInChain;
                try {
                    // insert certificate atomically with resolvibg fingerprint unique conflict and then update issuer uuid and serial number
                    nextInChain = createCertificateAtomic(chainCertificate, false);

                    assert nextInChain != null;
                    previousCertificate.setIssuerCertificateUuid(nextInChain.getUuid());
                    previousCertificate.setIssuerSerialNumber(nextInChain.getSerialNumber());
                    previousCertificate = nextInChain;
                    ++downloadedCertificates;
                } catch (NoSuchAlgorithmException | CertificateException | NotFoundException e) {
                    // Certificate downloaded from AIA cannot be parsed and inserted into inventory, so ignore the rest of chain
                    break;
                }
            }

            // if downloaded some certificate, try to update chain of last one, if it is really last self-signed
            if (downloadedCertificates > 0) {
                updateCertificateChain(previousCertificate);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateChainResponseDto getCertificateChain(SecuredUUID uuid, boolean withEndCertificate) throws NotFoundException {
        Certificate certificate = withEndCertificate ? getCertificateEntityWithChainAssociations(uuid) : getCertificateEntity(uuid);

        CertificateChainResponseDto certificateChainResponseDto = new CertificateChainResponseDto();
        if (certificate.getCertificateContent() != null) {
            List<Certificate> certificateChain = getCertificateChainInternal(certificate, withEndCertificate);
            Certificate lastCertificate = certificateChain.isEmpty() ? certificate : certificateChain.getLast();
            certificateChainResponseDto.setCompleteChain(completeCertificateChain(lastCertificate, certificateChain));
            certificateChainResponseDto.setCertificates(certificateChain.stream().map(Certificate::mapToChainDto).toList());
        }
        return certificateChainResponseDto;
    }

    private List<Certificate> getCertificateChainInternal(Certificate certificate, boolean withEndCertificate) {
        List<Certificate> certificateChain = new ArrayList<>();
        if (certificate.getCertificateContent() == null) {
            return certificateChain;
        }
        if (withEndCertificate) {
            certificateChain.add(certificate);
        }
        constructCertificateChainFromInventory(certificate, certificateChain);
        return certificateChain;
    }

    private boolean completeCertificateChain(Certificate lastCertificate, List<Certificate> certificateChain) {
        try {
            X509Certificate x509 = CertificateUtil.parseCertificate(lastCertificate.getCertificateContent().getContent());
            // If the last certificate is self-signed, we presume it is a root certificate and we are finished.
            if (isSelfSigned(x509, lastCertificate.getUuid())) {
                return true;
            } else {
                // update chain and determine if its issuer was found
                updateCertificateChain(lastCertificate, x509);
                if (lastCertificate.getIssuerCertificateUuid() != null) {
                    // construct newly found certificates from chain and do the self-signed check again
                    lastCertificate = constructCertificateChainFromInventory(lastCertificate, certificateChain);
                    return isSelfSigned(lastCertificate);
                }
            }
        } catch (CertificateException e) {
            // If it cannot be verified whether certificate is self-signed or updateCertificateChain fails,
            // we end certificate chain building and return partial result
        }
        return false;
    }

    private Certificate constructCertificateChainFromInventory(Certificate certificate, List<Certificate> certificateChain) {
        List<String> chainUuidStrings = certificateRepository.findCertificateChainUuids(certificate.getUuid(), certificateChainMaxDepth);
        if (chainUuidStrings.size() <= 1) {
            return certificate; // we have only the starting certificate
        }

        // Bulk-load all ancestor entities (indices 1..N) with their certificateContent in one query.
        List<UUID> ancestorUuids = chainUuidStrings.subList(1, chainUuidStrings.size())
                .stream()
                .map(UUID::fromString)
                .toList();

        Map<UUID, Certificate> byUuid = certificateRepository
                .findChainWithAssociationsByUuidIn(ancestorUuids)
                .stream()
                .collect(Collectors.toMap(Certificate::getUuid, c -> c));

        Certificate lastCertificate = certificate;
        for (UUID ancestorUuid : ancestorUuids) {
            Certificate issuerCertificate = byUuid.get(ancestorUuid);
            if (issuerCertificate != null) {
                certificateChain.add(issuerCertificate);
                lastCertificate = issuerCertificate;
            } else {
                // Dangling FK – the CTE found the UUID but the bulk-load did not return the entity.
                // Clear the references and return an incomplete chain.
                lastCertificate.setIssuerCertificateUuid(null);
                lastCertificate.setIssuerSerialNumber(null);
                certificateRepository.save(lastCertificate);
                break;
            }
        }

        return lastCertificate;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateChainDownloadResponseDto downloadCertificateChain(SecuredUUID uuid, CertificateFormat certificateFormat, boolean withEndCertificate, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException {
        List<CertificateContentDto> certificateContent = getCertificateContent(List.of(uuid.getValue()));
        if (certificateContent.isEmpty()) {
            throw new ValidationException("Cannot download certificate chain, the end certificate is not issued.");
        }
        CertificateChainResponseDto certificateChainResponseDto = getCertificateChain(uuid, withEndCertificate);
        List<CertificateDetailDto> certificateChain = certificateChainResponseDto.getCertificates();
        CertificateChainDownloadResponseDto certificateChainDownloadResponseDto = new CertificateChainDownloadResponseDto();
        certificateChainDownloadResponseDto.setCompleteChain(certificateChainResponseDto.isCompleteChain());
        certificateChainDownloadResponseDto.setFormat(certificateFormat);
        certificateChainDownloadResponseDto.setEncoding(encoding);
        certificateChainDownloadResponseDto.setContent(getDownloadedContent(certificateChain, certificateFormat, encoding, true));
        return certificateChainDownloadResponseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateDownloadResponseDto downloadCertificate(UUID uuid, CertificateFormat certificateFormat, CertificateFormatEncoding encoding) throws CertificateException, NotFoundException, IOException {
        CertificateDetailDto certificate = getCertificate(SecuredUUID.fromUUID(uuid));
        if (certificate.getCertificateContent() == null) {
            throw new ValidationException("Cannot download the certificate, certificate is not issued.");
        }
        CertificateDownloadResponseDto certificateDownloadResponseDto = new CertificateDownloadResponseDto();
        certificateDownloadResponseDto.setFormat(certificateFormat);
        certificateDownloadResponseDto.setEncoding(encoding);
        certificateDownloadResponseDto.setContent(getDownloadedContent(List.of(certificate), certificateFormat, encoding, false));
        return certificateDownloadResponseDto;
    }

    private String getDownloadedContent(List<CertificateDetailDto> certificateDetailDtos, CertificateFormat certificateFormat, CertificateFormatEncoding encoding, boolean downloadingChain) throws NotFoundException, CertificateException {
        if (certificateFormat == CertificateFormat.RAW) {
            if (encoding == CertificateFormatEncoding.DER) {
                if (downloadingChain) {
                    throw new ValidationException("DER encoding of raw format is unsupported for certificate chain.");
                }
                return getCertificateEntity(SecuredUUID.fromString(certificateDetailDtos.getFirst().getUuid())).getCertificateContent().getContent();
            }
            // Encoding is PEM otherwise
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream));
            for (CertificateDto certificateDto : certificateDetailDtos) {
                Certificate certificateInstance = getCertificateEntity(SecuredUUID.fromString(certificateDto.getUuid()));
                String content = certificateInstance.getCertificateContent().getContent();
                X509Certificate x509Certificate;
                x509Certificate = CertificateUtil.getX509Certificate(content);
                try {
                    jcaPEMWriter.writeObject(x509Certificate);
                    jcaPEMWriter.flush();
                } catch (IOException e) {
                    throw new CertificateException("Could not write downloaded content as PEM format: " + e.getMessage());
                }
            }
            return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        }
        // Formatting is PKCS7 otherwise
        else {
            List<X509Certificate> x509CertificateChain = new ArrayList<>();
            for (CertificateDto certificateDto : certificateDetailDtos) {
                Certificate certificateInstance = getCertificateEntity(SecuredUUID.fromString(certificateDto.getUuid()));
                X509Certificate x509Certificate;
                x509Certificate = CertificateUtil.getX509Certificate(certificateInstance.getCertificateContent().getContent());
                x509CertificateChain.add(x509Certificate);
            }
            try {
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                generator.addCertificates(new JcaCertStore(x509CertificateChain));
                byte[] encoded = generator.generate(new CMSProcessableByteArray(new byte[0])).getEncoded();
                if (encoding == CertificateFormatEncoding.PEM) {
                    ContentInfo contentInfo = ContentInfo.getInstance(ASN1Primitive.fromByteArray(encoded));
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream));
                    jcaPEMWriter.writeObject(contentInfo);
                    jcaPEMWriter.flush();
                    return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
                }
                // Encoding is DER otherwise
                else {
                    return Base64.getEncoder().encodeToString(encoded);
                }
            } catch (Exception e) {
                throw new CertificateException("Could not write downloaded content as PKCS#7 format: " + e.getMessage());
            }
        }
    }

    @Override
    public void validate(Certificate certificate) {
        List<Certificate> certificateChain = getCertificateChainInternal(certificate, true);
        boolean isCompleteChain = !certificateChain.isEmpty() && completeCertificateChain(certificateChain.getLast(), certificateChain);

        CertificateValidationStatus newStatus;
        CertificateValidationStatus oldStatus = certificate.getValidationStatus();
        ICertificateValidator certificateValidator = getCertificateValidator(certificate.getCertificateType());

        try {
            newStatus = certificateValidator.validateCertificate(certificate, isCompleteChain);
        } catch (Exception e) {
            logger.warn("Unable to validate the certificate {}: {}", certificate, e.getMessage());
            newStatus = CertificateValidationStatus.FAILED;
            certificate.setValidationStatus(newStatus);
            certificate.setStatusValidationTimestamp(OffsetDateTime.now());
            certificateRepository.save(certificate);
        }

        if (!oldStatus.equals(newStatus)) {
            eventProducer.produceMessage(CertificateStatusChangedEventHandler.constructEventMessage(certificate.getUuid(), oldStatus, newStatus));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateValidationResultDto getCertificateValidationResult(SecuredUUID uuid) throws NotFoundException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);
        CertificateValidationResultDto resultDto = new CertificateValidationResultDto();
        if (CertificateUtil.isValidationEnabled(certificate, resultDto)) {
            validate(certificate);
        }
        resultDto.setResultStatus(certificate.getValidationStatus());

        String validationResult = certificate.getCertificateValidationResult();
        try {
            Map<CertificateValidationCheck, CertificateValidationCheckDto> validationChecks = MetaDefinitions.deserializeValidation(validationResult);
            resultDto.setValidationChecks(validationChecks);
        } catch (IllegalStateException e) {
            logger.error(e.getMessage());
        }
        resultDto.setValidationTimestamp(certificate.getStatusValidationTimestamp());
        return resultDto;
    }

    /**
     * Check if the X.509 certificate is self-signed
     *
     * @param certificate entity
     * @return true if the certificate is self-signed, false otherwise
     * @throws CertificateException if the certificate cannot be parsed
     */
    private boolean isSelfSigned(Certificate certificate) throws CertificateException {
        return isSelfSigned(getX509(certificate.getCertificateContent().getContent()), certificate.getUuid());
    }

    private boolean isSelfSigned(X509Certificate x509Certificate, UUID certificateUuid) throws CertificateException {
        // we check the signature with the certificate public key
        try {
            x509Certificate.verify(x509Certificate.getPublicKey());
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.debug("Unable to verify if the certificate {} is self-signed: {}", certificateUuid, e.getMessage());
            throw new CertificateException(e);
        } catch (SignatureException | InvalidKeyException e) {
            // if the certificate is not self-signed, the verification will fail
            return false;
        }
    }

    private boolean verifySignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            subjectCertificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private X509Certificate getX509(String certificate) throws CertificateException {
        return CertificateUtil.getX509Certificate(certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("\r", "").replace("\n", "").replace("-----END CERTIFICATE-----", ""));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public Certificate createCertificate(String certificateData, CertificateType certificateType) throws com.czertainly.api.exception.CertificateException {
        Certificate entity = new Certificate();
        String fingerprint;

        // by default, we are working with the X.509 certificate
        if (certificateType == null) {
            certificateType = CertificateType.X509;
        }
        if (!certificateType.equals(CertificateType.X509)) {
            String message = "Unsupported type of the certificate: " + certificateType;
            logger.debug(message);
            throw new com.czertainly.api.exception.CertificateException(message);
        } else {
            X509Certificate certificate;
            try {
                certificate = getX509(certificateData);
            } catch (CertificateException e) {
                String message = "Failed to get parse the certificate " + certificateData + " > " + e.getMessage();
                logger.error("message");
                throw new com.czertainly.api.exception.CertificateException(message);
            }
            try {
                fingerprint = CertificateUtil.getThumbprint(certificate.getEncoded());
                Optional<Certificate> existingCertificate = certificateRepository.findByFingerprint(fingerprint);

                if (existingCertificate.isPresent()) {
                    logger.debug("Returning existing certificate with fingerprint {}", fingerprint);
                    return existingCertificate.get();
                }
            } catch (NoSuchAlgorithmException | CertificateException e) {
                String message = "Failed to get thumbprint for certificate " + certificate.getSerialNumber() + " > " + e.getMessage();
                logger.error("message");
                throw new com.czertainly.api.exception.CertificateException(message);
            }

            CertificateUtil.prepareIssuedCertificate(entity, certificate);
            byte[] altPublicKey = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
            uploadCertificateKey(certificate.getPublicKey(), entity, altPublicKey);
            entity.setFingerprint(fingerprint);
            entity.setCertificateContent(checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(certificate)));

            certificateRepository.save(entity);
            certificateEventHistoryService.addEventHistory(entity.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");

            return entity;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public Certificate createCertificateEntity(X509Certificate certificate) {
        logger.debug("Making a new entry for a certificate: subject={}, serialNumber={}",
                certificate.getSubjectX500Principal(),
                certificate.getSerialNumber()
        );
        Certificate modal = new Certificate();
        String fingerprint = null;
        try {
            fingerprint = CertificateUtil.getThumbprint(certificate.getEncoded());
            Optional<Certificate> existingCertificate = certificateRepository.findByFingerprint(fingerprint);

            if (existingCertificate.isPresent()) {
                return existingCertificate.get();
            }
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            logger.error("Unable to calculate sha 256 thumbprint");
        }

        CertificateUtil.prepareIssuedCertificate(modal, certificate);
        CertificateContent certificateContent = checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(certificate));
        modal.setFingerprint(fingerprint);
        modal.setCertificateContent(certificateContent);
        modal.setCertificateContentId(certificateContent.getId());

        return modal;
    }

    private void uploadCertificateKey(PublicKey publicKey, Certificate certificate, byte[] altPublicKeyEncoded) {
        UUID keyUuid;
        if (publicKey != null && certificate.getKeyUuid() == null) {
            keyUuid = cryptographicKeyService.findKeyByFingerprint(certificate.getPublicKeyFingerprint());
            if (keyUuid == null) {
                keyUuid = cryptographicKeyService.uploadCertificatePublicKey("certKey_" + Objects.requireNonNullElse(certificate.getCommonName(), certificate.getSerialNumber()), publicKey, certificate.getKeySize(), certificate.getPublicKeyFingerprint());
            }
            certificate.setKeyUuid(keyUuid);
        }
        if (altPublicKeyEncoded != null) {
            PublicKey altPublicKey;
            try {
                altPublicKey = CertificateUtil.getAltPublicKey(altPublicKeyEncoded);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
                logger.error("Could not retrieve alternative public key from the certificate: {}", e.getMessage());
                return;
            }
            String fingerprint = null;
            try {
                fingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(altPublicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                logger.error("Cannot create fingerprint for Alternative Public Key: {}", e.getMessage());
            }
            UUID altKeyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
            int keyLength = KeySizeUtil.getKeyLength(altPublicKey);
            if (altKeyUuid == null) {
                altKeyUuid = cryptographicKeyService.uploadCertificatePublicKey("altCertKey_" + Objects.requireNonNullElse(certificate.getCommonName(), certificate.getSerialNumber()), altPublicKey, keyLength, fingerprint);
            }
            certificate.setAltKeyUuid(altKeyUuid);
            certificate.setAltPublicKeyAlgorithm(CertificateUtil.getKeyAlgorithmStringFromProviderName(altPublicKey.getAlgorithm()));
            certificate.setAltKeySize(keyLength);
            certificate.setAltKeyFingerprint(fingerprint);
            certificate.setHybridCertificate(true);
        }
    }

    @Override
    public CertificateContent checkAddCertificateContent(String fingerprint, String content) {
        CertificateContent certificateContent = certificateContentRepository.findByFingerprint(fingerprint);
        if (certificateContent != null) {
            return certificateContent;
        }

        certificateContent = new CertificateContent();
        certificateContent.setContent(CertificateUtil.normalizeCertificateContent(content));
        certificateContent.setFingerprint(fingerprint);

        certificateContentRepository.save(certificateContent);
        return certificateContent;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto upload(UploadCertificateRequestDto request, boolean ignoreCustomAttributes) throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException {
        X509Certificate certificate = CertificateUtil.parseUploadedCertificateContent(request.getCertificate());
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }

        if (!ignoreCustomAttributes) {
            attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, request.getCustomAttributes());
        }

        Certificate entity = createCertificateEntity(certificate);
        byte[] altPublicKey = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        uploadCertificateKey(certificate.getPublicKey(), entity, altPublicKey);
        certificateRepository.save(entity);

        CertificateDetailDto dto = entity.mapToDto();
        if (!ignoreCustomAttributes) {
            dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, entity.getUuid(), request.getCustomAttributes()));
        }

        certificateEventHistoryService.addEventHistory(entity.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");
        applicationEventPublisher.publishEvent(new CertificateValidationEvent(entity.getUuid()));

        return dto;
    }

    @Override
    public Certificate checkCreateCertificate(String certificate) throws AlreadyExistException, CertificateException, NoSuchAlgorithmException {
        X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate);
        String fingerprint = CertificateUtil.getThumbprint(x509Cert);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }
        Certificate entity = createCertificateEntity(x509Cert);
        byte[] altPublicKey = x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        uploadCertificateKey(x509Cert.getPublicKey(), entity, altPublicKey);
        entity = certificateRepository.save(entity);

        // set owner of certificate to logged user
        objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, entity.getUuid());

        certificateComplianceCheck(entity);
        return entity;
    }

    @Override
    public Certificate createCertificateAtomic(String certificate, boolean assignOwner) throws CertificateException, NoSuchAlgorithmException, NotFoundException {
        X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate);
        String fingerprint = CertificateUtil.getThumbprint(x509Cert);

        certificateContentRepository.insertWithFingerprintConflictResolve(fingerprint, CertificateUtil.normalizeCertificateContent(X509ObjectToString.toPem(x509Cert)));
        CertificateContent certificateContent = certificateContentRepository.findByFingerprint(fingerprint);
        if (certificateContent == null) {
            throw new NotFoundException(CertificateContent.class, fingerprint);
        }

        OffsetDateTime now = OffsetDateTime.now();
        Certificate certificateEntity = new Certificate();
        certificateEntity.setUuid(UUID.randomUUID());
        certificateEntity.setCreated(now);
        certificateEntity.setUpdated(now);
        certificateEntity.setFingerprint(fingerprint);
        certificateEntity.setCertificateContent(certificateContent);
        CertificateUtil.prepareIssuedCertificate(certificateEntity, x509Cert);

        Integer countInserted = certificateRepository.insertWithFingerprintConflictResolve(certificateEntity);
        certificateEntity = certificateRepository.findByFingerprint(fingerprint).orElseThrow(() -> new NotFoundException(Certificate.class, fingerprint));

        // certificate was actually inserted
        if (countInserted == 1) {
            byte[] altPublicKey = x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
            uploadCertificateKey(x509Cert.getPublicKey(), certificateEntity, altPublicKey);

            // set owner of certificateEntity to logged user
            if (assignOwner) {
                objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, certificateEntity.getUuid());
            }
            certificateComplianceCheck(certificateEntity);
        }
        return certificateEntity;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.REVOKE)
    public void revokeCertificate(String serialNumber) {
        Certificate certificate = null;
        CertificateValidationStatus oldStatus = CertificateValidationStatus.NOT_CHECKED;
        try {
            certificate = certificateRepository.findBySerialNumberIgnoreCase(serialNumber).orElseThrow(() -> new NotFoundException(Certificate.class, serialNumber));
            oldStatus = certificate.getValidationStatus();
            certificate.setState(CertificateState.REVOKED);
            certificateRepository.save(certificate);
        } catch (NotFoundException e) {
            logger.warn("Unable to find the certificate with serialNumber {}", serialNumber);
        }
        if (certificate != null) {
            eventProducer.produceMessage(CertificateStatusChangedEventHandler.constructEventMessage(certificate.getUuid(), oldStatus, CertificateValidationStatus.REVOKED));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    // TODO - Enhance method to return data from location service using filter
    public List<LocationDto> listLocations(SecuredUUID certificateUuid) throws NotFoundException {
        Certificate certificateEntity = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));

        final LocationsResponseDto locationsResponseDto = locationService.listLocations(SecurityFilter.create(), new SearchRequestDto());
        final List<String> locations = locationsResponseDto.getLocations().stream().map(LocationDto::getUuid).toList();

        return certificateEntity.getLocations().stream().map(CertificateLocation::getLocation).sorted(Comparator.comparing(Location::getCreated).reversed()).map(Location::mapToDtoSimple).filter(e -> locations.contains(e.getUuid())).toList();
    }


    @Override
    // Only Internal method
    public List<Certificate> listCertificatesForRaProfile(RaProfile raProfile) {
        return certificateRepository.findByRaProfile(raProfile);
    }

    @Override
    // Only Internal method
    public List<Certificate> listCertificatesForRaProfileAndNonNullComplianceStatus(RaProfile raProfile) {
        return certificateRepository.findByRaProfileAndComplianceStatusIsNotNullAndArchivedIsFalse(raProfile);
    }

    @Override
    @Async
    public void checkCompliance(CertificateComplianceCheckDto request) throws NotFoundException {
        for (String uuid : request.getCertificateUuids()) {
            try {
                Certificate certificateEntity = getCertificateEntity(SecuredUUID.fromString(uuid));
                complianceService.checkResourceObjectCompliance(Resource.CERTIFICATE, certificateEntity.getUuid());
            } catch (Exception e) {
                logger.error("Compliance check failed.", e);
            }
        }
    }

    @Override
    // Internal Use only
    public void updateCertificateEntity(Certificate certificate) {
        certificateRepository.save(certificate);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public int updateCertificatesStatusScheduled() {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        CertificateValidationSettingsDto certificateValidationSettings = platformSettings.getCertificates().getValidation();
        boolean platformEnabled = certificateValidationSettings.getEnabled();
        List<CertificateValidationStatus> skipStatuses = List.of(CertificateValidationStatus.REVOKED, CertificateValidationStatus.EXPIRED);
        Long totalCertificates = certificateRepository.countCertificatesToCheckStatus(skipStatuses, platformEnabled);
        int maxCertsToValidate = Math.max(100, Math.round(totalCertificates / (float) 24));

        OffsetDateTime before = null;
        if (platformEnabled) before = OffsetDateTime.now().minusDays(certificateValidationSettings.getFrequency());

        // process 1/24 of eligible certificates for status update
        final List<UUID> certificateUuids = certificateRepository.findCertificatesToCheckStatus(before, skipStatuses, platformEnabled, PageRequest.of(0, maxCertsToValidate));

        logger.info(MarkerFactory.getMarker("scheduleInfo"), "Scheduled certificate status update. Batch size {}/{} certificates", certificateUuids.size(), totalCertificates);
        sendValidationBatches(certificateUuids); // send in batches
        return certificateUuids.size();
    }

    private void sendValidationBatches(List<UUID> certificateUuids) {
        if (certificateUuids == null || certificateUuids.isEmpty()) return;
        final int size = certificateUuids.size();
        for (int i = 0; i < size; i += VALIDATION_BATCH_SIZE) {
            List<UUID> batch = certificateUuids.subList(i, Math.min(i + VALIDATION_BATCH_SIZE, size));
            validationProducer.produceMessage(new ValidationMessage(Resource.CERTIFICATE, batch, null, null, null, null));
        }
    }

    @Override
    // Internal Use Only
    public void updateCertificateUser(UUID certificateUuid, String userUuid) throws NotFoundException {
        Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
        if (certificate.isArchived()) {
            throw new ValidationException("Certificate with UUID %s is archived and user with UUID %s cannot be set.".formatted(certificateUuid, userUuid));
        }
        if (userUuid == null) {
            certificate.setUserUuid(null);
        } else {
            certificate.setUserUuid(UUID.fromString(userUuid));
        }
        certificateRepository.save(certificate);
    }

    @Override
    // Internal Use Only
    public void removeCertificateUser(UUID userUuid) {
        try {
            Certificate certificate = certificateRepository.findByUserUuid(userUuid).orElseThrow(() -> new NotFoundException(Certificate.class, userUuid));
            certificate.setUserUuid(null);
            certificateRepository.save(certificate);
        } catch (NotFoundException e) {
            logger.warn("No Certificate found for the user with UUID {}", userUuid);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.MEMBERS)
    public Long statisticsCertificateCount(SecurityFilter filter, boolean includeArchived) {
        setupSecurityFilter(filter);
        if (includeArchived) return certificateRepository.countUsingSecurityFilter(filter);
        final TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> cb.isFalse(root.get(Certificate_.ARCHIVED));
        return certificateRepository.countUsingSecurityFilter(filter, additionalWhereClause);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.MEMBERS)
    public StatisticsDto addCertificateStatistics(SecurityFilter filter, StatisticsDto dto, boolean includeArchived) {
        setupSecurityFilter(filter);

        long start = System.nanoTime();
        final TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = includeArchived ? null : (root, cb, cr) -> cb.isFalse(root.get(Certificate_.ARCHIVED));

        try (ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newVirtualThreadPerTaskExecutor())) {
            List<Future<Void>> futures = executor.invokeAll(List.of(
                    () -> {
                        dto.setCertificateStatByKeySize(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.keySize, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setCertificateStatByType(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.certificateType, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setGroupStatByCertificateCount(certificateRepository.countGroupedUsingSecurityFilter(filter, Certificate_.groups, Group_.name, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setRaProfileStatByCertificateCount(certificateRepository.countGroupedUsingSecurityFilter(filter, Certificate_.raProfile, RaProfile_.name, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setCertificateStatBySubjectType(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.subjectType, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setCertificateStatByState(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.state, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setCertificateStatByValidationStatus(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.validationStatus, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        dto.setCertificateStatByComplianceStatus(certificateRepository.countGroupedUsingSecurityFilter(filter, null, Certificate_.complianceStatus, null, additionalWhereClause));
                        return null;
                    },
                    () -> {
                        Date now = new Date();
                        Instant nowInstant = now.toInstant();
                        final BiFunction<Root<Certificate>, CriteriaBuilder, Expression<?>> groupByExpressionExpiry = (root, cb) -> cb.selectCase()
                                .when(cb.between(root.get(Certificate_.notAfter), cb.literal(now), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(10))))), "10")
                                .when(cb.between(root.get(Certificate_.notAfter), cb.literal(now), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(20))))), "20")
                                .when(cb.between(root.get(Certificate_.notAfter), cb.literal(now), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(30))))), "30")
                                .when(cb.between(root.get(Certificate_.notAfter), cb.literal(now), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(60))))), "60")
                                .when(cb.between(root.get(Certificate_.notAfter), cb.literal(now), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(90))))), "90")
                                .when(cb.greaterThan(root.get(Certificate_.notAfter), cb.literal(Date.from(nowInstant.plus(Duration.ofDays(90))))), "More")
                                .when(cb.isNotNull(root.get(Certificate_.notAfter)), "Expired")
                                .otherwise("Not Issued");

                        dto.setCertificateStatByExpiry(certificateRepository.countGroupedUsingSecurityFilter(filter, null, null, groupByExpressionExpiry, additionalWhereClause));
                        return null;
                    }
            ));
            processFutures(futures);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("Certificate statistics calculation was interrupted", e);
        }
        logger.debug("Certificate statistics calculated in {} ms", (System.nanoTime() - start) / 1_000_000L);
        return dto;
    }

    private static void processFutures(List<Future<Void>> futures) throws InterruptedException {
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (ExecutionException ex) {
                logger.error("An error occurred during calculation of certificate statistics", ex.getCause());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public void checkCreatePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ISSUE)
    public void checkIssuePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.RENEW)
    public void checkRenewPermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.REVOKE)
    public void checkRevokePermissions() {
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ANY)
    public List<BaseAttribute> getCsrGenerationAttributes() {
        return CsrAttributes.csrAttributes();
    }

    @Override
    @Transactional
    public void clearKeyAssociations(UUID keyUuid) {
        certificateRepository.clearKeyAssociations(keyUuid);
        certificateRepository.clearAltKeyAssociations(keyUuid);
    }

    @Override
    @Transactional
    public void bulkClearKeyAssociations(List<UUID> keyUuids) {
        certificateRepository.clearKeyAssociationsIn(keyUuids);
        certificateRepository.clearAltKeyAssociationsIn(keyUuids);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return certificateRepository.findResourceObject(objectUuid, Certificate_.serialNumber);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        Certificate certificate = getCertificateEntity(objectUuid);
        return new NameAndUuidDto(certificate.getUuid(), certificate.getSerialNumber());
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        final TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = getAdditionalWhereClause(filters, false);
        return certificateRepository.listResourceObjects(filter, Certificate_.commonName, additionalWhereClause, pagination);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCertificateEntity(uuid);
    }

    @Override
    public void updateCertificateKeys(UUID keyUuid, String publicKeyFingerprint) {
        for (Certificate certificate : certificateRepository.findByPublicKeyFingerprint(publicKeyFingerprint)) {
            certificate.setKeyUuid(keyUuid);
            certificateRepository.save(certificate);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST)
    public List<CertificateContentDto> getCertificateContent(List<UUID> uuids) {
        List<CertificateContentDto> response = new ArrayList<>();
        for (UUID uuid : uuids) {
            try {
                SecuredUUID securedUUID = SecuredUUID.fromUUID(uuid);
                permissionEvaluator.certificate(securedUUID);
                Certificate certificate = getCertificateEntity(securedUUID);
                CertificateContentDto dto = new CertificateContentDto();
                dto.setUuid(uuid.toString());
                dto.setCommonName(certificate.getCommonName());
                dto.setSerialNumber(certificate.getSerialNumber());
                dto.setCertificateContent(certificate.getCertificateContent().getContent());
                response.add(dto);
            } catch (Exception e) {
                logger.error("Unable to get the certificate content {}. Exception: {}", uuid, e.getMessage());
            }
        }
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateDetailDto submitCertificateRequest(
            String certificateRequest,
            CertificateRequestFormat certificateRequestFormat,
            List<RequestAttribute> signatureAttributes,
            List<RequestAttribute> altSignatureAttributes,
            List<RequestAttribute> csrAttributes,
            List<RequestAttribute> issueAttributes,
            UUID keyUuid,
            UUID altKeyUuid,
            UUID raProfileUuid,
            UUID predecessorCertificateUuid,
            CertificateProtocolInfo protocolInfo
    ) throws NoSuchAlgorithmException, ConnectorException, AttributeException, CertificateRequestException, NotFoundException {
        RaProfile raProfile = raProfileService.getRaProfileEntity(SecuredUUID.fromUUID(raProfileUuid));
        extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, issueAttributes);

        // create certificate request from CSR and parse the data
        byte[] decodedCsr = Base64.getDecoder().decode(certificateRequest);
        CertificateRequest request = CertificateRequestUtils.createCertificateRequest(decodedCsr, certificateRequestFormat);

        Certificate certificate = new Certificate();
        // prepare certificate request data for certificate
        CertificateUtil.prepareCsrObject(certificate, request);

        certificate.setState(CertificateState.REQUESTED);
        certificate.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificate.setCertificateType(CertificateType.X509);
        certificate.setRaProfileUuid(raProfileUuid);

        // find if exists same certificate request by content
        CertificateRequestEntity certificateRequestEntity;

        final String certificateRequestFingerprint = CertificateUtil.getThumbprint(decodedCsr);
        // get the certificate request by fingerprint, if exists
        Optional<CertificateRequestEntity> certificateRequestOptional =
                certificateRequestRepository.findByFingerprint(certificateRequestFingerprint);

        List<ResponseAttribute> requestAttributes;
        List<ResponseAttribute> requestSignatureAttributes;
        List<ResponseAttribute> requestAltSignatureAttributes;
        if (certificateRequestOptional.isPresent()) {
            certificateRequestEntity = certificateRequestOptional.get();
            // if no CSR attributes are assigned to CSR, update them with ones provided
            requestAttributes = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).build()
            );
            requestSignatureAttributes = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build()
            );
            requestAltSignatureAttributes = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build()
            );
            if (requestAttributes.isEmpty() && csrAttributes != null && !csrAttributes.isEmpty()) {
                requestAttributes = attributeEngine.updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).build(), csrAttributes
                );
            }
            if (requestSignatureAttributes.isEmpty() && signatureAttributes != null && !signatureAttributes.isEmpty()) {
                requestSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build(), signatureAttributes
                );
            }

            if (requestAltSignatureAttributes.isEmpty() && altSignatureAttributes != null && !altSignatureAttributes.isEmpty()) {
                requestAltSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build(), altSignatureAttributes
                );
            }
        } else {
            certificateRequestEntity = certificate.prepareCertificateRequest(certificateRequestFormat);
            certificateRequestEntity.setFingerprint(certificateRequestFingerprint);
            certificateRequestEntity.setContent(certificateRequest);
            setCertificateRequestEntitySignatureAlgorithms(request, certificateRequestEntity);
            certificateRequestRepository.save(certificateRequestEntity);

            requestAttributes = attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).build(), csrAttributes
            );
            requestSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build(), signatureAttributes
            );
            requestAltSignatureAttributes = attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificateRequestEntity.getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build(), altSignatureAttributes
            );
        }

        if (keyUuid != null && certificateRequestEntity.getKeyUuid() == null)
            certificateRequestEntity.setKeyUuid(keyUuid);
        else {
            keyUuid = getCertificateRequestKey(certificateRequestEntity, request.getPublicKey());
        }

        setCertificateRequestAltKey(altKeyUuid, certificateRequestEntity, request);

        certificate.setCertificateRequest(certificateRequestEntity);
        certificate.setCertificateRequestUuid(certificateRequestEntity.getUuid());
        certificate.setKeyUuid(keyUuid);
        certificate = certificateRepository.save(certificate);

        if (predecessorCertificateUuid != null)
            associateCertificates(certificate.getUuid(), predecessorCertificateUuid);

        if (protocolInfo != null) {
            setProtocolAssociations(protocolInfo, certificate);
        } else {
            // set owner of certificate to logged user when there is not protocol involved
            objectAssociationService.setOwnerFromProfile(Resource.CERTIFICATE, certificate.getUuid());
        }


        CertificateDetailDto dto = certificate.mapToDto();
        dto.getCertificateRequest().setAttributes(requestAttributes);
        dto.getCertificateRequest().setSignatureAttributes(requestSignatureAttributes);
        dto.getCertificateRequest().setAltSignatureAttributes(requestAltSignatureAttributes);
        dto.setIssueAttributes(attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build(), issueAttributes)
        );
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(), CertificateEvent.REQUEST, CertificateEventStatus.SUCCESS,
                "Certificate request created", ""
        );

        logger.info("Certificate request submitted and certificate created {}", certificate);

        return dto;
    }

    private void setProtocolAssociations(CertificateProtocolInfo protocolInfo, Certificate certificate) throws NotFoundException, AttributeException {
        CertificateProtocolAssociation protocolAssociation = new CertificateProtocolAssociation();
        UUID protocolProfileUuid = protocolInfo.getProtocolProfileUuid();
        protocolAssociation.setCertificate(certificate);
        protocolAssociation.setProtocol(protocolInfo.getProtocol());
        protocolAssociation.setProtocolProfileUuid(protocolProfileUuid);
        protocolAssociation.setAdditionalProtocolUuid(protocolInfo.getAdditionalProtocolUuid());
        certificateProtocolAssociationRepository.save(protocolAssociation);
        certificate.setProtocolAssociation(protocolAssociation);
        ProtocolCertificateAssociations certificateAssociation = switch (protocolInfo.getProtocol()) {
            case ACME -> protocolCertificateAssociationsRepository.findByAcmeProfileUuid(protocolProfileUuid);
            case SCEP -> protocolCertificateAssociationsRepository.findByScepProfileUuid(protocolProfileUuid);
            case CMP -> protocolCertificateAssociationsRepository.findByCmpProfileUuid(protocolProfileUuid);
        };
        if (certificateAssociation != null) {
            if (certificateAssociation.getOwnerUuid() != null)
                updateOwner(certificate.getSecuredUuid(), String.valueOf(certificateAssociation.getOwnerUuid()));
            if (certificateAssociation.getGroupUuids() != null && !certificateAssociation.getGroupUuids().isEmpty())
                updateCertificateGroups(certificate.getSecuredUuid(), new HashSet<>(certificateAssociation.getGroupUuids()));
            if (certificateAssociation.getCustomAttributes() != null && !certificateAssociation.getCustomAttributes().isEmpty())
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), certificateAssociation.getCustomAttributes());
            certificateRepository.save(certificate);
        }
    }

    private void setCertificateRequestAltKey(UUID altKeyUuid, CertificateRequestEntity certificateRequestEntity, CertificateRequest request) throws NoSuchAlgorithmException, CertificateRequestException {
        if (altKeyUuid != null && certificateRequestEntity.getAltKeyUuid() == null) {
            certificateRequestEntity.setAltKeyUuid(altKeyUuid);
            if (request.getAltPublicKey() != null)
                certificateRequestEntity.setAltPublicKeyAlgorithm(CertificateUtil.getKeyAlgorithmStringFromProviderName(request.getAltPublicKey().getAlgorithm()));
        } else if (request.getAltPublicKey() != null) {
            setCertificateRequestAltKey(certificateRequestEntity, request.getAltPublicKey());
        }
    }

    private static void setCertificateRequestEntitySignatureAlgorithms(CertificateRequest request, CertificateRequestEntity certificateRequestEntity) {
        DefaultAlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        if (request.getSignatureAlgorithm() != null)
            certificateRequestEntity.setSignatureAlgorithm(algFinder.getAlgorithmName(request.getSignatureAlgorithm()).replace("WITH", "with"));
        if (request.getAltSignatureAlgorithm() != null)
            certificateRequestEntity.setAltSignatureAlgorithm(algFinder.getAlgorithmName(request.getAltSignatureAlgorithm()).replace("WITH", "with"));
    }

    private UUID getCertificateRequestKey(CertificateRequestEntity certificateRequest, PublicKey csrPublicKey) throws NoSuchAlgorithmException {
        if (certificateRequest.getKeyUuid() != null) return certificateRequest.getKeyUuid();

        String fingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(csrPublicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
        UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
        if (keyUuid == null) {
            keyUuid = cryptographicKeyService.uploadCertificatePublicKey("certKey_" + Objects.requireNonNullElse(certificateRequest.getCommonName(), certificateRequest.getFingerprint()),
                    csrPublicKey, KeySizeUtil.getKeyLength(csrPublicKey), fingerprint);
        }
        certificateRequest.setKeyUuid(keyUuid);
        return keyUuid;
    }

    private void setCertificateRequestAltKey(CertificateRequestEntity certificateRequest, PublicKey csrPublicKey) throws NoSuchAlgorithmException {
        if (certificateRequest.getAltKeyUuid() != null) return;

        String fingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(csrPublicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
        UUID altKeyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
        if (altKeyUuid == null) {
            altKeyUuid = cryptographicKeyService.uploadCertificatePublicKey("altCertKey_" + Objects.requireNonNullElse(certificateRequest.getCommonName(), certificateRequest.getFingerprint()),
                    csrPublicKey, KeySizeUtil.getKeyLength(csrPublicKey), fingerprint);
        }
        certificateRequest.setAltKeyUuid(altKeyUuid);
        certificateRequest.setAltPublicKeyAlgorithm(CertificateUtil.getKeyAlgorithmStringFromProviderName(csrPublicKey.getAlgorithm()));
    }

    @Override
    public CertificateDetailDto issueRequestedCertificate(UUID uuid, String certificateData, List<MetadataAttribute> meta) throws CertificateException, NoSuchAlgorithmException, AlreadyExistException, NotFoundException, AttributeException {
        X509Certificate x509Cert = CertificateUtil.parseCertificate(certificateData);
        String fingerprint = CertificateUtil.getThumbprint(x509Cert);
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }
        Certificate certificate = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        CertificateUtil.prepareIssuedCertificate(certificate, x509Cert);
        CertificateContent certificateContent = checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Cert));
        certificate.setFingerprint(fingerprint);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());

        // if key association is not sent, search in key inventory by fingerprint
        if (certificate.getKeyUuid() == null && certificate.getPublicKeyFingerprint() != null) {
            UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(certificate.getPublicKeyFingerprint());
            certificate.setKeyUuid(keyUuid);
        }

        if (x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()) != null) {
            uploadCertificateKey(null, certificate, x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()));
        }

        certificate = certificateRepository.save(certificate);

        for (CertificateRelation relation : certificate.getPredecessorRelations()) {
            relation.setRelationType(determineRelationType(certificate, relation.getPredecessorCertificate()));
            certificateRelationRepository.save(relation);
        }

        // save metadata
        UUID connectorUuid = certificate.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();

        attributeEngine.updateMetadataAttributes(meta, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorUuid).build());
        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.ISSUE, CertificateEventStatus.SUCCESS, "Issued using RA Profile " + certificate.getRaProfile().getName(), "");

        logger.info("Certificate was successfully issued. {}", certificate.getUuid());

        CertificateDetailDto dto = certificate.mapToDto();
        if (dto.getCertificateRequest() != null) {
            dto.getCertificateRequest().setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).build()));
            dto.getCertificateRequest().setSignatureAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).build()));
            dto.getCertificateRequest().setAltSignatureAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE_REQUEST, certificate.getCertificateRequest().getUuid()).operation(AttributeOperation.CERTIFICATE_REQUEST_SIGN).purpose(AttributeContentPurpose.CERTIFICATE_REQUEST_ALT_KEY).build()));
        }
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).build()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid()));

        // check validity of certificate async from queue
        applicationEventPublisher.publishEvent(new CertificateValidationEvent(certificate.getUuid()));

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public List<CertificateDto> listScepCaCertificates(SecurityFilter filter, boolean intuneEnabled) {
        setupSecurityFilter(filter);
        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(filter, List.of("groups", "owner"),
                CertificateUtil.constructQueryScepCaCertAcceptable(intuneEnabled));
        return certificates.stream().map(Certificate::mapToListDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST, parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.LIST)
    public List<CertificateDto> listCmpSigningCertificates(SecurityFilter filter) {
        setupSecurityFilter(filter);

        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(filter, List.of("groups", "owner"),
                CertificateUtil.constructQueryCmpSigningCertAcceptable());

        return certificates.stream()
                .map(Certificate::mapToListDto).toList();
    }

    @Override
    public int handleExpiringCertificates() {
        List<UUID> expiringCertificates = certificateRepository.findExpiringCertificatesWithoutRenewal();
        for (UUID uuid : expiringCertificates) {
            eventProducer.produceMessage(CertificateExpiringEventHandler.constructEventMessages(uuid));
        }
        return expiringCertificates.size();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ARCHIVE)
    public void archiveCertificate(UUID uuid) throws NotFoundException {
        Certificate certificate = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException("Certificate", uuid));
        certificate.setArchived(true);
        certificateRepository.save(certificate);
        certificateEventHistoryService.addEventHistory(uuid, CertificateEvent.ARCHIVE, CertificateEventStatus.SUCCESS, "Certificate has been archived.", "");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ARCHIVE)
    public void unarchiveCertificate(UUID uuid) throws NotFoundException {
        Certificate certificate = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException("Certificate", uuid));
        certificate.setArchived(false);
        certificateRepository.save(certificate);
        certificateEventHistoryService.addEventHistory(uuid, CertificateEvent.UNARCHIVE, CertificateEventStatus.SUCCESS, "Certificate has been unarchived.", "");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ARCHIVE)
    public void bulkArchiveCertificates(List<UUID> uuids) {
        certificateRepository.archiveCertificates(true, uuids);
        for (UUID uuid : uuids) {
            certificateEventHistoryService.addEventHistory(uuid, CertificateEvent.ARCHIVE, CertificateEventStatus.SUCCESS, "Certificate has been archived.", "");
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.ARCHIVE)
    public void bulkUnarchiveCertificates(List<UUID> uuids) {
        certificateRepository.archiveCertificates(false, uuids);
        for (UUID uuid : uuids) {
            certificateEventHistoryService.addEventHistory(uuid, CertificateEvent.UNARCHIVE, CertificateEventStatus.SUCCESS, "Certificate has been unarchived.", "");
        }
    }

    @Override
    public void updateCertificateDNs(String oid, String newCode, String oldCode) {
        String regex = "([!$()*+.:<=>?\\[\\\\\\]^{|}\\-])";
        String escapedOid = oid.replaceAll(regex, "\\\\$1");
        String escapedOldCode = oldCode.replaceAll(regex, "\\\\$1");

        certificateRepository.updateCertificateIssuerDN(escapedOid, newCode, escapedOldCode);
        certificateRepository.updateCertificateSubjectDN(escapedOid, newCode, escapedOldCode);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public CertificateRelationsDto getCertificateRelations(UUID uuid) throws NotFoundException {
        Certificate certificate = getCertificateEntity(SecuredUUID.fromUUID(uuid));
        CertificateRelationsDto certificateRelationsDto = new CertificateRelationsDto();
        certificateRelationsDto.setCertificateUuid(uuid);
        List<CertificateSimpleDto> successorCertificates = new ArrayList<>();
        for (CertificateRelation successorRelation : certificate.getSuccessorRelations()) {
            successorCertificates.add(successorRelation.getSuccessorCertificate().mapToSimpleDto(successorRelation.getRelationType()));
        }
        certificateRelationsDto.setSuccessorCertificates(successorCertificates);
        List<CertificateSimpleDto> predecessorCertificates = new ArrayList<>();
        for (CertificateRelation predecessorRelation : certificate.getPredecessorRelations()) {
            predecessorCertificates.add(predecessorRelation.getPredecessorCertificate().mapToSimpleDto(predecessorRelation.getRelationType()));
        }
        certificateRelationsDto.setPredecessorCertificates(predecessorCertificates);
        return certificateRelationsDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void associateCertificates(UUID uuid, UUID certificateUuid) throws NotFoundException {
        if (uuid.equals(certificateUuid))
            throw new ValidationException("Cannot associate certificate with itself as successor/predecessor.");
        Certificate certificate = getCertificateEntity(SecuredUUID.fromUUID(uuid));
        Certificate associatedCertificate = getCertificateEntity(SecuredUUID.fromUUID(certificateUuid));

        validateSubjectTypes(certificate, associatedCertificate);

        CertificateRelation certificateRelation = new CertificateRelation();
        CertificateRelationId id = determineCertificateRelationId(certificate, associatedCertificate);
        Certificate successorCertificate = id.getSuccessorCertificateUuid().equals(certificate.getUuid()) ? certificate : associatedCertificate;
        Certificate predecessorCertificate = id.getPredecessorCertificateUuid().equals(certificate.getUuid()) ? certificate : associatedCertificate;

        if (certificateRelationRepository.existsById(id) || certificateRelationRepository.existsById(new CertificateRelationId(id.getPredecessorCertificateUuid(), id.getSuccessorCertificateUuid())))
            throw new ValidationException("Association for certificates %s and %s already exists".formatted(associatedCertificate.getUuid(), certificate.getUuid()));
        if (!(predecessorCertificate.getState() == CertificateState.ISSUED || predecessorCertificate.getState() == CertificateState.REVOKED))
            throw new ValidationException("Certificate %s is not issued or revoked and cannot be a predecessor certificate for certificate %s".formatted(id.getPredecessorCertificateUuid(), id.getSuccessorCertificateUuid()));

        certificateRelation.setId(id);

        CertificateState successorCertificateState = successorCertificate.getState();
        if (successorCertificateState == CertificateState.FAILED || successorCertificateState == CertificateState.REJECTED)
            throw new ValidationException("Certificate %s state is failed or rejected and cannot be a successor certificate for certificate %s".formatted(id.getSuccessorCertificateUuid(), id.getPredecessorCertificateUuid()));
        if (successorCertificateHasBeenIssued(successorCertificateState))
            certificateRelation.setRelationType(determineRelationType(certificate, associatedCertificate));
        else
            certificateRelation.setRelationType(CertificateRelationType.PENDING);

        certificateRelation.setPredecessorCertificate(predecessorCertificate);
        certificateRelation.setSuccessorCertificate(successorCertificate);
        certificateRelationRepository.save(certificateRelation);
        certificateEventHistoryService.addEventHistory(id.getSuccessorCertificateUuid(), CertificateEvent.UPDATE_ENTITY, CertificateEventStatus.SUCCESS, "Predecessor certificate %s has been associated with the certificate by relation type %s".formatted(id.getPredecessorCertificateUuid(), certificateRelation.getRelationType().getLabel()), "");
        certificateEventHistoryService.addEventHistory(id.getPredecessorCertificateUuid(), CertificateEvent.UPDATE_ENTITY, CertificateEventStatus.SUCCESS, "Successor certificate %s has been associated with the certificate by relation type %s".formatted(id.getSuccessorCertificateUuid(), certificateRelation.getRelationType().getLabel()), "");

    }

    private static void validateSubjectTypes(Certificate certificate, Certificate associatedCertificate) {
        if (certificate.getSubjectType() != null && associatedCertificate.getSubjectType() != null) {
            CertificateSubjectType subjectType1 =
                    (certificate.getSubjectType() == CertificateSubjectType.SELF_SIGNED_END_ENTITY)
                            ? CertificateSubjectType.END_ENTITY
                            : certificate.getSubjectType();

            CertificateSubjectType subjectType2 =
                    (associatedCertificate.getSubjectType() == CertificateSubjectType.SELF_SIGNED_END_ENTITY)
                            ? CertificateSubjectType.END_ENTITY
                            : associatedCertificate.getSubjectType();

            if (subjectType1 != subjectType2) {
                throw new ValidationException("Certificate subject types do not match: "
                        + certificate.getSubjectType() + " vs " + associatedCertificate.getSubjectType());
            }
        }
    }

    private static boolean successorCertificateHasBeenIssued(CertificateState successorCertificateState) {
        return successorCertificateState == CertificateState.ISSUED || successorCertificateState == CertificateState.REVOKED;
    }

    private CertificateRelationType determineRelationType(Certificate certificate, Certificate associatedCertificate) {
        if (sameDnsAndIssuerSN(certificate, associatedCertificate)) {
            if (Objects.equals(certificate.getPublicKeyFingerprint(), associatedCertificate.getPublicKeyFingerprint()) && Objects.equals(certificate.getAltKeyFingerprint(), associatedCertificate.getAltKeyFingerprint()))
                return CertificateRelationType.RENEWAL;
            else return CertificateRelationType.REKEY;
        } else {
            return CertificateRelationType.REPLACEMENT;
        }
    }

    private boolean sameDnsAndIssuerSN(Certificate certificate, Certificate sourceCertificate) {
        if (isNotSelfSigned(certificate) && certificate.getIssuerSerialNumber() == null) {
            try {
                updateCertificateChain(certificate);
            } catch (CertificateException e) {
                // Leave issuer SN null
            }
        }
        if (isNotSelfSigned(sourceCertificate) && sourceCertificate.getIssuerSerialNumber() == null) {
            try {
                updateCertificateChain(sourceCertificate);
            } catch (CertificateException e) {
                // Leave issuer SN null
            }
        }
        return Objects.equals(certificate.getIssuerDnNormalized(), sourceCertificate.getIssuerDnNormalized()) && Objects.equals(certificate.getSubjectDnNormalized(), sourceCertificate.getSubjectDnNormalized()) && Objects.equals(certificate.getIssuerSerialNumber(), sourceCertificate.getIssuerSerialNumber());
    }

    private static boolean isNotSelfSigned(Certificate certificate) {
        return certificate.getSubjectType() == CertificateSubjectType.END_ENTITY || certificate.getSubjectType() == CertificateSubjectType.INTERMEDIATE_CA;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void removeCertificateAssociation(UUID uuid, UUID certificateUuid) throws NotFoundException {
        Certificate certificate = getCertificateEntity(SecuredUUID.fromUUID(uuid));
        Certificate associatedCertificate = getCertificateEntity(SecuredUUID.fromUUID(certificateUuid));
        CertificateRelationId id = determineCertificateRelationId(certificate, associatedCertificate);
        if (!certificateRelationRepository.existsById(id)) throw new NotFoundException(CertificateRelation.class, id);
        certificateRelationRepository.deleteById(id);
        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_ENTITY, CertificateEventStatus.SUCCESS, "Certificate %s has been unassociated with the certificate".formatted(associatedCertificate.getUuid()), "");
        certificateEventHistoryService.addEventHistory(associatedCertificate.getUuid(), CertificateEvent.UPDATE_ENTITY, CertificateEventStatus.SUCCESS, "Certificate %s has been unassociated with the certificate".formatted(certificate.getUuid()), "");
    }

    private CertificateRelationId determineCertificateRelationId(Certificate certificate, Certificate associatedCertificate) {
        Date certNotBefore = certificate.getNotBefore();
        Date assocNotBefore = associatedCertificate.getNotBefore();
        // Decide which certificate is predecessor, if the first certificate was issued before the second, then it is predecessor certificate
        UUID predecessorUuid = associatedCertificate.getUuid();
        UUID successorUuid = certificate.getUuid();
        if (certNotBefore != null && assocNotBefore != null && certNotBefore.before(assocNotBefore)) {
            predecessorUuid = certificate.getUuid();
            successorUuid = associatedCertificate.getUuid();
        }
        return new CertificateRelationId(successorUuid, predecessorUuid);
    }

    private void certificateComplianceCheck(Certificate certificate) {
        if (certificate.getRaProfile() != null) {
            try {
                complianceService.checkResourceObjectComplianceAsync(Resource.CERTIFICATE, certificate.getUuid());
            } catch (Exception e) {
                logger.debug("Error when checking compliance: {}", e.getMessage());
            }
        }
    }

    private List<String> downloadChainFromAia(Certificate certificate, X509Certificate certX509) {
        List<String> chainCertificates = new ArrayList<>();
        String chainUrl;
        try {
            while (true) {
                chainUrl = OcspUtil.getChainFromAia(certX509);
                if (chainUrl == null || chainUrl.isEmpty()) {
                    break;
                }
                String chainContent = downloadChain(chainUrl);
                if (chainContent.isEmpty()) {
                    break;
                }
                logger.info("Certificate {} downloaded from Authority Information Access extension URL {}", certX509.getSubjectX500Principal().getName(), chainUrl);

                chainCertificates.add(chainContent);
                certX509 = getX509(chainContent);

                // if self-signed, do not attempt to download itself
                if (verifySignature(certX509, certX509)) {
                    break;
                }
            }
        } catch (Exception e) {
            logger.debug("Unable to get the chain of certificate {} from Authority Information Access", certificate.getUuid(), e);
        }
        return chainCertificates;
    }

    private String downloadChain(String chainUrl) {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate cert;
            // Handle ldap protocol

            if (chainUrl.startsWith("ldap://") || chainUrl.startsWith("ldaps://")) {
                byte[] certificate = LdapUtils.downloadFromLdap(chainUrl);
                if (certificate == null) return "";
                cert = (X509Certificate) fac.generateCertificate(new ByteArrayInputStream(certificate));
            } else {
                URL url = URI.create(chainUrl).toURL();
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(1000);
                urlConnection.setReadTimeout(1000);
                try (InputStream in = url.openStream()) {
                    cert = (X509Certificate) fac.generateCertificate(in);
                } catch (Exception e) {
                    logger.error(e.getMessage());
                    return "";
                }
            }
            final StringWriter writer = new StringWriter();
            final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.close();
            writer.close();

            return writer.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return "";
    }

    public void switchRaProfile(SecuredUUID uuid, SecuredUUID raProfileUuid) throws NotFoundException, CertificateOperationException, AttributeException {
        Certificate certificate = getCertificateEntity(uuid);
        if (certificate.isArchived()) {
            throw new ValidationException("Certificate with UUID %s is archived and its RA Profile cannot be updated.".formatted(uuid));
        }

        // check if there is change in RA profile compared to current state
        if ((raProfileUuid == null && certificate.getRaProfileUuid() == null) || (raProfileUuid != null && certificate.getRaProfileUuid() != null) && certificate.getRaProfileUuid().toString().equals(raProfileUuid.toString())) {
            return;
        }

        // removing RA profile
        RaProfile newRaProfile = null;
        RaProfile currentRaProfile = certificate.getRaProfile();
        String newRaProfileName = UNDEFINED_CERTIFICATE_OBJECT_NAME;
        String currentRaProfileName = currentRaProfile != null ? currentRaProfile.getName() : UNDEFINED_CERTIFICATE_OBJECT_NAME;
        CertificateIdentificationResponseDto response = null;
        if (raProfileUuid != null) {
            newRaProfile = raProfileRepository.findByUuid(raProfileUuid).orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
            newRaProfileName = newRaProfile.getName();

            // identify certificate by new authority
            CertificateIdentificationRequestDto requestDto = new CertificateIdentificationRequestDto();
            requestDto.setCertificate(certificate.getCertificateContent().getContent());
            requestDto.setRaProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, newRaProfile.getUuid()).connector(newRaProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));
            try {
                var connectorDto = newRaProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
                response = connectorApiFactory.getCertificateApiClientV2(connectorDto).identifyCertificate(connectorDto, newRaProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), requestDto);
            } catch (ConnectorException e) {
                applicationEventPublisher.publishEvent(new UpdateCertificateHistoryEvent(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.FAILED, String.format("Certificate not identified by authority of new RA profile %s. Certificate needs to be reissued.", newRaProfile.getName()), null));
                throw new CertificateOperationException(String.format("Cannot switch RA profile for certificate. Certificate not identified by authority of new RA profile %s. Certificate: %s", newRaProfile.getName(), certificate.toStringShort()));
            } catch (ValidationException e) {
                applicationEventPublisher.publishEvent(new UpdateCertificateHistoryEvent(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.FAILED, String.format("Certificate identified by authority of new RA profile %s but not valid according to RA profile attributes. Certificate needs to be reissued.", newRaProfile.getName()), null));
                throw new CertificateOperationException(String.format("Cannot switch RA profile for certificate. Certificate identified by authority of new RA profile %s but not valid according to RA profile attributes. Certificate: %s", newRaProfile.getName(), certificate.toStringShort()));
            }
        }

        certificate.setRaProfile(newRaProfile);
        certificateRepository.save(certificate);

        // delete old metadata
        if (currentRaProfile != null) {
            attributeEngine.deleteObjectAttributesContent(AttributeType.META, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(currentRaProfile.getAuthorityInstanceReference().getConnectorUuid()).build());
        }

        // save metadata for identified certificate and run compliance
        if (newRaProfile != null) {
            UUID connectorUuid = newRaProfile.getAuthorityInstanceReference().getConnectorUuid();
            attributeEngine.updateMetadataAttributes(response.getMeta(), ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(connectorUuid).build());

            try {
                complianceService.checkResourceObjectComplianceAsync(Resource.CERTIFICATE, certificate.getUuid());
            } catch (Exception e) {
                logger.error("Error when checking compliance:", e);
            }
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_RA_PROFILE, CertificateEventStatus.SUCCESS, currentRaProfileName + " -> " + newRaProfileName, "");
    }

    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateCertificateGroups(SecuredUUID uuid, Set<UUID> groupUuids) throws NotFoundException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);

        if (certificate.isArchived()) {
            throw new ValidationException("Certificate with UUID %s is archived and its groups cannot be updated.".formatted(uuid));
        }

        if (groupUuids == null) {
            groupUuids = new HashSet<>();
        }

        // check if there is change in group compared to current state
        Set<UUID> currentGroups = certificate.getGroups().stream().map(Group::getUuid).collect(Collectors.toSet());
        if (currentGroups.equals(groupUuids)) {
            return;
        }

        String currentGroupNames = certificate.getGroups().isEmpty() ? UNDEFINED_CERTIFICATE_OBJECT_NAME : String.join(", ", certificate.getGroups().stream().map(Group::getName).toList());
        Set<Group> newGroups = objectAssociationService.setGroups(Resource.CERTIFICATE, certificate.getUuid(), groupUuids);
        String newGroupNames = newGroups.isEmpty() ? UNDEFINED_CERTIFICATE_OBJECT_NAME : String.join(", ", newGroups.stream().map(Group::getName).toList());

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_GROUP, CertificateEventStatus.SUCCESS, currentGroupNames + " -> " + newGroupNames, "");
    }

    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.UPDATE)
    public void updateOwner(SecuredUUID uuid, String ownerUuid) throws NotFoundException {
        Certificate certificate = getCertificateEntityWithAssociations(uuid);

        if (certificate.isArchived()) {
            throw new ValidationException("Certificate with UUID %s is archived and its owner cannot be updated.".formatted(uuid));
        }

        // if there is no change, do not update and save request to Auth service
        if ((ownerUuid == null && certificate.getOwner() == null) || (ownerUuid != null && certificate.getOwner() != null) && certificate.getOwner().getUuid().equals(UUID.fromString(ownerUuid))) {
            return;
        }

        UUID newOwnerUuid = ownerUuid == null ? null : UUID.fromString(ownerUuid);
        String currentOwnerName = certificate.getOwner() == null ? UNDEFINED_CERTIFICATE_OBJECT_NAME : certificate.getOwner().getOwnerUsername();

        String newOwnerName = UNDEFINED_CERTIFICATE_OBJECT_NAME;
        if (newOwnerUuid == null) certificate.setOwner(null);
        certificateRepository.save(certificate);
        NameAndUuidDto newOwner = objectAssociationService.setOwner(Resource.CERTIFICATE, uuid.getValue(), newOwnerUuid);
        if (newOwner != null) {
            newOwnerName = newOwner.getName();
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPDATE_OWNER, CertificateEventStatus.SUCCESS, "%s -> %s".formatted(currentOwnerName, newOwnerName == null ? UNDEFINED_CERTIFICATE_OBJECT_NAME : newOwnerName), "");
    }

    private void setupSecurityFilter(SecurityFilter filter) {
        filter.setParentRefProperty(Certificate_.raProfileUuid.getName());
    }

    private ICertificateValidator getCertificateValidator(CertificateType certificateType) {
        ICertificateValidator certificateValidator = certificateValidatorMap.get(certificateType.getCode());
        if (certificateValidator == null) {
            throw new ValidationException("Unsupported certificate type validator for certificate type " + certificateType.getLabel());
        }
        return certificateValidator;
    }

    @Override
    public ResourceObjectContentData getResourceObjectContent(UUID uuid) throws NotFoundException, AttributeException {
        ResourceCertificateContentData contentData = new ResourceCertificateContentData();
        contentData.setCertificateType(CertificateType.X509);
        Certificate certificate = getCertificateEntity(SecuredUUID.fromUUID(uuid));
        if (certificate.getCertificateContent() == null)
            throw new AttributeException("Certificate without content cannot be set as resource object in attribute.");
        contentData.setContent(certificate.getCertificateContent().getContent());
        return contentData;
    }

}
