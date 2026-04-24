package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.connector.compliance.v2.ComplianceRuleResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.ComplianceRuleStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.evaluator.TriggerEvaluator;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.compliance.*;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.ComplianceService;
import com.czertainly.core.service.handler.ComplianceProfileRuleHandler;
import com.czertainly.core.service.handler.ComplianceSubjectHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class ComplianceServiceImpl implements ComplianceService {

    private static final Logger logger = LoggerFactory.getLogger(ComplianceServiceImpl.class);
    private static final String COMPLIANCE_CHECK_VALIDATION_INVALID_RESOURCE_MESSAGE = "Cannot check compliance for resource %s. Resource does not support compliance check";

    private ConnectorApiFactory connectorApiFactory;

    private ComplianceProfileRepository complianceProfileRepository;
    private ComplianceProfileAssociationRepository complianceProfileAssociationRepository;
    private ComplianceInternalRuleRepository internalRuleRepository;

    private CertificateRepository certificateRepository;
    private CertificateRequestRepository certificateRequestRepository;
    private CryptographicKeyRepository cryptographicKeyRepository;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private SecretRepository secretRepository;

    // since only checking condition items, not necessary CertificateTriggerEvaluator that implements special logic for setting properties
    private TriggerEvaluator<Certificate> certificateTriggerEvaluator;
    private TriggerEvaluator<CertificateRequestEntity> certificateRequestTriggerEvaluator;
    private TriggerEvaluator<CryptographicKeyItem> cryptographicKeyItemTriggerEvaluator;
    private TriggerEvaluator<Secret> secretTriggerEvaluator;

    private ComplianceProfileRuleHandler ruleHandler;

    private EventProducer eventProducer;

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setComplianceProfileRepository(ComplianceProfileRepository complianceProfileRepository) {
        this.complianceProfileRepository = complianceProfileRepository;
    }

    @Autowired
    public void setComplianceProfileAssociationRepository(ComplianceProfileAssociationRepository complianceProfileAssociationRepository) {
        this.complianceProfileAssociationRepository = complianceProfileAssociationRepository;
    }

    @Autowired
    public void setInternalRuleRepository(ComplianceInternalRuleRepository internalRuleRepository) {
        this.internalRuleRepository = internalRuleRepository;
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
    public void setCryptographicKeyRepository(CryptographicKeyRepository cryptographicKeyRepository) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
    }

    @Autowired
    public void setCryptographicKeyItemRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Lazy
    @Autowired
    public void setCertificateTriggerEvaluator(TriggerEvaluator<Certificate> certificateTriggerEvaluator) {
        this.certificateTriggerEvaluator = certificateTriggerEvaluator;
    }

    @Autowired
    public void setCertificateRequestTriggerEvaluator(TriggerEvaluator<CertificateRequestEntity> certificateRequestTriggerEvaluator) {
        this.certificateRequestTriggerEvaluator = certificateRequestTriggerEvaluator;
    }

    @Autowired
    public void setCryptographicKeyItemTriggerEvaluator(TriggerEvaluator<CryptographicKeyItem> cryptographicKeyItemTriggerEvaluator) {
        this.cryptographicKeyItemTriggerEvaluator = cryptographicKeyItemTriggerEvaluator;
    }

    @Autowired
    public void setSecretTriggerEvaluator(TriggerEvaluator<Secret> secretTriggerEvaluator) {
        this.secretTriggerEvaluator = secretTriggerEvaluator;
    }

    @Autowired
    public void setRuleHandler(ComplianceProfileRuleHandler ruleHandler) {
        this.ruleHandler = ruleHandler;
    }

    @Override
    public ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid) throws NotFoundException {
        logger.debug("Get Compliance Check Result called for resource={} uuid={}", resource.getLabel(), objectUuid);
        if (!resource.complianceSubject() && resource != Resource.CRYPTOGRAPHIC_KEY_ITEM) {
            throw new ValidationException("Cannot get compliance result for resource %s. Resource does not support compliance check".formatted(resource.getLabel()));
        }

        ComplianceSubject complianceSubject = switch (resource) {
            case CERTIFICATE ->
                    certificateRepository.findByUuid(objectUuid).orElseThrow(() -> new NotFoundException(Certificate.class, objectUuid));
            case CERTIFICATE_REQUEST ->
                    certificateRequestRepository.findByUuid(objectUuid).orElseThrow(() -> new NotFoundException(CertificateRequestEntity.class, objectUuid));
            case CRYPTOGRAPHIC_KEY_ITEM ->
                    cryptographicKeyItemRepository.findByUuid(objectUuid).orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, objectUuid));
            case SECRET ->
                    secretRepository.findByUuid(objectUuid).orElseThrow(() -> new NotFoundException(Secret.class, objectUuid));
            default ->
                    throw new ValidationException("Cannot get compliance result for resource %s. Resource does not support compliance check".formatted(resource.getLabel()));
        };

        return getComplianceCheckResult(resource, objectUuid, complianceSubject.getComplianceResult());
    }

    @Override
    public ComplianceCheckResultDto getComplianceCheckResult(Resource resource, UUID objectUuid, ComplianceResultDto complianceResult) {
        ComplianceCheckResultDto resultDto = new ComplianceCheckResultDto();
        if (complianceResult == null) {
            resultDto.setStatus(ComplianceStatus.NOT_CHECKED);
            return resultDto;
        }
        if (complianceResult.getProviderRules() == null) {
            complianceResult.setProviderRules(new ArrayList<>());
        }

        resultDto.setStatus(complianceResult.getStatus());
        resultDto.setMessage(complianceResult.getMessage());
        resultDto.setTimestamp(complianceResult.getTimestamp());
        // load internal rules
        if (complianceResult.getInternalRules() != null) {
            List<UUID> failedInternalRulesUuids = new ArrayList<>(complianceResult.getInternalRules().getNotCompliant());
            failedInternalRulesUuids.addAll(complianceResult.getInternalRules().getNotApplicable());
            failedInternalRulesUuids.addAll(complianceResult.getInternalRules().getNotAvailable());
            internalRuleRepository.findByUuidIn(failedInternalRulesUuids).forEach(internalRule -> {
                ComplianceRuleStatus status = getFailedRuleStatus(complianceResult.getInternalRules(), internalRule.getUuid());
                resultDto.getFailedRules().add(internalRule.mapToComplianceCheckRuleDto(status));
            });
        }

        // load provider rules
        for (ComplianceResultProviderRulesDto providerRules : complianceResult.getProviderRules()) {
            Set<UUID> failedProviderRulesUuids = new HashSet<>(providerRules.getNotCompliant());
            failedProviderRulesUuids.addAll(providerRules.getNotApplicable());
            failedProviderRulesUuids.addAll(providerRules.getNotAvailable());
            ComplianceRulesGroupsBatchDto batchDto = null;
            try {
                batchDto = ruleHandler.getComplianceProviderRulesBatch(providerRules.getConnectorUuid(), providerRules.getKind(), failedProviderRulesUuids, null, false);
            } catch (Exception e) {
                logger.warn("Cannot retrieve compliance rules from provider {} of kind {} when getting compliance result rules of {} with UUID {}. Marking all {} rules as Not Available", providerRules.getConnectorUuid(), providerRules.getKind(), resource, objectUuid, failedProviderRulesUuids.size());
                batchDto = new ComplianceRulesGroupsBatchDto();
                batchDto.setConnectorUuid(providerRules.getConnectorUuid());
                batchDto.setKind(providerRules.getKind());
            }

            for (UUID failedRuleUuid : failedProviderRulesUuids) {
                ComplianceRuleStatus status = getFailedRuleStatus(providerRules, failedRuleUuid);
                ComplianceRuleResponseDto providerRule = batchDto.getRules().get(failedRuleUuid);
                resultDto.getFailedRules().add(ruleHandler.mapComplianceCheckProviderRuleDto(batchDto.getConnectorUuid(), batchDto.getConnectorName(), batchDto.getKind(), failedRuleUuid, status, providerRule));
            }
        }

        return resultDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkComplianceValidation(List<SecuredUUID> uuids, Resource resource, String type) throws ValidationException, NotFoundException {
        if (resource != null) {
            if (!resource.complianceSubject()) {
                throw new ValidationException(COMPLIANCE_CHECK_VALIDATION_INVALID_RESOURCE_MESSAGE.formatted(resource.getLabel()));
            }
            ComplianceProfileRuleHandler.getComplianceRuleTypeFromCode(resource, type);
        } else if (type != null) {
            throw new ValidationException("Cannot check compliance for type %s. Resource must be specified when type is specified".formatted(type));
        }

        for (SecuredUUID uuid : uuids) {
            if (!complianceProfileRepository.existsById(uuid.getValue())) {
                throw new NotFoundException("Cannot check compliance. Compliance profile with UUID %s not found".formatted(uuid.getValue()));
            }
        }
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkComplianceAsync(List<SecuredUUID> uuids, Resource resource, String type) {
        logger.debug("CheckComplianceAsync for {} profiles resource={} type={}", uuids.size(), resource, type);
        checkCompliance(uuids, resource, type);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkCompliance(List<SecuredUUID> uuids, Resource resource, String type) {
        logger.info("Starting compliance check for {} profiles resource={} type={}", uuids.size(), resource, type);
        IPlatformEnum typeEnum = null;
        if (resource != null) {
            if (!resource.complianceSubject()) {
                throw new ValidationException(COMPLIANCE_CHECK_VALIDATION_INVALID_RESOURCE_MESSAGE.formatted(resource.getLabel()));
            }
            typeEnum = ComplianceProfileRuleHandler.getComplianceRuleTypeFromCode(resource, type);
        } else if (type != null) {
            throw new ValidationException("Cannot check compliance for type %s. Resource must be specified when type is specified".formatted(type));
        }

        // load compliance profiles
        ComplianceCheckContext context = new ComplianceCheckContext(resource, typeEnum, ruleHandler, getSubjectHandlers(true), connectorApiFactory, eventProducer);
        List<ComplianceProfile> complianceProfiles = complianceProfileRepository.findWithAssociationsByUuidIn(uuids.stream().map(SecuredUUID::getValue).toList()).stream()
                .filter(p -> !p.getAssociations().isEmpty() && !p.getComplianceRules().isEmpty()).toList();
        logger.debug("Loaded {} compliance profiles to be checked", complianceProfiles.size());
        for (ComplianceProfile profile : complianceProfiles) {
            // load compliance subjects
            Map<Resource, Set<ComplianceSubject>> complianceSubjects = new EnumMap<>(Resource.class);
            for (ComplianceProfileAssociation association : profile.getAssociations()) {
                if (!isAssociationResourceCompatible(association.getResource(), resource)) {
                    logger.debug("Skipping association resource {} for requested resource {}", association.getResource(), resource);
                    continue;
                }

                List<ComplianceSubject> subjects = getComplianceSubjects(association.getResource(), association.getObjectUuid());
                if (!subjects.isEmpty()) {
                    complianceSubjects.computeIfAbsent(getSubjectResouceByAssociationResource(association.getResource()), r -> new HashSet<>()).addAll(subjects);
                }
            }

            // if no subjects found for any association, skip the profile
            if (complianceSubjects.isEmpty()) {
                logger.debug("No subjects found for compliance profile {}, skipping", profile.getUuid());
                continue;
            }
            logger.debug("Adding compliance profile {} with {} subject resource entries", profile.getUuid(), complianceSubjects.size());
            context.addComplianceProfile(profile, complianceSubjects);
        }
        context.performComplianceCheck();
        logger.info("Completed compliance check for provided profiles");
    }

    @Override
    public void checkResourceObjectsComplianceValidation(Resource resource, List<UUID> objectUuids) throws ValidationException, NotFoundException {
        if (resource == Resource.CERTIFICATE_REQUEST || (!resource.complianceSubject() && !resource.hasComplianceProfiles() && resource != Resource.CRYPTOGRAPHIC_KEY_ITEM)) {
            throw new ValidationException("Cannot check compliance for resource %s. Resource does not support compliance check or does not allow association of compliance profiles".formatted(resource.getLabel()));
        }

        for (UUID objectUuid : objectUuids) {
            boolean exists = switch (resource) {
                case CERTIFICATE -> certificateRepository.existsById(objectUuid);
                case CRYPTOGRAPHIC_KEY -> cryptographicKeyRepository.existsById(objectUuid);
                case CRYPTOGRAPHIC_KEY_ITEM -> cryptographicKeyItemRepository.existsById(objectUuid);
                case SECRET -> secretRepository.existsById(objectUuid);
                case RA_PROFILE ->
                        complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.RA_PROFILE, objectUuid) > 0;
                case TOKEN_PROFILE ->
                        complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.TOKEN_PROFILE, objectUuid) > 0;
                case VAULT_PROFILE ->
                    complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.VAULT_PROFILE, objectUuid) > 0;
                default ->
                        throw new ValidationException(COMPLIANCE_CHECK_VALIDATION_INVALID_RESOURCE_MESSAGE.formatted(resource.getLabel()));
            };
            if (!exists) {
                throw new NotFoundException("Cannot check compliance. %s with UUID %s not found".formatted(resource.getLabel(), objectUuid));
            }
        }
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkResourceObjectComplianceAsync(Resource resource, UUID objectUuid) {
        checkResourceObjectsComplianceAsync(resource, List.of(objectUuid));
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkResourceObjectCompliance(Resource resource, UUID objectUuid) {
        checkResourceObjectsComplianceAsync(resource, List.of(objectUuid));
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void checkResourceObjectComplianceAsSystem(Resource resource, UUID objectUuid) {
        checkResourceObjectsComplianceAsync(resource, List.of(objectUuid));
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.CHECK_COMPLIANCE)
    public void checkResourceObjectsComplianceAsync(Resource resource, List<UUID> objectUuids) {
        logger.info("Starting compliance check for resource={} objectCount={}", resource, objectUuids.size());
        if (resource == Resource.CERTIFICATE_REQUEST || (!resource.complianceSubject() && !resource.hasComplianceProfiles() && resource != Resource.CRYPTOGRAPHIC_KEY_ITEM)) {
            throw new ValidationException("Cannot check compliance for resource %s. Resource does not support compliance check or does not allow association of compliance profiles".formatted(resource.getLabel()));
        }

        Map<UUID, ComplianceProfile> complianceProfilesMap = new HashMap<>();
        Map<UUID, Map<Resource, Set<ComplianceSubject>>> complianceProfileSubjectsMap = new HashMap<>();
        loadComplianceProfilesFromComplianceSubjects(resource, objectUuids, complianceProfilesMap, complianceProfileSubjectsMap);

        ComplianceCheckContext context = new ComplianceCheckContext(null, null, ruleHandler, getSubjectHandlers(false), connectorApiFactory, eventProducer);
        for (ComplianceProfile profile : complianceProfilesMap.values()) {
            context.addComplianceProfile(profile, complianceProfileSubjectsMap.get(profile.getUuid()));
        }
        context.performComplianceCheck();
        logger.info("Completed compliance check for resource {} on {} objects", resource, objectUuids.size());
    }

    private void loadComplianceProfilesFromComplianceSubjects(Resource resource, List<UUID> objectUuids, Map<UUID, ComplianceProfile> complianceProfilesMap, Map<UUID, Map<Resource, Set<ComplianceSubject>>> complianceProfileSubjectsMap) {
        switch (resource) {
            case CERTIFICATE -> {
                List<Certificate> certificates = certificateRepository.findByUuidInAndArchivedFalse(objectUuids);
                for (Certificate certificate : certificates) {
                    ComplianceSubject subject = certificate.getCertificateContentId() != null ? certificate : certificate.getCertificateRequestEntity();
                    if (certificate.getRaProfileUuid() == null || subject == null) continue;

                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.RA_PROFILE, certificate.getRaProfileUuid(), certificate.getCertificateContentId() != null ? Resource.CERTIFICATE : Resource.CERTIFICATE_REQUEST, List.of(subject));
                }
            }
            case CRYPTOGRAPHIC_KEY -> {
                List<CryptographicKey> keys = cryptographicKeyRepository.findByUuidIn(objectUuids);
                for (CryptographicKey key : keys) {
                    if (key.getTokenProfileUuid() == null) continue;
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.TOKEN_PROFILE, key.getTokenProfileUuid(), Resource.CRYPTOGRAPHIC_KEY, new ArrayList<>(key.getItems()));
                }
            }
            case CRYPTOGRAPHIC_KEY_ITEM -> {
                List<CryptographicKeyItem> keyItems = cryptographicKeyItemRepository.findByUuidIn(objectUuids);
                for (CryptographicKeyItem keyItem : keyItems) {
                    if (keyItem.getKey() == null || keyItem.getKey().getTokenProfileUuid() == null) continue;
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.TOKEN_PROFILE, keyItem.getKey().getTokenProfileUuid(), Resource.CRYPTOGRAPHIC_KEY, List.of(keyItem));
                }
            }
            case SECRET -> {
                List<Secret> secrets = secretRepository.findByUuidIn(objectUuids);
                for (Secret secret : secrets) {
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.VAULT_PROFILE, secret.getSourceVaultProfileUuid(), Resource.SECRET, List.of(secret));
                }
            }
            case RA_PROFILE -> {
                for (UUID associationObjectUuid : objectUuids) {
                    if (complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.RA_PROFILE, associationObjectUuid) == 0) {
                        continue;
                    }
                    List<Certificate> certificates = certificateRepository.findByRaProfileUuidAndCertificateContentIdNotNullAndArchivedFalse(associationObjectUuid);
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.RA_PROFILE, associationObjectUuid, Resource.CERTIFICATE, new ArrayList<>(certificates));
                }
            }
            case TOKEN_PROFILE -> {
                for (UUID associationObjectUuid : objectUuids) {
                    if (complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.TOKEN_PROFILE, associationObjectUuid) == 0) {
                        continue;
                    }
                    List<CryptographicKeyItem> keyItems = cryptographicKeyItemRepository.findByKeyTokenProfileUuid(associationObjectUuid);
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.TOKEN_PROFILE, associationObjectUuid, Resource.CRYPTOGRAPHIC_KEY, new ArrayList<>(keyItems));
                }
            }
            case VAULT_PROFILE -> {
                for (UUID associationObjectUuid : objectUuids) {
                    if (complianceProfileAssociationRepository.countByResourceAndObjectUuid(Resource.VAULT_PROFILE, associationObjectUuid) == 0) {
                        continue;
                    }
                    List<Secret> secrets = secretRepository.findBySourceVaultProfileUuid(associationObjectUuid);
                    loadComplianceProfilesWithSubjects(complianceProfilesMap, complianceProfileSubjectsMap, Resource.VAULT_PROFILE, associationObjectUuid, Resource.SECRET, new ArrayList<>(secrets));
                }
            }
            default ->
                    throw new ValidationException(COMPLIANCE_CHECK_VALIDATION_INVALID_RESOURCE_MESSAGE.formatted(resource.getLabel()));
        }
    }

    private ComplianceRuleStatus getFailedRuleStatus(ComplianceResultRulesDto complianceResultRules, UUID ruleUuid) {
        if (complianceResultRules.getNotCompliant().contains(ruleUuid)) {
            return ComplianceRuleStatus.NOK;
        } else if (complianceResultRules.getNotApplicable().contains(ruleUuid)) {
            return ComplianceRuleStatus.NA;
        } else if (complianceResultRules.getNotAvailable().contains(ruleUuid)) {
            return ComplianceRuleStatus.NOT_AVAILABLE;
        }
        return ComplianceRuleStatus.NOT_AVAILABLE;
    }

    private void loadComplianceProfilesWithSubjects(Map<UUID, ComplianceProfile> complianceProfilesMap, Map<UUID, Map<Resource, Set<ComplianceSubject>>> complianceProfileSubjectsMap, Resource resource, UUID associationObjectUuid, Resource subjectResource, Collection<ComplianceSubject> complianceSubjects) {
        List<ComplianceProfile> complianceProfiles = complianceProfileAssociationRepository.findDistinctByResourceAndObjectUuid(resource, associationObjectUuid).stream().map(ComplianceProfileAssociation::getComplianceProfile).toList();
        for (ComplianceProfile profile : complianceProfiles) {
            complianceProfilesMap.putIfAbsent(profile.getUuid(), profile);
            complianceProfileSubjectsMap.computeIfAbsent(profile.getUuid(), k -> new EnumMap<>(Resource.class))
                    .computeIfAbsent(subjectResource, r -> new HashSet<>())
                    .addAll(complianceSubjects);
        }
    }

    private boolean isAssociationResourceCompatible(Resource associationResource, Resource resource) {
        if (resource == null) {
            return true;
        }

        return switch (resource) {
            case CERTIFICATE, CERTIFICATE_REQUEST ->
                    associationResource == Resource.CERTIFICATE || associationResource == Resource.CERTIFICATE_REQUEST || associationResource == Resource.RA_PROFILE;
            case CRYPTOGRAPHIC_KEY, CRYPTOGRAPHIC_KEY_ITEM ->
                    associationResource == Resource.CRYPTOGRAPHIC_KEY || associationResource == Resource.CRYPTOGRAPHIC_KEY_ITEM || associationResource == Resource.TOKEN_PROFILE;
            case SECRET ->
                    associationResource == Resource.VAULT_PROFILE || associationResource == Resource.SECRET;
            default -> false;
        };
    }

    private Resource getSubjectResouceByAssociationResource(Resource associationResource) {
        return switch (associationResource) {
            case CERTIFICATE, RA_PROFILE -> Resource.CERTIFICATE;
            case CERTIFICATE_REQUEST -> Resource.CERTIFICATE_REQUEST;
            case CRYPTOGRAPHIC_KEY, CRYPTOGRAPHIC_KEY_ITEM, TOKEN_PROFILE -> Resource.CRYPTOGRAPHIC_KEY;
            case SECRET, VAULT_PROFILE -> Resource.SECRET;
            default ->
                    throw new ValidationException("Cannot determine compliance subject resource for association resource %s".formatted(associationResource.getLabel()));
        };
    }

    private <T extends ComplianceSubject> List<T> getComplianceSubjects(Resource associationResource, UUID associationObjectUuid) {
        // Filter by access control or if user can check compliance, allow listing of objects as subjects for compliance check?
        return (List<T>) switch (associationResource) {
            case CERTIFICATE ->
                    certificateRepository.findByUuidInAndCertificateContentIdNotNullAndArchivedFalse(List.of(associationObjectUuid));
            case CERTIFICATE_REQUEST ->
                    certificateRequestRepository.findByUuidIn(List.of(associationObjectUuid)).map(List::of).orElse(List.of());
            case CRYPTOGRAPHIC_KEY -> cryptographicKeyItemRepository.findByKeyUuidIn(List.of(associationObjectUuid));
            case CRYPTOGRAPHIC_KEY_ITEM ->
                    cryptographicKeyItemRepository.findByUuid(associationObjectUuid).map(List::of).orElse(List.of());
            case SECRET -> secretRepository.findByUuidIn(List.of(associationObjectUuid));
            case RA_PROFILE ->
                    certificateRepository.findByRaProfileUuidAndCertificateContentIdNotNullAndArchivedFalse(associationObjectUuid);
            case TOKEN_PROFILE -> cryptographicKeyItemRepository.findByKeyTokenProfileUuid(associationObjectUuid);
            case VAULT_PROFILE -> secretRepository.findBySourceVaultProfileUuid(associationObjectUuid);
            default -> List.of();
        };
    }

    private Map<Resource, ComplianceSubjectHandler<? extends ComplianceSubject>> getSubjectHandlers(boolean checkByProfiles) {
        Map<Resource, ComplianceSubjectHandler<? extends ComplianceSubject>> map = new EnumMap<>(Resource.class);
        map.put(Resource.CERTIFICATE, new ComplianceSubjectHandler<>(checkByProfiles, Resource.CERTIFICATE, certificateTriggerEvaluator, certificateRepository));
        map.put(Resource.CERTIFICATE_REQUEST, new ComplianceSubjectHandler<>(checkByProfiles, Resource.CERTIFICATE_REQUEST, certificateRequestTriggerEvaluator, certificateRequestRepository));
        map.put(Resource.CRYPTOGRAPHIC_KEY, new ComplianceSubjectHandler<>(checkByProfiles, Resource.CRYPTOGRAPHIC_KEY_ITEM, cryptographicKeyItemTriggerEvaluator, cryptographicKeyItemRepository));
        map.put(Resource.SECRET, new ComplianceSubjectHandler<>(checkByProfiles, Resource.SECRET, secretTriggerEvaluator, secretRepository));

        return map;
    }
}
