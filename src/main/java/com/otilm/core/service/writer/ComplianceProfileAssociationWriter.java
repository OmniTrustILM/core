package com.otilm.core.service.writer;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.service.ResourceInternalService;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * An association names its object without a foreign key, so whoever deletes the object removes its associations, in the
 * transaction of the delete.
 */
@Service
public class ComplianceProfileAssociationWriter {

    private final ComplianceProfileAssociationRepository complianceProfileAssociationRepository;
    private final CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private final CertificateRepository certificateRepository;
    private final ResourceInternalService resourceService;
    private final ClusterOperationSynchronizer synchronizer;

    public ComplianceProfileAssociationWriter(
            ComplianceProfileAssociationRepository complianceProfileAssociationRepository,
            CryptographicKeyItemRepository cryptographicKeyItemRepository, CertificateRepository certificateRepository,
            ResourceInternalService resourceService, ClusterOperationSynchronizer synchronizer) {
        this.complianceProfileAssociationRepository = complianceProfileAssociationRepository;
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
        this.certificateRepository = certificateRepository;
        this.resourceService = resourceService;
        this.synchronizer = synchronizer;
    }

    /**
     * The advisory lock serializes this insert against {@link #deleteAllForObject}, and the object is looked up only
     * once the lock is held: an object deleted meanwhile is then seen as missing, so no association to it is saved.
     */
    @Transactional
    public ComplianceProfileAssociation create(UUID complianceProfileUuid, Resource resource, UUID objectUuid)
            throws NotFoundException, AlreadyExistException {
        synchronizer.lock(objectLockKey(resource, objectUuid));
        requireExistingObject(resource, objectUuid);
        if (complianceProfileAssociationRepository
                .existsByComplianceProfileUuidAndResourceAndObjectUuid(complianceProfileUuid, resource, objectUuid)) {
            throw new AlreadyExistException("Compliance profile is already associated to %s with UUID %s"
                    .formatted(resource.getLabel(), objectUuid));
        }

        ComplianceProfileAssociation association = new ComplianceProfileAssociation();
        association.setComplianceProfileUuid(complianceProfileUuid);
        association.setResource(resource);
        association.setObjectUuid(objectUuid);
        return complianceProfileAssociationRepository.save(association);
    }

    @Transactional
    public int delete(UUID complianceProfileUuid, Resource resource, UUID objectUuid) {
        return complianceProfileAssociationRepository
                .deleteByComplianceProfileUuidAndResourceAndObjectUuid(complianceProfileUuid, resource, objectUuid);
    }

    @Transactional
    public int deleteAllOfProfile(UUID complianceProfileUuid) {
        return complianceProfileAssociationRepository.deleteByComplianceProfileUuid(complianceProfileUuid);
    }

    @Transactional
    public int deleteAllForObject(Resource resource, UUID objectUuid) {
        synchronizer.lock(objectLockKey(resource, objectUuid));
        return complianceProfileAssociationRepository.deleteByResourceAndObjectUuid(resource, objectUuid);
    }

    @Transactional
    public int deleteAllForObjects(Resource resource, Collection<UUID> objectUuids) {
        if (objectUuids.isEmpty()) {
            return 0;
        }
        synchronizer.lockAll(objectUuids.stream().map(objectUuid -> objectLockKey(resource, objectUuid)).toList());
        return complianceProfileAssociationRepository.deleteByResourceAndObjectUuidIn(resource, objectUuids);
    }

    /**
     * A certificate request exists while a certificate refers to it, so removing a certificate, or its reference to a
     * request, can end the request's existence. The lock is the one {@link #create} takes before it looks for such a
     * certificate, so an associate racing the removal either sees no certificate or is purged here. Only requests with
     * associations are looked up, because nothing indexes the certificates' reference to their request.
     */
    @Transactional
    public int deleteAllForCertificateRequestsWithoutCertificate(Collection<UUID> certificateRequestUuids) {
        if (certificateRequestUuids.isEmpty()) {
            return 0;
        }
        synchronizer
                .lockAll(certificateRequestUuids
                        .stream()
                        .map(requestUuid -> objectLockKey(Resource.CERTIFICATE_REQUEST, requestUuid))
                        .toList());
        List<UUID> requestUuidsWithoutCertificate = complianceProfileAssociationRepository
                .findAssociatedObjectUuids(Resource.CERTIFICATE_REQUEST, certificateRequestUuids)
                .stream()
                .filter(requestUuid -> !certificateRepository.existsByCertificateRequestUuid(requestUuid))
                .toList();
        if (requestUuidsWithoutCertificate.isEmpty()) {
            return 0;
        }
        return complianceProfileAssociationRepository
                .deleteByResourceAndObjectUuidIn(Resource.CERTIFICATE_REQUEST, requestUuidsWithoutCertificate);
    }

    /**
     * A certificate request counts as existing while a certificate refers to it, the same rule the association list
     * applies.
     */
    private void requireExistingObject(Resource resource, UUID objectUuid) throws NotFoundException {
        switch (resource) {
            case CRYPTOGRAPHIC_KEY_ITEM -> requireFound(cryptographicKeyItemRepository.existsById(objectUuid),
                    CryptographicKeyItem.class, objectUuid);
            case CERTIFICATE_REQUEST -> requireFound(certificateRepository.existsByCertificateRequestUuid(objectUuid),
                    CertificateRequestEntity.class, objectUuid);
            default -> resourceService.getResourceObjectInternal(resource, objectUuid);
        }
    }

    private static void requireFound(boolean exists, Class<?> type, UUID objectUuid) throws NotFoundException {
        if (!exists) {
            throw new NotFoundException(type, objectUuid);
        }
    }

    private static String objectLockKey(Resource resource, UUID objectUuid) {
        return "compliance-profile-association-object:" + resource.getCode() + ":" + objectUuid;
    }
}
