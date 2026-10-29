package com.otilm.core.service.writer;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.service.ResourceInternalService;
import java.util.Collection;
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
    private final CertificateRequestRepository certificateRequestRepository;
    private final ResourceInternalService resourceService;
    private final ClusterOperationSynchronizer synchronizer;

    public ComplianceProfileAssociationWriter(
            ComplianceProfileAssociationRepository complianceProfileAssociationRepository,
            CryptographicKeyItemRepository cryptographicKeyItemRepository,
            CertificateRequestRepository certificateRequestRepository, ResourceInternalService resourceService,
            ClusterOperationSynchronizer synchronizer) {
        this.complianceProfileAssociationRepository = complianceProfileAssociationRepository;
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
        this.certificateRequestRepository = certificateRequestRepository;
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

    private void requireExistingObject(Resource resource, UUID objectUuid) throws NotFoundException {
        switch (resource) {
            case CRYPTOGRAPHIC_KEY_ITEM -> requireFound(cryptographicKeyItemRepository.existsById(objectUuid),
                    CryptographicKeyItem.class, objectUuid);
            case CERTIFICATE_REQUEST -> requireFound(certificateRequestRepository.existsById(objectUuid),
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
