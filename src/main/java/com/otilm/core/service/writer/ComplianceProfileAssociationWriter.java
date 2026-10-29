package com.otilm.core.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
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

    public ComplianceProfileAssociationWriter(
            ComplianceProfileAssociationRepository complianceProfileAssociationRepository) {
        this.complianceProfileAssociationRepository = complianceProfileAssociationRepository;
    }

    @Transactional
    public int deleteAllForObject(Resource resource, UUID objectUuid) {
        return complianceProfileAssociationRepository.deleteByResourceAndObjectUuid(resource, objectUuid);
    }

    @Transactional
    public int deleteAllForObjects(Resource resource, Collection<UUID> objectUuids) {
        return complianceProfileAssociationRepository.deleteByResourceAndObjectUuidIn(resource, objectUuids);
    }
}
