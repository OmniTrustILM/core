package com.otilm.core.util.builders;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.ComplianceProfile;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
import com.otilm.core.dao.repository.ComplianceProfileRepository;
import java.util.UUID;

/**
 * Associates a new compliance profile with an object directly through the repositories. The association row only names
 * the object, so this works for any resource, including objects that do not exist.
 */
public final class ComplianceProfileFixtures {

    private ComplianceProfileFixtures() {
    }

    public static ComplianceProfile associateNewComplianceProfile(ComplianceProfileRepository profileRepository,
            ComplianceProfileAssociationRepository associationRepository, Resource resource, UUID objectUuid) {
        ComplianceProfile profile = new ComplianceProfile();
        profile.setName("ComplianceProfile-" + UUID.randomUUID());
        profileRepository.save(profile);

        ComplianceProfileAssociation association = new ComplianceProfileAssociation();
        association.setComplianceProfileUuid(profile.getUuid());
        association.setResource(resource);
        association.setObjectUuid(objectUuid);
        associationRepository.save(association);
        return profile;
    }
}
