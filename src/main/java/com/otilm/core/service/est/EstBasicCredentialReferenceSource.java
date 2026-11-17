package com.otilm.core.service.est;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.reference.ObjectReferenceSource;
import com.otilm.core.reference.ObjectReferrer;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * An EST Profile lets an RA enroll with the content of any of its basic-auth secrets, so deleting one would leave the
 * profile accepting a credential that no longer exists.
 */
@Component
public class EstBasicCredentialReferenceSource implements ObjectReferenceSource {

    private final EstProfileRepository estProfileRepository;

    public EstBasicCredentialReferenceSource(EstProfileRepository estProfileRepository) {
        this.estProfileRepository = estProfileRepository;
    }

    @Override
    public Set<Resource> referencedResources() {
        return Set.of(Resource.SECRET);
    }

    @Override
    public List<ObjectReferrer> findReferrers(ObjectRef referenced) {
        return estProfileRepository
                .findByBasicCredentialSecretUuid(referenced.uuid())
                .stream()
                .map(EstBasicCredentialReferenceSource::toReferrer)
                .toList();
    }

    private static ObjectReferrer toReferrer(EstProfile profile) {
        ObjectRef profileRef = new ObjectRef(Resource.EST_PROFILE, profile.getUuid());
        return new ObjectReferrer(profileRef, profile.getName(), "EST RA basic credential");
    }
}
