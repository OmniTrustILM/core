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
 * An EST Profile creates the keys of its key recovery on a token profile, so deleting or disabling that token profile
 * would leave the EST Profile unable to serve a request for a key.
 */
@Component
public class EstTokenProfileReferenceSource implements ObjectReferenceSource {

    private final EstProfileRepository estProfileRepository;

    public EstTokenProfileReferenceSource(EstProfileRepository estProfileRepository) {
        this.estProfileRepository = estProfileRepository;
    }

    @Override
    public Set<Resource> referencedResources() {
        return Set.of(Resource.TOKEN_PROFILE);
    }

    @Override
    public List<ObjectReferrer> findReferrers(ObjectRef referenced) {
        return estProfileRepository
                .findAllByKeyRecoveryTokenProfileUuid(referenced.uuid())
                .stream()
                .map(EstTokenProfileReferenceSource::toReferrer)
                .toList();
    }

    private static ObjectReferrer toReferrer(EstProfile profile) {
        ObjectRef profileRef = new ObjectRef(Resource.EST_PROFILE, profile.getUuid());
        return new ObjectReferrer(profileRef, profile.getName(), "EST key recovery token profile");
    }
}
