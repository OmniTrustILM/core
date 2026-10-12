package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.reference.ObjectReferenceSource;
import com.otilm.core.reference.ObjectReferrer;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * A TSP Basic credential owns the secret holding its password: it creates the secret and deletes it with itself, naming
 * itself as the releasing owner. Anyone else deleting the secret is refused, since the credential would be left
 * pointing at nothing.
 */
@Component
public class TspBasicCredentialReferenceSource implements ObjectReferenceSource {

    private final TspProfileBasicCredentialRepository credentialRepository;

    public TspBasicCredentialReferenceSource(TspProfileBasicCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @Override
    public Set<Resource> referencedResources() {
        return Set.of(Resource.SECRET);
    }

    @Override
    public List<ObjectReferrer> findReferrers(ObjectRef referenced) {
        return credentialRepository
                .findBySecretUuid(referenced.uuid())
                .map(TspBasicCredentialReferenceSource::toReferrer)
                .stream()
                .toList();
    }

    private static ObjectReferrer toReferrer(TspProfileBasicCredential credential) {
        ObjectRef credentialRef = new ObjectRef(Resource.TSP_PROFILE_BASIC_CREDENTIAL, credential.getUuid());
        TspProfile tspProfile = credential.getTspProfile();
        ObjectRef tspProfileRef = new ObjectRef(Resource.TSP_PROFILE, tspProfile.getUuid());
        String role = "owns this secret; delete the credential from TSP Profile '%s'".formatted(tspProfile.getName());
        return new ObjectReferrer(credentialRef, credential.getUsername(), role, List.of(credentialRef, tspProfileRef));
    }
}
