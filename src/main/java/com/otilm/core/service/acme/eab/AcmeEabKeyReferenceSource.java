package com.otilm.core.service.acme.eab;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.reference.ObjectReferenceSource;
import com.otilm.core.reference.ObjectReferrer;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * An ACME profile that lost one of its External Account Binding keys would keep advertising externalAccountRequired
 * against a key that no longer exists, locking out the clients that bind with it. Disabling the secret is the
 * reversible way to take a key out of service.
 */
@Component
public class AcmeEabKeyReferenceSource implements ObjectReferenceSource {

    private final AcmeProfileRepository acmeProfileRepository;

    public AcmeEabKeyReferenceSource(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Override
    public Set<Resource> referencedResources() {
        return Set.of(Resource.SECRET);
    }

    @Override
    public List<ObjectReferrer> findReferrers(ObjectRef referenced) {
        return acmeProfileRepository
                .findByEabSecretUuid(referenced.uuid())
                .stream()
                .map(profile -> new ObjectReferrer(new ObjectRef(Resource.ACME_PROFILE, profile.getUuid()),
                        profile.getName(), "External Account Binding key"))
                .toList();
    }
}
