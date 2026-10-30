package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.AuthorityInstanceReference;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorityInstanceReferenceRepository
        extends
            SecurityFilterRepository<AuthorityInstanceReference, Long> {

    Optional<AuthorityInstanceReference> findByUuid(UUID uuid);

    Optional<AuthorityInstanceReference> findByName(String name);
}
