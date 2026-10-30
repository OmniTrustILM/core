package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileProtocolAttribute;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface RaProfileProtocolAttributeRepository
        extends
            SecurityFilterRepository<RaProfileProtocolAttribute, Long> {

    Optional<RaProfileProtocolAttribute> findByUuid(UUID uuid);

    Optional<RaProfileProtocolAttribute> findByRaProfile(RaProfile raProfile);

}
