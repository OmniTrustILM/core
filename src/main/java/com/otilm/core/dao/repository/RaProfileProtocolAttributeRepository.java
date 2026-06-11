package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileProtocolAttribute;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RaProfileProtocolAttributeRepository extends SecurityFilterRepository<RaProfileProtocolAttribute, Long> {

    Optional<RaProfileProtocolAttribute> findByUuid(UUID uuid);

    Optional<RaProfileProtocolAttribute> findByRaProfile(RaProfile raProfile);

}
