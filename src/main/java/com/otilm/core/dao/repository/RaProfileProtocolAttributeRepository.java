package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileProtocolAttribute;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface RaProfileProtocolAttributeRepository
        extends
            SecurityFilterRepository<RaProfileProtocolAttribute, Long> {

    Optional<RaProfileProtocolAttribute> findByUuid(UUID uuid);

    Optional<RaProfileProtocolAttribute> findByRaProfile(RaProfile raProfile);

    /** The serialized issue attributes of the EST activation of the RA Profile, read without managing the entity. */
    @Query("SELECT a.estIssueCertificateAttributes FROM RaProfileProtocolAttribute a WHERE a.raProfileUuid = :raProfileUuid")
    Optional<String> findEstIssueCertificateAttributesByRaProfileUuid(@Param("raProfileUuid") UUID raProfileUuid);

}
