package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ConnectorContentSigningDeclaration;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConnectorContentSigningDeclarationRepository
        extends
            JpaRepository<ConnectorContentSigningDeclaration, UUID> {
}
