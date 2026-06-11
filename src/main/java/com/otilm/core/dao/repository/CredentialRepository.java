package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Credential;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialRepository extends SecurityFilterRepository<Credential, Long> {

    Optional<Credential> findByUuid(UUID uuid);

    Optional<Credential> findByName(String name);

}
