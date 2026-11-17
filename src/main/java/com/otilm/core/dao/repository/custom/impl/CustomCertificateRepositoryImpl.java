package com.otilm.core.dao.repository.custom.impl;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.custom.CustomCertificateRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import java.util.Optional;
import java.util.UUID;

public class CustomCertificateRepositoryImpl implements CustomCertificateRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void bulkUpdateQuery(String query) {
        entityManager.createQuery(query).executeUpdate();
    }

    @Override
    public Optional<Certificate> findAndLockFreshByUuid(UUID uuid) {
        Certificate certificate = entityManager.find(Certificate.class, uuid);
        if (certificate == null) {
            return Optional.empty();
        }
        entityManager.refresh(certificate, LockModeType.PESSIMISTIC_WRITE);
        return Optional.of(certificate);
    }
}
