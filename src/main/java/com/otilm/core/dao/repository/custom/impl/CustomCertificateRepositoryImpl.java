package com.otilm.core.dao.repository.custom.impl;

import com.otilm.core.dao.repository.custom.CustomCertificateRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

public class CustomCertificateRepositoryImpl implements CustomCertificateRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void bulkUpdateQuery(String query) {
        entityManager.createQuery(query).executeUpdate();
    }
}
