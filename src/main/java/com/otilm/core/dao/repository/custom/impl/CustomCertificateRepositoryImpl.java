package com.otilm.core.dao.repository.custom.impl;

import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.custom.CustomCertificateRepository;
import com.otilm.core.security.ai.AiReadInvocationContext;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.handler.StoredCertificateHealthProjector;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

public class CustomCertificateRepositoryImpl implements CustomCertificateRepository {

    private static final String STORED_HEALTH_QUERY = """
            SELECT new com.otilm.core.service.handler.StoredCertificateHealthProjector$Snapshot(
                c.uuid, c.raProfileUuid, c.commonName, c.serialNumber, c.issuerCommonName, c.fingerprint,
                c.notBefore, c.notAfter, c.state, c.validationStatus, c.statusValidationTimestamp,
                substring(c.certificateValidationResult, 1, 100001))
            FROM Certificate c WHERE c.uuid = :certificate AND c.raProfileUuid = :expectedProfile
            """;
    private static final String SCOPED_STORED_HEALTH_QUERY = STORED_HEALTH_QUERY
            + " AND c.raProfileUuid = :trustedProfile AND c.uuid IN :trusted";

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<CertificateDto> findScopedCertificateDtos(SecurityFilter filter, List<UUID> selectedPage) {
        var context = filter.requireCurrentCertificateRead();
        var page = List.copyOf(selectedPage);
        if (page.size() > 100 || !context.scope().certificateUuids().containsAll(page)) {
            throw new AccessDeniedException("Certificate read page unavailable");
        }
        int timeout = context.remainingQueryTimeoutSeconds();
        var query = entityManager.createQuery(CertificateRepository.CERTIFICATE_DTO_PROJECTION + """
                 WHERE c.uuid IN :page AND c.raProfileUuid = :profile AND c.uuid IN :trusted
                   AND (:allCertificates = true OR c.uuid IN :allowedCertificates)
                   AND c.uuid NOT IN :forbiddenCertificates
                   AND (:allProfiles = true OR c.raProfileUuid IN :allowedProfiles)
                   AND c.raProfileUuid NOT IN :forbiddenProfiles
                """, CertificateDto.class);
        query.setParameter("page", page);
        query.setParameter("profile", context.scope().raProfileUuid());
        query.setParameter("trusted", context.scope().certificateUuids());
        var resource = filter.getResourceFilter();
        query.setParameter("allCertificates", !resource.areOnlySpecificObjectsAllowed());
        query.setParameter("allowedCertificates", resource.getAllowedObjects());
        query.setParameter("forbiddenCertificates", resource.getForbiddenObjects());
        var parent = filter.getParentResourceFilter();
        query.setParameter("allProfiles", !parent.areOnlySpecificObjectsAllowed());
        query.setParameter("allowedProfiles", parent.getAllowedObjects());
        query.setParameter("forbiddenProfiles", parent.getForbiddenObjects());
        query.setHint("org.hibernate.timeout", Math.min(timeout, context.remainingQueryTimeoutSeconds()));
        return query.getResultList();
    }

    @Override
    public Optional<StoredCertificateHealthProjector.Snapshot> findStoredCertificateHealth(UUID expectedProfile,
            UUID certificate) {
        var invocation = AiReadInvocationContext.current();
        invocation.ifPresent(context -> {
            context.requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
            if (!context.scope().raProfileUuid().equals(expectedProfile)
                    || !context.scope().certificateUuids().contains(certificate)) {
                throw new AccessDeniedException("Certificate read tuple unavailable");
            }
            context.remainingQueryTimeoutSeconds();
        });
        var query = invocation.isPresent()
                ? entityManager.createQuery(SCOPED_STORED_HEALTH_QUERY, StoredCertificateHealthProjector.Snapshot.class)
                : entityManager.createQuery(STORED_HEALTH_QUERY, StoredCertificateHealthProjector.Snapshot.class);
        query.setParameter("certificate", certificate);
        query.setParameter("expectedProfile", expectedProfile);
        invocation.ifPresent(context -> {
            query.setParameter("trustedProfile", context.scope().raProfileUuid());
            query.setParameter("trusted", context.scope().certificateUuids());
            query.setHint("org.hibernate.timeout", context.remainingQueryTimeoutSeconds());
        });
        var result = query.getResultList();
        invocation
                .ifPresent(
                        context -> context.requirePinnedActor(SecurityContextHolder.getContext().getAuthentication()));
        return result.stream().findFirst();
    }

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
