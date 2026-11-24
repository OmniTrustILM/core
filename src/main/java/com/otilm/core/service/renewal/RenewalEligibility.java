package com.otilm.core.service.renewal;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRelationId_;
import com.otilm.core.dao.entity.CertificateRelation_;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.entity.CertificateRenewalLocation_;
import com.otilm.core.dao.entity.Certificate_;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited_;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;

/** The certificates that are still to be renewed. */
public final class RenewalEligibility {

    private RenewalEligibility() {
    }

    /** Issued, unarchived and unexpired certificates that have no issued successor yet. */
    public static Predicate awaitingRenewal(Root<Certificate> certificate, CriteriaBuilder cb, CriteriaQuery<?> query) {
        return cb.and(live(certificate, cb), cb.not(cb.exists(issuedSuccessor(certificate, cb, query))));
    }

    /**
     * Issued, unarchived and unexpired certificates that have no issued successor yet, or that a key-generating
     * location has still to renew after another location's successor was issued.
     */
    public static Predicate awaitingRenewalOrLocationRenewal(Root<Certificate> certificate, CriteriaBuilder cb,
            CriteriaQuery<?> query) {
        Subquery<Integer> openLocation = query.subquery(Integer.class);
        Root<CertificateRenewalLocation> location = openLocation.from(CertificateRenewalLocation.class);
        openLocation
                .select(cb.literal(1))
                .where(cb
                        .equal(location.get(CertificateRenewalLocation_.certificateUuid),
                                certificate.get(UniquelyIdentifiedAndAudited_.uuid)),
                        cb.isNull(location.get(CertificateRenewalLocation_.completedAt)));
        return cb
                .and(live(certificate, cb),
                        cb.or(cb.not(cb.exists(issuedSuccessor(certificate, cb, query))), cb.exists(openLocation)));
    }

    private static Predicate live(Root<Certificate> certificate, CriteriaBuilder cb) {
        return cb
                .and(cb.equal(certificate.get(Certificate_.state), CertificateState.ISSUED),
                        cb.isFalse(certificate.get(Certificate_.archived)),
                        cb.greaterThan(certificate.get(Certificate_.notAfter), cb.currentTimestamp()));
    }

    private static Subquery<Integer> issuedSuccessor(Root<Certificate> certificate, CriteriaBuilder cb,
            CriteriaQuery<?> query) {
        Subquery<Integer> issuedSuccessor = query.subquery(Integer.class);
        Root<CertificateRelation> relation = issuedSuccessor.from(CertificateRelation.class);
        Join<CertificateRelation, Certificate> successor = relation.join(CertificateRelation_.successorCertificate);
        issuedSuccessor
                .select(cb.literal(1))
                .where(cb
                        .equal(relation
                                .get(CertificateRelation_.id)
                                .get(CertificateRelationId_.predecessorCertificateUuid),
                                certificate.get(UniquelyIdentifiedAndAudited_.uuid)),
                        cb.equal(successor.get(Certificate_.state), CertificateState.ISSUED));
        return issuedSuccessor;
    }
}
