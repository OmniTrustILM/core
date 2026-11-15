package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.authentication.EstSourceCertificate;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.registration.RegistrationIdentityMatcher;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Candidate;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Outcome;
import com.otilm.core.util.CertificateUtil;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;

/**
 * The rules that EST re-enrolment (RFC 7030 section 4.2.2) applies to a request before it renews or rekeys the current
 * certificate of the client. A rule that refuses throws an {@link EstException} without a realm, which the caller adds.
 */
@Slf4j
public final class EstReenrollmentRules {

    /** The {@code changeSubjectName} attribute of RFC 6402 section 2.8, for which BouncyCastle has no constant. */
    private static final ASN1ObjectIdentifier CHANGE_SUBJECT_NAME = CMCObjectIdentifiers.id_cmc.branch("36");

    private EstReenrollmentRules() {
    }

    /**
     * @return {@link EstReenrollmentKind#RENEWAL} when the request carries the public key of the source certificate,
     * {@link EstReenrollmentKind#REKEY} when it carries another
     */
    public static EstReenrollmentKind classify(EstSourceCertificate source, Pkcs10CertificateRequest csr) {
        boolean sameKey = requestKeyOf(csr).equals(source.publicKey());
        return sameKey ? EstReenrollmentKind.RENEWAL : EstReenrollmentKind.REKEY;
    }

    /**
     * @throws EstException {@link EstError#RENEWAL_NOT_ALLOWED} or {@link EstError#REKEY_NOT_ALLOWED} when the profile
     * forbids the kind of re-enrolment
     */
    public static void requireAllowed(EstReenrollmentKind kind, EstProfile profile) {
        if (kind == EstReenrollmentKind.RENEWAL && !profile.isAllowRenewal()) {
            throw new EstException(EstError.RENEWAL_NOT_ALLOWED);
        }
        if (kind == EstReenrollmentKind.REKEY && !profile.isAllowRekey()) {
            throw new EstException(EstError.REKEY_NOT_ALLOWED);
        }
    }

    /**
     * @throws EstException {@link EstError#IDENTITY_MISMATCH} unless the subject and the subject alternative names of
     * the request equal those of the source certificate
     */
    public static void requireSameIdentity(EstSourceCertificate source, Pkcs10CertificateRequest csr) {
        Candidate identity = new Candidate(source.uuid(), source.subjectDn(), source.subjectAlternativeNames());
        Outcome outcome = RegistrationIdentityMatcher
                .match(csr.getSubject(), CertificateUtil.getSAN(csr), List.of(identity))
                .outcome();
        if (outcome != Outcome.MATCHED) {
            throw new EstException(EstError.IDENTITY_MISMATCH);
        }
    }

    /** @throws EstException {@link EstError#SUBJECT_CHANGE_UNSUPPORTED} when the request carries changeSubjectName */
    public static void refuseSubjectChange(Pkcs10CertificateRequest csr) {
        boolean changesSubject = csr.getJcaObject().getAttributes(CHANGE_SUBJECT_NAME).length > 0;
        if (changesSubject) {
            throw new EstException(EstError.SUBJECT_CHANGE_UNSUPPORTED);
        }
    }

    /**
     * Whether a certificate is in its renewal window, counting whole days like the SCEP renewal window: due when the
     * days remaining are at most the threshold, or at most half of the validity when there is no threshold.
     *
     * @param thresholdDays the days before expiry at which renewal opens; null or 0 for half of the validity
     */
    public static boolean isDue(Date notBefore, Date notAfter, Integer thresholdDays, Instant now) {
        long remainingDays = TimeUnit.DAYS.convert(notAfter.getTime() - now.toEpochMilli(), TimeUnit.MILLISECONDS);
        long validityDays = TimeUnit.DAYS.convert(notAfter.getTime() - notBefore.getTime(), TimeUnit.MILLISECONDS);
        boolean hasThreshold = thresholdDays != null && thresholdDays != 0;
        long windowDays = hasThreshold ? thresholdDays : validityDays / 2;
        return remainingDays <= windowDays;
    }

    private static PublicKey requestKeyOf(Pkcs10CertificateRequest csr) {
        try {
            return csr.getPublicKey();
        } catch (NoSuchAlgorithmException | CertificateRequestException e) {
            log.debug("The public key of the EST request cannot be read", e);
            throw new EstException(EstError.BAD_REQUEST);
        }
    }
}
