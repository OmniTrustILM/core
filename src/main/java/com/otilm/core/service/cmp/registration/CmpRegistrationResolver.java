package com.otilm.core.service.cmp.registration;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.registration.RegistrationChallengeGate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Binds a MAC-protected CMP request to its pre-registered certificate: the {@code senderKID} names the
 * pre-registration by UUID, and the registration challenge is the MAC key. Verifies the message MAC through
 * the shared {@link RegistrationChallengeGate} (so a wrong MAC is counted and eventually locks out exactly
 * one authorization), and returns the matched certificate and the challenge plaintext for the handler and
 * response keying.
 *
 * <p>Every failure — unparseable senderKID, wrong certificate state, wrong RA profile, non-ACTIVE
 * authorization, MAC mismatch — surfaces as the single generic rejection; the reason stays in the log.
 */
@Service
public class CmpRegistrationResolver {

    private static final Logger logger = LoggerFactory.getLogger(CmpRegistrationResolver.class);

    /** The single wire message for every registration-mode rejection, so a prober cannot enumerate registrations. */
    public static final String REGISTRATION_REJECTION = "The request does not match an active certificate registration.";

    private CertificateRepository certificateRepository;
    private RegistrationChallengeGate registrationChallengeGate;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setRegistrationChallengeGate(RegistrationChallengeGate registrationChallengeGate) {
        this.registrationChallengeGate = registrationChallengeGate;
    }

    /** The matched pre-registration and its challenge plaintext (for {@code authorizationSecret} and response keying). */
    public record RegistrationMacResolution(Certificate certificate, String challenge) {
    }

    /**
     * Resolves the senderKID to a REGISTERED certificate of {@code raProfile} with an ACTIVE authorization,
     * verifies the message MAC via {@code macMatches} through the challenge gate, and returns the match.
     *
     * @param macMatches given a candidate challenge key's bytes, whether the message MAC verifies under it
     * @throws CmpProcessingException the single generic rejection ({@link PKIFailureInfo#badMessageCheck}) on any failure
     */
    public RegistrationMacResolution resolveAndVerify(RaProfile raProfile, ASN1OctetString senderKID,
                                                      CertificateEvent event, Predicate<byte[]> macMatches,
                                                      ASN1OctetString tid) throws CmpBaseException {
        Certificate certificate = resolveEligibleCertificate(raProfile, senderKID, event, tid);
        return verifyChallenge(certificate, event, macMatches, tid);
    }

    /**
     * As {@link #resolveAndVerify} but for a CMP follow-up (pollReq / certConf) of a registration exchange:
     * by the time the client polls, the placeholder has moved past {@code REGISTERED}, so the certificate
     * state is not constrained — only that the senderKID references a certificate of {@code raProfile} whose
     * authorization still verifies the MAC through the gate (a forged follow-up is still counted and locks
     * out). Issuance leaves the authorization ACTIVE, so the challenge remains available to key the response.
     */
    public RegistrationMacResolution resolveAndVerifyFollowup(RaProfile raProfile, ASN1OctetString senderKID,
                                                              Predicate<byte[]> macMatches,
                                                              ASN1OctetString tid) throws CmpBaseException {
        Certificate certificate = resolveEligibleCertificate(raProfile, senderKID, null, tid);
        return verifyChallenge(certificate, CertificateEvent.ISSUE, macMatches, tid);
    }

    /**
     * Resolves the senderKID to a certificate of {@code raProfile}. A non-null {@code event} additionally
     * requires the state to match the operation ({@link #stateMatchesOperation}); a null {@code event} skips
     * the state check (the follow-up path, where the certificate has already left {@code REGISTERED}).
     */
    private Certificate resolveEligibleCertificate(RaProfile raProfile, ASN1OctetString senderKID,
                                                   CertificateEvent event, ASN1OctetString tid) throws CmpBaseException {
        UUID certificateUuid = parseSenderKid(senderKID);
        if (certificateUuid == null) {
            throw rejection(tid, "senderKID is not a certificate registration reference");
        }
        Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElse(null);
        if (certificate == null
                || certificate.getRaProfileUuid() == null || !certificate.getRaProfileUuid().equals(raProfile.getUuid())
                || (event != null && !stateMatchesOperation(certificate.getState(), event))) {
            throw rejection(tid, "senderKID does not reference an eligible certificate of this RA profile");
        }
        return certificate;
    }

    private RegistrationMacResolution verifyChallenge(Certificate certificate, CertificateEvent event,
                                                      Predicate<byte[]> macMatches, ASN1OctetString tid) throws CmpBaseException {
        // The gate resolves the plaintext internally and hands it to the predicate; capture it on the
        // verifying key so the handler can present it as authorizationSecret and the response can be keyed.
        String[] captured = new String[1];
        boolean verified;
        try {
            verified = registrationChallengeGate.verify(certificate.getUuid(), event, plaintext -> {
                boolean ok = macMatches.test(plaintext.getBytes(StandardCharsets.UTF_8));
                if (ok) {
                    captured[0] = plaintext;
                }
                return ok;
            });
        } catch (ValidationException denial) {
            // Locked, expired window, or wrong MAC (counted). Detail stays in the gate's event history.
            return reject(tid, "registration challenge denied: " + denial.getMessage());
        }
        if (!verified) {
            // No ACTIVE authorization behind the senderKID.
            return reject(tid, "senderKID references a certificate with no active registration authorization");
        }
        return new RegistrationMacResolution(certificate, captured[0]);
    }

    /**
     * ir/cr completes a REGISTERED placeholder; kur rekeys the already-issued certificate whose registration
     * authorization survived issuance (a REGISTERED placeholder has no key to rekey).
     */
    private static boolean stateMatchesOperation(CertificateState state, CertificateEvent event) {
        return event == CertificateEvent.REKEY
                ? state != CertificateState.REGISTERED
                : state == CertificateState.REGISTERED;
    }

    private static UUID parseSenderKid(ASN1OctetString senderKID) {
        if (senderKID == null || senderKID.getOctets().length == 0) {
            return null;
        }
        try {
            return UUID.fromString(new String(senderKID.getOctets(), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static RegistrationMacResolution reject(ASN1OctetString tid, String reason) throws CmpProcessingException {
        throw rejection(tid, reason);
    }

    private static CmpProcessingException rejection(ASN1OctetString tid, String reason) {
        logger.info("CMP registration enrolment rejected: {}", reason);
        return new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck, REGISTRATION_REJECTION);
    }
}
