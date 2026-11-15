package com.otilm.core.util.seeders;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.builders.CertificateBuilder;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;

/**
 * Seeds the pre-registrations that a protocol enrollment completes, as registering a certificate leaves them: a
 * placeholder certificate of an RA Profile, its register-to-issue binding, and the registration authorization that
 * guards it. Unless a method says otherwise, the placeholder is {@code REGISTERED}, not archived, and its authorization
 * is {@code ACTIVE}, protected by {@link #CHALLENGE}, without a failed attempt and open for seven days. It also seeds
 * the authorization that a completed registration keeps on the certificate that it issued. Every method saves through
 * the repositories and returns the saved placeholder, or the certificate whose authorization it seeds.
 */
@Component
public class CertificateRegistrationSeeder {

    /** The challenge that every seeded authorization holds. */
    public static final String CHALLENGE = "registration-challenge";

    private static final Duration ISSUANCE_WINDOW = Duration.ofDays(7);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;

    @Autowired
    private CertificateRegistrationWriter registrationWriter;

    @Autowired
    private RegistrationChallengeStore challengeStore;

    /** Seeds a registration of the subject, with no subject alternative names. */
    public Certificate seedRegistration(RaProfile raProfile, String subjectDn) {
        return authorize(save(registered(raProfile, subjectDn)), RegistrationState.ACTIVE);
    }

    /** Seeds a registration of the subject and the subject alternative names, as {@code getSAN} renders them. */
    public Certificate seedRegistration(RaProfile raProfile, String subjectDn, Map<String, List<String>> sans) {
        CertificateBuilder registration = registered(raProfile, subjectDn)
                .withSubjectAlternativeNames(CertificateUtil.serializeSans(sans));
        return authorize(save(registration), RegistrationState.ACTIVE);
    }

    /** Seeds a placeholder that has left {@code REGISTERED}, whose authorization stays {@code ACTIVE}. */
    public Certificate seedRegistrationInState(RaProfile raProfile, String subjectDn, CertificateState state) {
        return authorize(save(registered(raProfile, subjectDn).withState(state)), RegistrationState.ACTIVE);
    }

    /** Seeds a {@code REGISTERED} placeholder whose authorization is in the given state. */
    public Certificate seedRegistrationWithAuthorization(RaProfile raProfile, String subjectDn,
            RegistrationState authorizationState) {
        return authorize(save(registered(raProfile, subjectDn)), authorizationState);
    }

    /**
     * Seeds a registration whose issuance window has passed. Its authorization stays {@code ACTIVE} until the challenge
     * is next verified, which expires it.
     */
    public Certificate seedRegistrationWithPassedWindow(RaProfile raProfile, String subjectDn) {
        return authorize(save(registered(raProfile, subjectDn)), RegistrationState.ACTIVE,
                OffsetDateTime.now().minusMinutes(1));
    }

    /** Seeds an archived placeholder, whose authorization stays {@code ACTIVE}. */
    public Certificate seedArchivedRegistration(RaProfile raProfile, String subjectDn) {
        return authorize(save(registered(raProfile, subjectDn).withArchived(true)), RegistrationState.ACTIVE);
    }

    /** Seeds a {@code REGISTERED} placeholder that no challenge protects, so it has no authorization. */
    public Certificate seedRegistrationWithoutAuthorization(RaProfile raProfile, String subjectDn) {
        return save(registered(raProfile, subjectDn));
    }

    /**
     * Seeds what completing the registration with a request leaves: the placeholder carries the request, by whose
     * fingerprint Core finds it, and is in the state that the completion reached.
     *
     * @param registration a placeholder that another method of this seeder returned
     * @param requestDer the DER of the request
     */
    public Certificate seedCompletion(Certificate registration, byte[] requestDer, CertificateState state) {
        CertificateRequestEntity request = certificateRequestRepository
                .save(aCertificateRequest().withContent(Base64.getEncoder().encodeToString(requestDer)).build());
        registration.setCertificateRequestUuid(request.getUuid());
        registration.setState(state);
        return certificateRepository.save(registration);
    }

    /**
     * Seeds what completing a registration leaves on the certificate that it issued: the authorization that guards the
     * renewals and rekeys of the certificate, in the state, protected by {@link #CHALLENGE}, without a failed attempt
     * and without an issuance window, which the first issue cleared.
     *
     * @param issued a certificate in the inventory, which the completed registration issued
     */
    public Certificate seedRetainedAuthorization(Certificate issued, RegistrationState authorizationState) {
        return authorize(issued, authorizationState, null);
    }

    private static CertificateBuilder registered(RaProfile raProfile, String subjectDn) {
        return aCertificate()
                .withSubjectDn(subjectDn)
                .withSubjectDnNormalized(CertificateUtil.normalizeStoredSubjectDn(subjectDn))
                .withState(CertificateState.REGISTERED)
                .withRaProfile(raProfile);
    }

    /** Registering writes the binding without connector meta, which marks the placeholder as a registration. */
    private Certificate save(CertificateBuilder placeholder) {
        Certificate saved = certificateRepository.save(placeholder.build());
        registrationWriter.upsert(saved.getUuid(), List.of());
        return saved;
    }

    private Certificate authorize(Certificate placeholder, RegistrationState state) {
        return authorize(placeholder, state, OffsetDateTime.now().plus(ISSUANCE_WINDOW));
    }

    private Certificate authorize(Certificate placeholder, RegistrationState state, OffsetDateTime expiresAt) {
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(placeholder.getUuid());
        authorization.setState(state);
        authorization.setFailedAttempts(0);
        authorization.setExpiresAt(expiresAt);
        challengeStore.store(authorization, CHALLENGE);
        authorizationRepository.save(authorization);
        return placeholder;
    }
}
