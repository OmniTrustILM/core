package com.otilm.core.service.est;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Turns the label of an EST request into the profiles that serve it. EST Profile names and the names of RA Profiles
 * with EST activated share one namespace of labels, so a label that both hold resolves to nothing rather than to
 * either. A route is returned only when it can issue: both profiles are enabled and the authority of the RA Profile has
 * a connector. The reason a request resolved to nothing is logged at DEBUG; the result carries none.
 * <p>
 * It reads the repositories without authorization: the route is what selects the authentication policy that identifies
 * the client, so it has to be known first.
 */
@Slf4j
@Component
public class EstRouteResolver {

    private final EstProfileRepository estProfileRepository;
    private final RaProfileRepository raProfileRepository;

    public EstRouteResolver(EstProfileRepository estProfileRepository, RaProfileRepository raProfileRepository) {
        this.estProfileRepository = estProfileRepository;
        this.raProfileRepository = raProfileRepository;
    }

    /**
     * @param label the label from the request path, {@code null} for a request without one, which the system default
     * EST Profile serves through its default RA Profile
     * @return the route, empty when the request addresses nothing that can serve it
     */
    public Optional<EstRoute> resolve(String label) {
        if (label == null) {
            return resolveSystemDefault();
        }
        if (!EstLabels.isUsable(label)) {
            // The label comes from the request path and can carry control characters, so it is not echoed.
            log.debug("EST route not resolved: unusable label");
            return Optional.empty();
        }
        Optional<EstProfile> estProfile = estProfileRepository.findByName(label);
        Optional<RaProfile> activatedRaProfile = raProfileRepository
                .findByName(label)
                .filter(raProfile -> raProfile.getEstProfileUuid() != null);
        if (estProfile.isPresent() && activatedRaProfile.isPresent()) {
            log.debug("EST route not resolved: label '{}' matches both an EST Profile and an RA Profile", label);
            return Optional.empty();
        }
        if (estProfile.isPresent()) {
            return resolveDirectRoute(estProfile.get(), label);
        }
        if (activatedRaProfile.isPresent()) {
            return resolveRaProfileRoute(activatedRaProfile.get(), label);
        }
        log
                .debug("EST route not resolved: label '{}' matches no EST Profile and no RA Profile with EST activated",
                        label);
        return Optional.empty();
    }

    private Optional<EstRoute> resolveSystemDefault() {
        Optional<EstProfile> systemDefault = estProfileRepository.findBySystemDefaultTrue();
        if (systemDefault.isEmpty()) {
            log.debug("EST route not resolved: no EST Profile is the system default");
            return Optional.empty();
        }
        return resolveDirectRoute(systemDefault.get(), null);
    }

    private Optional<EstRoute> resolveDirectRoute(EstProfile estProfile, String label) {
        return resolveRoute(estProfile, estProfile.getRaProfileUuid(), false, label);
    }

    private Optional<EstRoute> resolveRaProfileRoute(RaProfile activatedRaProfile, String label) {
        UUID estProfileUuid = activatedRaProfile.getEstProfileUuid();
        Optional<EstProfile> estProfile = estProfileRepository.findById(estProfileUuid);
        if (estProfile.isEmpty()) {
            log
                    .debug("EST route not resolved: EST Profile {} activated on RA Profile '{}' no longer exists",
                            estProfileUuid, activatedRaProfile.getName());
            return Optional.empty();
        }
        return resolveRoute(estProfile.get(), activatedRaProfile.getUuid(), true, label);
    }

    /**
     * @param raProfileUuid the RA Profile that issues, {@code null} for an EST Profile without a default RA Profile
     * @param label the usable label of the request, {@code null} when it has none
     */
    private Optional<EstRoute> resolveRoute(EstProfile estProfile, UUID raProfileUuid, boolean raProfileRoute,
            String label) {
        if (!estProfile.isEnabled()) {
            log.debug("EST route not resolved: EST Profile '{}' is disabled", estProfile.getName());
            return Optional.empty();
        }
        if (raProfileUuid == null) {
            log.debug("EST route not resolved: EST Profile '{}' has no default RA Profile", estProfile.getName());
            return Optional.empty();
        }
        Optional<RaProfile> loaded = raProfileRepository.findWithAuthorityByUuid(raProfileUuid);
        if (loaded.isEmpty()) {
            log.debug("EST route not resolved: RA Profile {} no longer exists", raProfileUuid);
            return Optional.empty();
        }
        RaProfile raProfile = loaded.get();
        if (!Boolean.TRUE.equals(raProfile.getEnabled())) {
            log.debug("EST route not resolved: RA Profile '{}' is disabled", raProfile.getName());
            return Optional.empty();
        }
        if (EstProfileReferenceResolver.issueConnectorUuid(raProfile) == null) {
            log.debug("EST route not resolved: RA Profile '{}' has no authority with a connector", raProfile.getName());
            return Optional.empty();
        }
        return Optional.of(new EstRoute(estProfile, raProfile, raProfileRoute, label));
    }
}
