package com.otilm.core.service.writer.est;

import com.otilm.core.dao.entity.est.EstRequestClaim;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository.ClaimLink;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A claim lets one of several identical requests submit while the others wait for its certificate, which the claim
 * links in the transaction that stores it. The link is written only while the claim is still the caller's, so a request
 * whose claim was taken over stores nothing; correctness therefore does not depend on {@link #EXPIRY}, after which a
 * claim that links nothing is taken over, so that a node that died while holding one blocks the request for at most
 * that long. A claim that links a certificate is taken over at once, as its request has finished. Only {@link #link}
 * joins the caller's transaction; the other methods are short transactions of their own, none held across a connector
 * call.
 */
@Slf4j
@Service
public class EstRequestClaimWriter {

    static final Duration EXPIRY = Duration.ofMinutes(2);

    private final EstRequestClaimRepository repository;

    public EstRequestClaimWriter(EstRequestClaimRepository repository) {
        this.repository = repository;
    }

    /**
     * Returns the new claim's UUID when this caller won the claim, empty when a live claim already exists.
     */
    @Transactional
    public Optional<UUID> claim(UUID estProfileUuid, UUID raProfileUuid, EstRequestClaim.Operation operation,
            String requestKey) {
        UUID claimUuid = UUID.randomUUID();
        int written = repository
                .claim(claimUuid, estProfileUuid, raProfileUuid, operation.name(), requestKey, EXPIRY.toSeconds());
        log
                .debug("EST {} request claim {} for EST Profile {}, RA Profile {}, key {}", operation,
                        written == 1 ? "won " + claimUuid : "lost", estProfileUuid, raProfileUuid, requestKey);
        return written == 1 ? Optional.of(claimUuid) : Optional.empty();
    }

    /**
     * Links the certificate that the request stored to the claim, inside the transaction that stores the certificate,
     * which then holds the claim until it ends.
     *
     * @throws EstRequestClaimLostException when the claim was taken over, so that the store is rolled back
     */
    @Transactional
    public void link(UUID claimUuid, UUID certificateUuid) {
        if (repository.link(claimUuid, certificateUuid) == 0) {
            log
                    .info("EST request claim {} was taken over, so certificate {} is not stored", claimUuid,
                            certificateUuid);
            throw new EstRequestClaimLostException(claimUuid);
        }
        log.debug("EST request claim {} links certificate {}", claimUuid, certificateUuid);
    }

    /**
     * @return the claim on the request, empty when there is none
     */
    @Transactional(readOnly = true)
    public Optional<ClaimLink> findLink(UUID estProfileUuid, UUID raProfileUuid, EstRequestClaim.Operation operation,
            String requestKey) {
        return repository.findLink(estProfileUuid, raProfileUuid, operation, requestKey);
    }

    /**
     * Deletes only the given claim, and only while it links no certificate: a claim taken over from this caller is left
     * in place, and a linked one stays to lead identical requests to its certificate until the next attempt replaces
     * it.
     */
    @Transactional
    public void release(UUID claimUuid) {
        int deleted = repository.release(claimUuid);
        log.debug("EST request claim {} {}", claimUuid, deleted == 1 ? "released" : "kept");
    }
}
