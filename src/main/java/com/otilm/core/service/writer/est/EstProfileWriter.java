package com.otilm.core.service.writer.est;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EstProfileWriter {

    private final EstProfileRepository estProfileRepository;
    private final TokenProfileRepository tokenProfileRepository;

    public EstProfileWriter(EstProfileRepository estProfileRepository, TokenProfileRepository tokenProfileRepository) {
        this.estProfileRepository = estProfileRepository;
        this.tokenProfileRepository = tokenProfileRepository;
    }

    /**
     * Holds the token profile against a disable or delete until the saving transaction ends, and refuses it when a
     * disable committed after the save was checked. Makes no connector call.
     */
    @Transactional(rollbackFor = Exception.class)
    public void requireKeyRecoveryTokenProfileEnabled(UUID tokenProfileUuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository
                .findWithSharedLockByUuid(tokenProfileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfileUuid));
        if (!Boolean.TRUE.equals(tokenProfile.getEnabled())) {
            throw new ValidationException("Key recovery token profile " + tokenProfile.getName() + " is disabled");
        }
    }

    @Transactional
    public void clearSystemDefault() {
        estProfileRepository.clearSystemDefault();
    }

    @Transactional
    public void clearSystemDefaultExcept(UUID uuid) {
        estProfileRepository.clearSystemDefaultExcept(uuid);
    }

    @Transactional
    public void removeTrustedCaCertificates(List<UUID> certificateUuids) {
        // An empty list would render as IN (), which is not valid SQL.
        if (certificateUuids.isEmpty()) {
            return;
        }
        estProfileRepository.removeTrustedCaCertificates(certificateUuids);
    }
}
