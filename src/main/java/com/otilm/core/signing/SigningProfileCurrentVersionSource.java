package com.otilm.core.signing;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.reference.CurrentVersionSource;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class SigningProfileCurrentVersionSource implements CurrentVersionSource {

    private final SigningProfileRepository signingProfileRepository;

    public SigningProfileCurrentVersionSource(SigningProfileRepository signingProfileRepository) {
        this.signingProfileRepository = signingProfileRepository;
    }

    @Override
    public Resource resource() {
        return Resource.SIGNING_PROFILE;
    }

    @Override
    public Optional<Integer> currentVersion(UUID objectUuid) {
        return signingProfileRepository.findById(objectUuid).map(SigningProfile::getLatestVersion);
    }
}
