package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class SigningProfileWriter {

    private final SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    public SigningProfileWriter(SigningProfileVersionRepository signingProfileVersionRepository) {
        this.signingProfileVersionRepository = signingProfileVersionRepository;
    }

    @Transactional
    public void deleteAllVersionsBySigningProfileUuid(UUID signingProfileUuid) {
        signingProfileVersionRepository.deleteAllBySigningProfileUuid(signingProfileUuid);
    }
}
