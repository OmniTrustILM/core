package com.otilm.core.architecture;

import com.otilm.core.dao.repository.CertificateRepository;

/** A builder planted for {@link TestStyleArchSelfTest} that depends on a repository. */
public final class PlantedRepositoryBuilder {

    private final CertificateRepository certificateRepository;

    PlantedRepositoryBuilder(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    public long build() {
        return certificateRepository.count();
    }
}
