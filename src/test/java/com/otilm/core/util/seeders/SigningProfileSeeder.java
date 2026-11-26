package com.otilm.core.util.seeders;

import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Seeds managed static-key raw-signing profiles with their stored versions, for tests about the certificates those
 * versions hold. The highest version seeded is the profile's current one.
 */
@Component
public class SigningProfileSeeder {

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    /** A profile at version 1, which signs with the certificate. */
    public SigningProfile seedSigningWith(String name, Certificate certificate) {
        SigningProfile profile = saveProfile(name, 1);
        saveVersion(profile, 1, certificate);
        return profile;
    }

    /**
     * A profile moved to another certificate after it had signed: version 1 keeps the earlier certificate, and the
     * current version 2 signs with the later one.
     */
    public SigningProfile seedRenewedOnto(String name, Certificate earlierCertificate, Certificate laterCertificate) {
        SigningProfile profile = saveProfile(name, 2);
        saveVersion(profile, 1, earlierCertificate);
        saveVersion(profile, 2, laterCertificate);
        return profile;
    }

    private SigningProfile saveProfile(String name, int currentVersion) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(currentVersion);
        return signingProfileRepository.save(profile);
    }

    private void saveVersion(SigningProfile profile, int version, Certificate certificate) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.MANAGED);
        profileVersion.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersion.setCertificate(certificate);
        signingProfileVersionRepository.save(profileVersion);
    }
}
