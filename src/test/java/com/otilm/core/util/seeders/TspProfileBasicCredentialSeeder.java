package com.otilm.core.util.seeders;

import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Seeds a TSP profile with one basic credential, the owner of the secret that holds its password. */
@Component
public class TspProfileBasicCredentialSeeder {

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @Autowired
    private TspProfileBasicCredentialRepository credentialRepository;

    public TspProfileBasicCredential persistCredential(Secret password) {
        TspProfile profile = new TspProfile();
        profile.setName("tsa");
        tspProfileRepository.save(profile);

        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        credential.setUsername("tsa-client");
        credential.setSecretUuid(password.getUuid());
        credential.setMappedUserUuid(UUID.randomUUID());
        return credentialRepository.save(credential);
    }
}
