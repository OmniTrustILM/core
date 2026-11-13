package com.otilm.core.util.seeders;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.util.SecretsUtil;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Seeds Secrets as the vault service leaves them: the row, the vault profile it is sourced from, and a latest version
 * whose fingerprint is the one of the content. No vault is called and no content is stored, as Core keeps only the
 * fingerprint. Every method saves through the repositories and returns the saved entity.
 */
@Component
public class SecretSeeder {

    private static final int FIRST_VERSION = 1;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private SecretVersionRepository secretVersionRepository;

    /** Seeds an enabled, active Basic authentication Secret whose latest version fingerprints the credentials. */
    public Secret seedBasicAuthSecret(String name, String username, String password) {
        String fingerprint = fingerprintOf(username, password);
        return seedSecret(name, SecretType.BASIC_AUTH, SecretState.ACTIVE, true, fingerprint);
    }

    /**
     * @param fingerprint the fingerprint of the latest version; a test gives a Secret of another type or state the
     * fingerprint of Basic credentials to show that the type or the state alone is what refuses it
     */
    public Secret seedSecret(String name, SecretType type, SecretState state, boolean enabled, String fingerprint) {
        VaultProfile vaultProfile = seedVaultProfile(name);
        SecretVersion version = seedVersion(vaultProfile.getUuid(), FIRST_VERSION, fingerprint);
        Secret secret = new Secret();
        secret.setName(name);
        secret.setType(type);
        secret.setState(state);
        secret.setEnabled(enabled);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setLatestVersion(version);
        Secret saved = secretRepository.save(secret);
        version.setSecretUuid(saved.getUuid());
        secretVersionRepository.save(version);
        return saved;
    }

    /**
     * Stores new Basic credentials as a newer version of a Secret that this seeder returned and makes it the latest, as
     * an update of its content does.
     */
    public Secret replaceBasicAuthContent(Secret secret, String username, String password) {
        int nextVersion = secret.getLatestVersion().getVersion() + 1;
        SecretVersion version = seedVersion(secret.getSourceVaultProfileUuid(), nextVersion,
                fingerprintOf(username, password));
        version.setSecretUuid(secret.getUuid());
        secretVersionRepository.save(version);
        secret.setLatestVersion(version);
        return secretRepository.save(secret);
    }

    /** Enables or disables the vault profile that the Secret is sourced from. */
    public void setSourceVaultProfileEnabled(Secret secret, boolean enabled) {
        VaultProfile vaultProfile = vaultProfileRepository.findById(secret.getSourceVaultProfileUuid()).orElseThrow();
        vaultProfile.setEnabled(enabled);
        vaultProfileRepository.save(vaultProfile);
    }

    /** The fingerprint that Core stores for Basic credentials. */
    public static String fingerprintOf(String username, String password) {
        try {
            return SecretsUtil.calculateSecretContentFingerprint(new BasicAuthSecretContent(username, password));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private VaultProfile seedVaultProfile(String name) {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("vault-" + name);
        vaultInstanceRepository.save(vaultInstance);
        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("vault-profile-" + name);
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setEnabled(true);
        return vaultProfileRepository.save(vaultProfile);
    }

    private SecretVersion seedVersion(UUID vaultProfileUuid, int number, String fingerprint) {
        SecretVersion version = new SecretVersion();
        version.setVersion(number);
        version.setVaultProfileUuid(vaultProfileUuid);
        version.setFingerprint(fingerprint);
        return secretVersionRepository.save(version);
    }
}
