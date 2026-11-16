package com.otilm.core.util.builders;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Builds an in-memory {@link EstProfile}; tests override only the fields whose values drive the assertion under test.
 * The defaults produce a profile named {@code est-devices} with the {@code CERTIFICATE_REGISTRATION} authentication
 * policy, the two values the database requires. Every other field keeps the entity's own default until its
 * {@code withXxx} is called, so a test of those defaults reads them as the entity sets them. Persistence goes through
 * {@code EstProfileRepository}, not this builder.
 */
public final class EstProfileBuilder {

    private String name = "est-devices";
    private EstAuthenticationPolicy authenticationPolicy = EstAuthenticationPolicy.CERTIFICATE_REGISTRATION;
    private final List<Consumer<EstProfile>> overrides = new ArrayList<>();

    public static EstProfileBuilder anEstProfile() {
        return new EstProfileBuilder();
    }

    public EstProfileBuilder withUuid(UUID uuid) {
        return override(profile -> profile.setUuid(uuid));
    }

    public EstProfileBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public EstProfileBuilder withDescription(String description) {
        return override(profile -> profile.setDescription(description));
    }

    public EstProfileBuilder withEnabled(boolean enabled) {
        return override(profile -> profile.setEnabled(enabled));
    }

    public EstProfileBuilder withSystemDefault(boolean systemDefault) {
        return override(profile -> profile.setSystemDefault(systemDefault));
    }

    public EstProfileBuilder withRaProfile(RaProfile raProfile) {
        return override(profile -> profile.setRaProfile(raProfile));
    }

    public EstProfileBuilder withAuthenticationPolicy(EstAuthenticationPolicy authenticationPolicy) {
        this.authenticationPolicy = authenticationPolicy;
        return this;
    }

    public EstProfileBuilder withBasicCredentialSecrets(UUID... secretUuids) {
        List<UUID> secrets = List.of(secretUuids);
        return override(profile -> profile.setBasicCredentialSecretUuids(new ArrayList<>(secrets)));
    }

    public EstProfileBuilder withTrustedCaCertificates(UUID... certificateUuids) {
        List<UUID> certificates = List.of(certificateUuids);
        return override(profile -> profile.setTrustedCaCertificateUuids(new ArrayList<>(certificates)));
    }

    public EstProfileBuilder withAllowRenewal(boolean allowRenewal) {
        return override(profile -> profile.setAllowRenewal(allowRenewal));
    }

    public EstProfileBuilder withAllowRekey(boolean allowRekey) {
        return override(profile -> profile.setAllowRekey(allowRekey));
    }

    public EstProfileBuilder withRenewalThreshold(Integer renewalThreshold) {
        return override(profile -> profile.setRenewalThreshold(renewalThreshold));
    }

    public EstProfileBuilder withServerKeyGeneration(boolean serverKeyGeneration) {
        return override(profile -> profile.setServerKeyGeneration(serverKeyGeneration));
    }

    public EstProfileBuilder withIssueWaitTimeout(int seconds) {
        return override(profile -> profile.setIssueWaitTimeout(seconds));
    }

    public EstProfileBuilder withRetryAfter(int seconds) {
        return override(profile -> profile.setRetryAfter(seconds));
    }

    public EstProfileBuilder withServerKeyGenerationTimeout(int seconds) {
        return override(profile -> profile.setServerKeyGenerationTimeout(seconds));
    }

    public EstProfileBuilder withKeyRecovery(boolean keyRecovery) {
        return override(profile -> profile.setKeyRecovery(keyRecovery));
    }

    public EstProfileBuilder withKeyRecoveryTokenProfile(TokenProfile tokenProfile) {
        return override(profile -> profile.setKeyRecoveryTokenProfile(tokenProfile));
    }

    public EstProfileBuilder withKeyRecoveryKeyAttributes(String keyAttributesJson) {
        return override(profile -> profile.setKeyRecoveryKeyAttributes(keyAttributesJson));
    }

    public EstProfileBuilder withCertificateAssociations(ProtocolCertificateAssociations certificateAssociations) {
        return override(profile -> profile.setCertificateAssociations(certificateAssociations));
    }

    public EstProfile build() {
        EstProfile profile = new EstProfile();
        profile.setName(name);
        profile.setAuthenticationPolicy(authenticationPolicy);
        overrides.forEach(override -> override.accept(profile));
        return profile;
    }

    private EstProfileBuilder override(Consumer<EstProfile> change) {
        overrides.add(change);
        return this;
    }
}
