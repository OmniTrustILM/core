package com.otilm.core.util.builders;

import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.util.CertificateTestUtil;
import java.util.List;
import java.util.UUID;

/**
 * Builds a resolved raw-signing profile with no certificate-purpose requirement and a static-key scheme over a valid
 * signing certificate; tests override only the field their scenario is about.
 */
public final class ResolvedManagedRawSigningProfileBuilder {

    private UUID uuid = UUID.fromString("00000000-0000-0000-0000-0000000000d7");
    private String name = "test-raw-signing-profile";
    private String description = null;
    private int version = 1;
    private boolean enabled = true;
    private List<SigningProtocol> enabledProtocols = List.of(SigningProtocol.ILM_NATIVE);
    private CertificatePurposeRequirements certificatePurpose = CertificatePurposeRequirements.NONE;
    private ResolvedManagedScheme resolvedScheme = defaultScheme();

    public static ResolvedManagedRawSigningProfileBuilder aResolvedRawSigningProfile() {
        return new ResolvedManagedRawSigningProfileBuilder();
    }

    public ResolvedManagedRawSigningProfileBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withVersion(int version) {
        this.version = version;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withEnabledProtocols(List<SigningProtocol> enabledProtocols) {
        this.enabledProtocols = enabledProtocols;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withCertificatePurpose(
            CertificatePurposeRequirements certificatePurpose) {
        this.certificatePurpose = certificatePurpose;
        return this;
    }

    public ResolvedManagedRawSigningProfileBuilder withResolvedScheme(ResolvedManagedScheme resolvedScheme) {
        this.resolvedScheme = resolvedScheme;
        return this;
    }

    public ResolvedManagedRawSigningProfile build() {
        return new ResolvedManagedRawSigningProfile(uuid, name, description, version, enabled, enabledProtocols,
                certificatePurpose, resolvedScheme);
    }

    private static ResolvedManagedScheme defaultScheme() {
        try {
            return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(),
                    CertificateChain.of(CertificateTestUtil.createCertificateWithoutEku()), List.of());
        } catch (Exception e) {
            throw new IllegalStateException("failed to build default resolved scheme for tests", e);
        }
    }
}
