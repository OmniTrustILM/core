package com.otilm.core.util.builders;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SignatureParameterPolicy;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.util.CertificateTestUtil;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

public final class ResolvedManagedContentSigningProfileBuilder {

    private UUID uuid = UUID.fromString("00000000-0000-0000-0000-0000000000c5");
    private String name = "test-content-signing-profile";
    private String description = null;
    private int version = 1;
    private boolean enabled = true;
    private List<SigningProtocol> enabledProtocols = List.of(SigningProtocol.CSC_API);
    private List<RequestAttribute> signatureFormattingConnectorAttributes = List.of();
    private SignatureFamilyDeclarationDto familyDeclaration = SignatureFamilyDeclarationDtoBuilder
            .aFamilyDeclaration(SignatureFamily.PADES)
            .build();
    private SignatureLevel maxLevel = SignatureLevel.TIMESTAMPED;
    private String timestampSourceProfileName = "internal-tsa";
    private Long documentSizeCap = null;
    private CertificatePurposeRequirements certificatePurpose = CertificatePurposeRequirements.NONE;
    private SignatureParameterPolicy parameterPolicy = SignatureParameterPolicy.DENY_ALL;
    private ApiClientConnectorInfo signatureFormattingConnector = null;
    private ResolvedManagedScheme resolvedScheme = defaultScheme();

    public static ResolvedManagedContentSigningProfileBuilder aResolvedContentSigningProfile() {
        return new ResolvedManagedContentSigningProfileBuilder();
    }

    public ResolvedManagedContentSigningProfileBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withVersion(int version) {
        this.version = version;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withEnabledProtocols(List<SigningProtocol> enabledProtocols) {
        this.enabledProtocols = enabledProtocols;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withSignatureFormattingConnectorAttributes(
            List<RequestAttribute> signatureFormattingConnectorAttributes) {
        this.signatureFormattingConnectorAttributes = signatureFormattingConnectorAttributes;
        return this;
    }

    /** Uses the declaration a connector serving the family sends, with every level up to {@code ARCHIVAL}. */
    public ResolvedManagedContentSigningProfileBuilder withFamily(SignatureFamily family) {
        this.familyDeclaration = SignatureFamilyDeclarationDtoBuilder.aFamilyDeclaration(family).build();
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withFamilyDeclaration(
            SignatureFamilyDeclarationDto familyDeclaration) {
        this.familyDeclaration = familyDeclaration;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withMaxLevel(SignatureLevel maxLevel) {
        this.maxLevel = maxLevel;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withTimestampSourceProfileName(
            String timestampSourceProfileName) {
        this.timestampSourceProfileName = timestampSourceProfileName;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withDocumentSizeCap(Long documentSizeCap) {
        this.documentSizeCap = documentSizeCap;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withCertificatePurpose(
            CertificatePurposeRequirements certificatePurpose) {
        this.certificatePurpose = certificatePurpose;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withParameterPolicy(SignatureParameterPolicy parameterPolicy) {
        this.parameterPolicy = parameterPolicy;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withSignatureFormattingConnector(
            ApiClientConnectorInfo signatureFormattingConnector) {
        this.signatureFormattingConnector = signatureFormattingConnector;
        return this;
    }

    public ResolvedManagedContentSigningProfileBuilder withResolvedScheme(ResolvedManagedScheme resolvedScheme) {
        this.resolvedScheme = resolvedScheme;
        return this;
    }

    public ResolvedManagedContentSigningProfile build() {
        return new ResolvedManagedContentSigningProfile(uuid, name, description, version, enabled, enabledProtocols,
                signatureFormattingConnectorAttributes, familyDeclaration, maxLevel, timestampSourceProfileName,
                documentSizeCap, certificatePurpose, parameterPolicy, signatureFormattingConnector, resolvedScheme);
    }

    private static ResolvedManagedScheme defaultScheme() {
        try {
            X509Certificate certificate = CertificateTestUtil.createCertificateWithoutEku();
            return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(),
                    CertificateChain.of(certificate), List.of());
        } catch (Exception e) {
            throw new IllegalStateException("failed to build default resolved scheme for tests", e);
        }
    }
}
