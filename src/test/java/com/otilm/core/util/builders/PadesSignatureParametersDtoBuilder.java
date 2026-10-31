package com.otilm.core.util.builders;

import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureScope;
import java.util.Arrays;
import java.util.List;

/**
 * Test builder for {@link PadesSignatureParametersDto} with no defaults, because absence is what the merge, permission
 * and discovery rules read. The subtype fixes the family discriminator.
 */
public final class PadesSignatureParametersDtoBuilder {

    private String reason;
    private String location;
    private String contactInfo;
    private String signerName;
    private PadesSignatureScope signatureScope;
    private CommitmentType commitmentType;
    private List<String> claimedRoles;
    private PadesVisibleSignatureDtoBuilder visibleSignature;

    public static PadesSignatureParametersDtoBuilder aPadesParameters() {
        return new PadesSignatureParametersDtoBuilder();
    }

    public PadesSignatureParametersDtoBuilder withReason(String reason) {
        this.reason = reason;
        return this;
    }

    public PadesSignatureParametersDtoBuilder withLocation(String location) {
        this.location = location;
        return this;
    }

    public PadesSignatureParametersDtoBuilder withContactInfo(String contactInfo) {
        this.contactInfo = contactInfo;
        return this;
    }

    public PadesSignatureParametersDtoBuilder withSignerName(String signerName) {
        this.signerName = signerName;
        return this;
    }

    public PadesSignatureParametersDtoBuilder withSignatureScope(PadesSignatureScope signatureScope) {
        this.signatureScope = signatureScope;
        return this;
    }

    public PadesSignatureParametersDtoBuilder withCommitmentType(CommitmentType commitmentType) {
        this.commitmentType = commitmentType;
        return this;
    }

    /** Kept as a plain list, nulls and all — the refusal of a null element is itself a scenario under test. */
    public PadesSignatureParametersDtoBuilder withClaimedRoles(String... claimedRoles) {
        this.claimedRoles = Arrays.asList(claimedRoles);
        return this;
    }

    public PadesSignatureParametersDtoBuilder withVisibleSignature(PadesVisibleSignatureDtoBuilder visibleSignature) {
        this.visibleSignature = visibleSignature;
        return this;
    }

    public PadesSignatureParametersDto build() {
        PadesSignatureParametersDto parameters = new PadesSignatureParametersDto();
        parameters.setReason(reason);
        parameters.setLocation(location);
        parameters.setContactInfo(contactInfo);
        parameters.setSignerName(signerName);
        parameters.setSignatureScope(signatureScope);
        parameters.setCommitmentType(commitmentType);
        parameters.setClaimedRoles(claimedRoles);
        parameters.setVisibleSignature(visibleSignature == null ? null : visibleSignature.build());
        return parameters;
    }
}
