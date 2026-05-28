package com.czertainly.core.model.signing;

import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.scheme.StaticKeyManagedSigning;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflowBuilder;
import com.czertainly.core.model.signing.workflow.SigningWorkflow;

import java.util.List;
import java.util.UUID;

public final class SigningProfileModelBuilder {

    private UUID uuid = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private String name = "test-profile";
    private String description = null;
    private int version = 1;
    private boolean enabled = true;
    private List<SigningProtocol> enabledProtocols = List.of(SigningProtocol.TSP);
    private SigningWorkflow workflow = ManagedTimestampingWorkflowBuilder.aManagedTimestampingWorkflow()
            .timeQualityConfigurationUuid(UUID.fromString("00000000-0000-0000-0000-000000000002"))
            .build();
    private SigningSchemeModel signingScheme = new StaticKeyManagedSigning(
            UUID.fromString("00000000-0000-0000-0000-000000000003"), List.of());

    public static SigningProfileModelBuilder aSigningProfile() {
        return new SigningProfileModelBuilder();
    }

    public static SigningProfileModel<?, ?> valid() {
        return aSigningProfile().build();
    }

    public SigningProfileModelBuilder uuid(UUID uuid) { this.uuid = uuid; return this; }
    public SigningProfileModelBuilder name(String name) { this.name = name; return this; }
    public SigningProfileModelBuilder description(String description) { this.description = description; return this; }
    public SigningProfileModelBuilder version(int version) { this.version = version; return this; }
    public SigningProfileModelBuilder enabled(boolean enabled) { this.enabled = enabled; return this; }
    public SigningProfileModelBuilder enabledProtocols(List<SigningProtocol> v) { this.enabledProtocols = v; return this; }
    public SigningProfileModelBuilder workflow(SigningWorkflow v) { this.workflow = v; return this; }
    public SigningProfileModelBuilder signingScheme(SigningSchemeModel v) { this.signingScheme = v; return this; }

    @SuppressWarnings("unchecked")
    public <W extends SigningWorkflow, SM extends SigningSchemeModel> SigningProfileModel<W, SM> build() {
        return new SigningProfileModel<>(uuid, name, description, version, enabled, enabledProtocols, (W) workflow, (SM) signingScheme);
    }
}
