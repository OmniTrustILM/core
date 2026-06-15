package com.otilm.core.util.builders;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflowBuilder;
import com.otilm.core.model.signing.workflow.SigningWorkflow;

import java.util.List;
import java.util.UUID;

public final class SigningProfileModelBuilder {

    private UUID uuid = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private String name = "test-profile";
    private String description = null;
    private int version = 1;
    private boolean enabled = true;
    private List<SigningProtocol> enabledProtocols = List.of(SigningProtocol.TSP);
    private UUID tspProfileUuid = UUID.fromString("00000000-0000-0000-0000-000000000004");
    private SigningWorkflow workflow = ManagedTimestampingWorkflowBuilder.aManagedTimestampingWorkflow()
            .timeQualityConfigurationUuid(UUID.fromString("00000000-0000-0000-0000-000000000002"))
            .build();
    private SigningSchemeModel signingScheme = new StaticKeyManagedSigning(
            UUID.fromString("00000000-0000-0000-0000-000000000003"), List.of());
    private SigningRecordPolicyModel recordPolicy = new SigningRecordPolicyModel(
            true, false, false, false, false, null, false, SigningRecordPersistenceMode.DEFERRED_DURABLE);

    public static SigningProfileModelBuilder aSigningProfile() {
        return new SigningProfileModelBuilder();
    }

    public static SigningProfileModel<?, ?> valid() {
        return aSigningProfile().build();
    }

    public SigningProfileModelBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public SigningProfileModelBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public SigningProfileModelBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public SigningProfileModelBuilder withVersion(int version) {
        this.version = version;
        return this;
    }

    public SigningProfileModelBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public SigningProfileModelBuilder withEnabledProtocols(List<SigningProtocol> v) {
        this.enabledProtocols = v;
        return this;
    }

    public SigningProfileModelBuilder withTspProfileUuid(UUID v) {
        this.tspProfileUuid = v;
        return this;
    }

    public SigningProfileModelBuilder withWorkflow(SigningWorkflow v) {
        this.workflow = v;
        return this;
    }

    public SigningProfileModelBuilder withSigningScheme(SigningSchemeModel v) {
        this.signingScheme = v;
        return this;
    }

    public SigningProfileModelBuilder withRecordPolicy(SigningRecordPolicyModel v) {
        this.recordPolicy = v;
        return this;
    }

    @SuppressWarnings({"unchecked", "java:S119"})
    public <W extends SigningWorkflow, SM extends SigningSchemeModel> SigningProfileModel<W, SM> build() {
        return new SigningProfileModel<>(uuid, name, description, version, enabled, enabledProtocols, tspProfileUuid, (W) workflow, (SM) signingScheme, recordPolicy);
    }
}
