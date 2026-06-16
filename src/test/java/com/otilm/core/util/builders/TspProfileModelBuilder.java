package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.model.signing.TspProfileModel.BasicCredentialRef;

import java.util.List;
import java.util.UUID;

public final class TspProfileModelBuilder {

    private UUID uuid = UUID.randomUUID();
    private String name = "tsp-profile";
    private String description = null;
    private boolean enabled = true;
    private UUID defaultSigningProfileUuid = null;
    private String defaultSigningProfileName = "default-signing-profile";
    private List<ResponseAttribute> customAttributes = List.of();
    private List<TspAuthenticationMethod> allowedAuthenticationMethods = List.of();
    private List<BasicCredentialRef> basicCredentials = List.of();
    private UUID vaultProfileUuid = null;

    public static TspProfileModelBuilder aTspProfile() {
        return new TspProfileModelBuilder();
    }

    public TspProfileModelBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public TspProfileModelBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public TspProfileModelBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public TspProfileModelBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public TspProfileModelBuilder withDefaultSigningProfileUuid(UUID v) {
        this.defaultSigningProfileUuid = v;
        return this;
    }

    public TspProfileModelBuilder withDefaultSigningProfileName(String v) {
        this.defaultSigningProfileName = v;
        return this;
    }

    public TspProfileModelBuilder withCustomAttributes(List<ResponseAttribute> v) {
        this.customAttributes = v;
        return this;
    }

    public TspProfileModelBuilder withAllowedAuthenticationMethods(List<TspAuthenticationMethod> v) {
        this.allowedAuthenticationMethods = v;
        return this;
    }

    public TspProfileModelBuilder withBasicCredentials(List<BasicCredentialRef> v) {
        this.basicCredentials = v;
        return this;
    }

    public TspProfileModelBuilder withVaultProfileUuid(UUID v) {
        this.vaultProfileUuid = v;
        return this;
    }

    public TspProfileModel build() {
        return new TspProfileModel(uuid, name, description, enabled, defaultSigningProfileUuid,
                defaultSigningProfileName, customAttributes, allowedAuthenticationMethods, basicCredentials, vaultProfileUuid);
    }
}
