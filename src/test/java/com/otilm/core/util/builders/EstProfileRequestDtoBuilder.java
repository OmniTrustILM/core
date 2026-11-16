package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.est.BaseEstProfileRequestDto;
import com.otilm.api.model.client.est.EstProfileEditRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class EstProfileRequestDtoBuilder {

    private String name = "est-devices";
    private String description;
    private UUID raProfileUuid;
    private boolean systemDefault;
    private EstAuthenticationPolicy authenticationPolicy = EstAuthenticationPolicy.CERTIFICATE_REGISTRATION;
    private List<UUID> basicCredentialSecretUuids = List.of();
    private List<UUID> trustedCaCertificateUuids = List.of();
    private boolean allowRenewal = true;
    private boolean allowRekey = true;
    private Integer renewalThreshold;
    private boolean serverKeyGeneration;
    private boolean keyRecovery;
    private Integer issueWaitTimeout;
    private Integer retryAfter;
    private Integer serverKeyGenerationTimeout;
    private UUID keyRecoveryTokenProfileUuid;
    private List<RequestAttribute> keyRecoveryKeyAttributes = List.of();
    private List<RequestAttribute> issueCertificateAttributes = List.of();
    private List<RequestAttribute> customAttributes = List.of();
    private ProtocolCertificateAssociationsRequestDto certificateAssociations;

    public static EstProfileRequestDtoBuilder anEstProfileRequest() {
        return new EstProfileRequestDtoBuilder();
    }

    public EstProfileRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public EstProfileRequestDtoBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public EstProfileRequestDtoBuilder withRaProfile(UUID raProfileUuid) {
        this.raProfileUuid = raProfileUuid;
        return this;
    }

    public EstProfileRequestDtoBuilder asSystemDefault() {
        this.systemDefault = true;
        return this;
    }

    public EstProfileRequestDtoBuilder withAuthenticationPolicy(EstAuthenticationPolicy authenticationPolicy) {
        this.authenticationPolicy = authenticationPolicy;
        return this;
    }

    public EstProfileRequestDtoBuilder withBasicCredentialSecrets(UUID... secretUuids) {
        this.basicCredentialSecretUuids = List.of(secretUuids);
        return this;
    }

    public EstProfileRequestDtoBuilder withTrustedCaCertificates(UUID... certificateUuids) {
        this.trustedCaCertificateUuids = List.of(certificateUuids);
        return this;
    }

    public EstProfileRequestDtoBuilder withAllowRekey(boolean allowRekey) {
        this.allowRekey = allowRekey;
        return this;
    }

    public EstProfileRequestDtoBuilder withRenewalThreshold(Integer renewalThreshold) {
        this.renewalThreshold = renewalThreshold;
        return this;
    }

    /** Key recovery needs server-side key generation, so this turns both on. */
    public EstProfileRequestDtoBuilder withKeyRecovery(UUID tokenProfileUuid, List<RequestAttribute> keyAttributes) {
        this.serverKeyGeneration = true;
        this.keyRecovery = true;
        this.keyRecoveryTokenProfileUuid = tokenProfileUuid;
        this.keyRecoveryKeyAttributes = keyAttributes;
        return this;
    }

    public EstProfileRequestDtoBuilder withTimings(int issueWaitTimeout, int retryAfter,
            int serverKeyGenerationTimeout) {
        this.issueWaitTimeout = issueWaitTimeout;
        this.retryAfter = retryAfter;
        this.serverKeyGenerationTimeout = serverKeyGenerationTimeout;
        return this;
    }

    public EstProfileRequestDtoBuilder withIssueCertificateAttributes(List<RequestAttribute> issueAttributes) {
        this.issueCertificateAttributes = issueAttributes;
        return this;
    }

    public EstProfileRequestDtoBuilder withCustomAttributes(List<RequestAttribute> customAttributes) {
        this.customAttributes = customAttributes;
        return this;
    }

    public EstProfileRequestDtoBuilder withCertificateAssociations(
            ProtocolCertificateAssociationsRequestDto certificateAssociations) {
        this.certificateAssociations = certificateAssociations;
        return this;
    }

    public EstProfileRequestDto build() {
        EstProfileRequestDto dto = new EstProfileRequestDto();
        dto.setName(name);
        fill(dto);
        return dto;
    }

    /** The same settings as an update, which never carries the name. */
    public EstProfileEditRequestDto buildEdit() {
        EstProfileEditRequestDto dto = new EstProfileEditRequestDto();
        fill(dto);
        return dto;
    }

    private void fill(BaseEstProfileRequestDto dto) {
        dto.setDescription(description);
        dto.setRaProfileUuid(raProfileUuid);
        dto.setSystemDefault(systemDefault);
        dto.setAuthenticationPolicy(authenticationPolicy);
        dto.setBasicCredentialSecretUuids(new ArrayList<>(basicCredentialSecretUuids));
        dto.setTrustedCaCertificateUuids(new ArrayList<>(trustedCaCertificateUuids));
        dto.setAllowRenewal(allowRenewal);
        dto.setAllowRekey(allowRekey);
        dto.setRenewalThreshold(renewalThreshold);
        dto.setServerKeyGeneration(serverKeyGeneration);
        dto.setKeyRecovery(keyRecovery);
        if (issueWaitTimeout != null) {
            dto.setIssueWaitTimeout(issueWaitTimeout);
        }
        if (retryAfter != null) {
            dto.setRetryAfter(retryAfter);
        }
        if (serverKeyGenerationTimeout != null) {
            dto.setServerKeyGenerationTimeout(serverKeyGenerationTimeout);
        }
        dto.setKeyRecoveryTokenProfileUuid(keyRecoveryTokenProfileUuid);
        dto.setKeyRecoveryKeyAttributes(new ArrayList<>(keyRecoveryKeyAttributes));
        dto.setIssueCertificateAttributes(new ArrayList<>(issueCertificateAttributes));
        dto.setCustomAttributes(new ArrayList<>(customAttributes));
        dto.setCertificateAssociations(certificateAssociations);
    }
}
