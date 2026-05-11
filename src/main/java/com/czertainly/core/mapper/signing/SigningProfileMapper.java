package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.signing.profile.SigningProfileDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileListDto;
import com.czertainly.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.czertainly.api.model.client.signing.profile.record.SigningRecordPolicyDto;
import com.czertainly.api.model.client.signing.profile.scheme.DelegatedSigningDto;
import com.czertainly.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.czertainly.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningDto;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.scheme.StaticKeyManagedSigningDto;
import com.czertainly.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.czertainly.api.model.client.signing.profile.workflow.RawSigningWorkflowDto;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.client.signing.profile.workflow.TimestampingWorkflowDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.workflow.*;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.scheme.DelegatedSigning;
import com.czertainly.core.model.signing.scheme.OneTimeKeyManagedSigning;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.scheme.StaticKeyManagedSigning;
import org.jspecify.annotations.NonNull;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class SigningProfileMapper {

    private SigningProfileMapper() {
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public mappers — DTO
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Converts a {@link SigningProfile} and {@link SigningProfileVersion} entities to a full {@link SigningProfileDto},
     * populating custom attributes, connector signing-operation attributes, and workflow formatter attributes.
     */
    public static SigningProfileDto toDto(SigningProfile header, SigningProfileVersion version,
                                          List<ResponseAttribute> customAttributes,
                                          List<ResponseAttribute> signingOperationAttributes,
                                          List<ResponseAttribute> signatureFormatterConnectorAttributes) {
        SigningProfileDto dto = new SigningProfileDto();
        dto.setUuid(header.getUuid().toString());
        dto.setName(header.getName());
        dto.setDescription(header.getDescription());
        dto.setVersion(version.getVersion() != null ? version.getVersion() : 1);
        dto.setEnabled(header.getEnabled() != null ? header.getEnabled() : false);
        dto.setCustomAttributes(safeList(customAttributes));

        // Build signing scheme DTO from version
        if (version.getSigningScheme() == SigningScheme.DELEGATED) {
            DelegatedSigningDto delegatedDto = new DelegatedSigningDto();
            if (version.getDelegatedSignerConnectorUuid() != null) {
                NameAndUuidDto ref = new NameAndUuidDto();
                ref.setUuid(version.getDelegatedSignerConnectorUuid().toString());
                delegatedDto.setConnector(ref);
            }
            dto.setSigningScheme(delegatedDto);
        } else if (version.getSigningScheme() == SigningScheme.MANAGED && version.getManagedSigningType() != null) {
            if (version.getManagedSigningType() == ManagedSigningType.STATIC_KEY) {
                StaticKeyManagedSigningDto staticDto = new StaticKeyManagedSigningDto();
                if (version.getCertificateUuid() != null && version.getCertificate() != null) {
                    staticDto.setCertificate(version.getCertificate().mapToSimpleDto(null));
                }
                staticDto.setSigningOperationAttributes(safeList(signingOperationAttributes));
                dto.setSigningScheme(staticDto);
            } else if (version.getManagedSigningType() == ManagedSigningType.ONE_TIME_KEY) {
                OneTimeKeyManagedSigningDto oneTimeDto = new OneTimeKeyManagedSigningDto();
                if (version.getTokenProfileUuid() != null) {
                    NameAndUuidDto ref = new NameAndUuidDto();
                    ref.setUuid(version.getTokenProfileUuid().toString());
                    oneTimeDto.setTokenProfile(ref);
                }
                if (version.getRaProfileUuid() != null) {
                    NameAndUuidDto ref = new NameAndUuidDto();
                    ref.setUuid(version.getRaProfileUuid().toString());
                    oneTimeDto.setRaProfile(ref);
                }
                if (version.getCsrTemplateUuid() != null) {
                    NameAndUuidDto ref = new NameAndUuidDto();
                    ref.setUuid(version.getCsrTemplateUuid().toString());
                    oneTimeDto.setCsrTemplate(ref);
                }
                dto.setSigningScheme(oneTimeDto);
            }
        }

        // Build workflow DTO from version (timestamping also reads unversioned fields from header)
        dto.setWorkflow(switch (version.getWorkflowType()) {
            case CONTENT_SIGNING -> buildContentSigningWorkflowDto(version, signatureFormatterConnectorAttributes);
            case RAW_SIGNING -> new RawSigningWorkflowDto();
            case TIMESTAMPING -> buildTimestampingWorkflowDto(header, version, signatureFormatterConnectorAttributes);
        });

        // Enabled protocols from header (unversioned)
        if (header.getTspProfileUuid() != null) {
            dto.getEnabledProtocols().add(SigningProtocol.TSP);
        }

        SigningRecordPolicyDto policy = getSigningRecordPolicyDto(header, version);
        dto.setRecordPolicy(policy);
        return dto;
    }

    private static @NonNull SigningRecordPolicyDto getSigningRecordPolicyDto(SigningProfile header, SigningProfileVersion version) {
        SigningRecordPolicyDto policy = new SigningRecordPolicyDto();
        policy.setRecordMetadata(version.isRecordMetadata());
        policy.setRecordRequestMetadata(version.isRecordRequestMetadata());
        policy.setRecordSignature(version.isRecordSignature());
        policy.setRecordSignedDocument(version.isRecordSignedDocument());
        policy.setRecordDtbs(version.isRecordDtbs());
        policy.setRetentionDays(header.getRetentionDays());
        policy.setDeleteAfterRetrieval(header.isDeleteAfterRetrieval());
        policy.setPersistenceMode(header.getPersistenceMode());
        return policy;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public mappers — model layer
    // ──────────────────────────────────────────────────────────────────────────

    @FunctionalInterface
    public interface SigningProfileModelFactory<T> {
        T create(SigningProfile header, SigningProfileVersion version,
                 List<RequestAttribute> signingOperationAttributes,
                 List<RequestAttribute> signatureFormatterConnectorAttributes);
    }

    /**
     * Converts a {@link SigningProfile} and {@link SigningProfileVersion} entities to a {@link SigningProfileModel} typed with
     * {@link ManagedTimestampingWorkflow}. The caller must ensure the profile uses a managed timestamping workflow.
     *
     * @throws IllegalArgumentException if the profile's workflow type is not {@code TIMESTAMPING} or its signing scheme is not {@code MANAGED}
     */
    public static SigningProfileModel<ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel>, SigningSchemeModel> toManagedTimestampingModel(
            SigningProfile header,
            SigningProfileVersion version,
            List<RequestAttribute> signingOperationAttributes,
            List<RequestAttribute> signatureFormatterConnectorAttributes) {
        if (version.getWorkflowType() != SigningWorkflowType.TIMESTAMPING) {
            throw new IllegalArgumentException("Signing Profile '%s' does not use a timestamping workflow".formatted(header.getName()));
        }
        if (version.getSigningScheme() != SigningScheme.MANAGED) {
            throw new IllegalArgumentException("Signing Profile '%s' does not use a managed signing scheme".formatted(header.getName()));
        }

        List<SigningProtocol> protocols = header.getTspProfileUuid() != null ? List.of(SigningProtocol.TSP) : List.of();
        int ver = version.getVersion() != null ? version.getVersion() : 1;
        boolean enabled = header.getEnabled() != null ? header.getEnabled() : false;

        return new SigningProfileModel<>(
                header.getUuid(), header.getName(), header.getDescription(),
                ver, enabled, protocols,
                buildManagedTimestampingWorkflowModel(header, version, signatureFormatterConnectorAttributes),
                buildSchemeModel(version, signingOperationAttributes));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public mappers — list / simple / TSP
    // ──────────────────────────────────────────────────────────────────────────

    public static SigningProfileListDto toListDto(SigningProfile profile) {
        SigningProfileListDto dto = new SigningProfileListDto();
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setVersion(profile.getLatestVersion() != null ? profile.getLatestVersion() : 1);
        dto.setSigningWorkflowType(profile.getWorkflowType());
        dto.setEnabled(profile.getEnabled() != null ? profile.getEnabled() : false);
        return dto;
    }

    public static TspActivationDetailDto toTspActivationDto(SigningProfile profile) {
        TspActivationDetailDto dto = new TspActivationDetailDto();
        if (profile.getTspProfile() != null) {
            dto.setUuid(profile.getTspProfile().getUuid().toString());
            dto.setName(profile.getTspProfile().getName());
            dto.setAvailable(true);
            dto.setSigningUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + "/v1/protocols/tsp/signingProfile/" + profile.getName() + "/sign");
        } else {
            dto.setAvailable(false);
        }
        return dto;
    }

    public static SimplifiedSigningProfileDto toSimpleDto(SigningProfile signingProfile) {
        SimplifiedSigningProfileDto signingProfileDto = new SimplifiedSigningProfileDto();
        signingProfileDto.setUuid(signingProfile.getUuid().toString());
        signingProfileDto.setName(signingProfile.getName());
        signingProfileDto.setEnabled(Boolean.TRUE.equals(signingProfile.getEnabled()));
        return signingProfileDto;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // DTO builders (read from version)
    // ──────────────────────────────────────────────────────────────────────────

    private static ContentSigningWorkflowDto buildContentSigningWorkflowDto(
            SigningProfileVersion version, List<ResponseAttribute> signatureFormatterConnectorAttributes) {
        ContentSigningWorkflowDto wf = new ContentSigningWorkflowDto();
        setFormatterRef(version, wf::setSignatureFormatterConnector);
        wf.setSignatureFormatterConnectorAttributes(safeList(signatureFormatterConnectorAttributes));
        return wf;
    }

    private static TimestampingWorkflowDto buildTimestampingWorkflowDto(
            SigningProfile header, SigningProfileVersion version, List<ResponseAttribute> signatureFormatterConnectorAttributes) {
        TimestampingWorkflowDto wf = new TimestampingWorkflowDto();
        setFormatterRef(version, wf::setSignatureFormatterConnector);
        wf.setSignatureFormatterConnectorAttributes(safeList(signatureFormatterConnectorAttributes));
        wf.setQualifiedTimestamp(version.getQualifiedTimestamp());
        wf.setDefaultPolicyId(version.getDefaultPolicyId());
        wf.setAllowedPolicyIds(safeList(version.getAllowedPolicyIds()));
        if (version.getAllowedDigestAlgorithms() != null && !version.getAllowedDigestAlgorithms().isEmpty()) {
            wf.setAllowedDigestAlgorithms(
                    version.getAllowedDigestAlgorithms().stream()
                            .map(DigestAlgorithm::findByCode)
                            .toList()
            );
        }
        wf.setValidateTokenSignature(version.getValidateTokenSignature() != null ? version.getValidateTokenSignature() : false);
        if (header.getTimeQualityConfiguration() != null) {
            wf.setTimeQualityConfiguration(TimeQualityConfigurationMapper.toDto(header.getTimeQualityConfiguration(), List.of()));
        }
        return wf;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Model-layer workflow builders (read from version)
    // ──────────────────────────────────────────────────────────────────────────

    private static ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel> buildManagedTimestampingWorkflowModel(
            SigningProfile header, SigningProfileVersion version, List<RequestAttribute> signatureFormatterConnectorAttributes) {
        return new ManagedTimestampingWorkflow<>(
                version.getSignatureFormatterConnectorUuid(),
                safeList(signatureFormatterConnectorAttributes),
                version.getQualifiedTimestamp(),
                TimeQualityConfigurationMapper.toModel(header.getTimeQualityConfiguration()),
                version.getDefaultPolicyId(),
                safeList(version.getAllowedPolicyIds()),
                timestampingDigestAlgorithms(version),
                version.getValidateTokenSignature());
    }

    private static List<DigestAlgorithm> timestampingDigestAlgorithms(SigningProfileVersion version) {
        return version.getAllowedDigestAlgorithms() != null
                ? version.getAllowedDigestAlgorithms().stream().map(DigestAlgorithm::findByCode).toList()
                : List.of();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Model-layer scheme builder (read from version)
    // ──────────────────────────────────────────────────────────────────────────

    private static SigningSchemeModel buildSchemeModel(SigningProfileVersion version,
                                                       List<RequestAttribute> signingOperationAttributes) {
        return switch (version.getSigningScheme()) {
            case DELEGATED -> new DelegatedSigning(
                    version.getDelegatedSignerConnectorUuid(),
                    List.of());
            case MANAGED -> {
                if (version.getManagedSigningType() == null) {
                    throw new IllegalStateException("MANAGED signing profile version has no managedSigningType");
                }
                yield switch (version.getManagedSigningType()) {
                    case STATIC_KEY -> new StaticKeyManagedSigning(
                            version.getCertificate(),
                            safeList(signingOperationAttributes));
                    case ONE_TIME_KEY -> new OneTimeKeyManagedSigning(
                            version.getRaProfile(),
                            version.getTokenProfile(),
                            version.getCsrTemplateUuid(),
                            safeList(signingOperationAttributes));
                };
            }
        };
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Shared utilities
    // ──────────────────────────────────────────────────────────────────────────

    private static void setFormatterRef(SigningProfileVersion profileVersion, Consumer<NameAndUuidDto> setter) {
        NameAndUuidDto ref = new NameAndUuidDto();
        ref.setName(profileVersion.getSignatureFormatterConnector().getName());
        ref.setUuid(profileVersion.getSignatureFormatterConnectorUuid().toString());
        setter.accept(ref);
    }

    private static <T> List<T> safeList(List<T> list) {
        return list != null ? list : new ArrayList<>();
    }
}
