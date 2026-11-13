package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureLevelDeclarationDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.declaration.ContentSigningDeclarations;
import com.otilm.core.signing.contentsigning.declaration.FamilyAlgorithms;
import com.otilm.core.signing.contentsigning.parameters.PadesVisibleSignatureCompleteness;
import com.otilm.core.signing.contentsigning.parameters.SignatureParameterMerge;
import com.otilm.core.signing.contentsigning.state.ContentSigningTransitions;
import com.otilm.core.signing.record.SigningRecordFloor;
import jakarta.annotation.Nullable;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Validates a managed content-signing workflow against the declaration of its formatting connector. A saved profile
 * then advertises only a family, level, signer and timestamp source that signing accepts.
 */
@Component
public class ContentSigningWorkflowValidator {

    private final SigningProfileVersionRepository versionRepository;
    private final ContentSigningDeclarations declarations;

    public ContentSigningWorkflowValidator(SigningProfileVersionRepository versionRepository,
            ContentSigningDeclarations declarations) {
        this.versionRepository = versionRepository;
        this.declarations = declarations;
    }

    /**
     * @param signatureAlgorithm the algorithm the profile's key and signing attributes sign with
     * @param targetProfileUuid the profile being written, or {@code null} when the profile is being created
     */
    public void validate(ContentSigningWorkflowRequestDto workflow, Connector connector,
            SignatureAlgorithm signatureAlgorithm, @Nullable UUID targetProfileUuid) {
        SignatureFamily family = requireFamily(workflow);
        SignatureLevel maxLevel = requireMaxLevel(workflow);

        SignatureFamilyDeclarationDto declared = requireConnectorServes(connector, family, maxLevel);
        requireFamilyAcceptsAlgorithm(declared, signatureAlgorithm);
        validateTimestampSource(workflow, maxLevel, targetProfileUuid);
        validateSignatureParameters(workflow, family);
    }

    /**
     * Checks the connector alone: it must declare the family and a level at the ceiling. The formatting-attribute
     * discovery applies this same check, so a form built from its answer passes save on the connector's account.
     *
     * @return the connector's declaration of the family
     */
    public SignatureFamilyDeclarationDto requireConnectorServes(Connector connector, SignatureFamily family,
            SignatureLevel maxLevel) {
        requireFamily(family);
        requireMaxLevel(maxLevel);
        SignatureFamilyDeclarationDto declared = requireDeclaredFamily(connector, family);
        requireDeclaredLevel(connector, declared, maxLevel);
        requireExecutableMaxLevel(maxLevel);
        return declared;
    }

    private SignatureFamilyDeclarationDto requireDeclaredFamily(Connector connector, SignatureFamily family) {
        return declarations
                .family(connector.getUuid(), family)
                .orElseThrow(() -> new ValidationException(
                        "Signature Formatting Provider '%s' does not declare the %s family"
                                .formatted(connector.getName(), family)));
    }

    private static SignatureFamily requireFamily(ContentSigningWorkflowRequestDto workflow) {
        return requireFamily(workflow.getFamily());
    }

    private static SignatureFamily requireFamily(SignatureFamily family) {
        if (family == null) {
            throw new ValidationException("Signature family is required for a managed content signing workflow");
        }
        return family;
    }

    private static SignatureLevel requireMaxLevel(ContentSigningWorkflowRequestDto workflow) {
        return requireMaxLevel(workflow.getMaxLevel());
    }

    private static SignatureLevel requireMaxLevel(SignatureLevel maxLevel) {
        if (maxLevel == null) {
            throw new ValidationException("maxLevel is required for a managed content signing workflow");
        }
        return maxLevel;
    }

    /**
     * A ceiling above what the engine executes would be advertised by the API and the UI while every request at that
     * level is refused at signing time, so it is refused here instead.
     */
    private static void requireExecutableMaxLevel(SignatureLevel maxLevel) {
        if (!maxLevel.isWithin(ContentSigningTransitions.HIGHEST_EXECUTABLE_LEVEL)) {
            throw new ValidationException(
                    "Signature level %s is not available yet, so it cannot be a maxLevel; the highest ceiling this version supports is %s"
                            .formatted(maxLevel.name(), ContentSigningTransitions.HIGHEST_EXECUTABLE_LEVEL.name()));
        }
    }

    private static void requireDeclaredLevel(Connector connector, SignatureFamilyDeclarationDto declared,
            SignatureLevel maxLevel) {
        boolean reached = declared
                .getLevels()
                .stream()
                .map(SignatureLevelDeclarationDto::getLevel)
                .anyMatch(maxLevel::equals);
        if (!reached) {
            throw new ValidationException("Signature Formatting Provider '%s' does not reach level %s for %s"
                    .formatted(connector.getName(), maxLevel.name(), declared.getLabel()));
        }
    }

    /** A family that restricts its algorithms cannot embed a signature made with any other. */
    private static void requireFamilyAcceptsAlgorithm(SignatureFamilyDeclarationDto declared,
            SignatureAlgorithm signatureAlgorithm) {
        FamilyAlgorithms
                .restriction(declared)
                .filter(accepted -> !accepted.contains(signatureAlgorithm))
                .ifPresent(accepted -> {
                    throw new ValidationException(
                            "The signature algorithm %s is not accepted by the %s family, which accepts %s"
                                    .formatted(signatureAlgorithm.getCode(), declared.getLabel(), codesOf(accepted)));
                });
    }

    private static String codesOf(Set<SignatureAlgorithm> signatureAlgorithms) {
        return signatureAlgorithms.stream().map(SignatureAlgorithm::getCode).sorted().collect(Collectors.joining(", "));
    }

    private void validateTimestampSource(ContentSigningWorkflowRequestDto workflow, SignatureLevel maxLevel,
            @Nullable UUID targetProfileUuid) {
        UUID referenced = TimestampSourceRequests.internalProfileUuid(workflow.getTimestampSource());
        boolean timestampsEmbedded = maxLevel != SignatureLevel.SIGNED;

        if (!timestampsEmbedded) {
            if (referenced != null) {
                throw new ValidationException(
                        "A maxLevel of SIGNED embeds no timestamp, so a timestamp source must be omitted");
            }
            return;
        }
        if (referenced == null) {
            throw new ValidationException(
                    "A timestamp source is required when maxLevel is %s or higher".formatted(maxLevel.name()));
        }
        requireDistinctTimestampSource(referenced, targetProfileUuid);
        requireUsableTimestampingProfile(referenced);
    }

    /**
     * A self-reference outlives the version that made it: once superseded it holds the profile's own deletion open with
     * no way to release it.
     */
    private static void requireDistinctTimestampSource(UUID referenced, @Nullable UUID targetProfileUuid) {
        if (referenced.equals(targetProfileUuid)) {
            throw new ValidationException(
                    "A Signing Profile cannot name itself as its timestamp source; name a TIMESTAMPING Signing Profile instead");
        }
    }

    /**
     * Only an ILM-managed TIMESTAMPING profile can issue these timestamps, and it must record what it issues --
     * otherwise a signature's timestamp traces to nothing.
     */
    private void requireUsableTimestampingProfile(UUID referenced) {
        SigningProfileVersion version = versionRepository
                .findLatestByProfileUuid(referenced)
                .orElseThrow(() -> new ValidationException(
                        "The Signing Profile named as the timestamp source does not exist: " + referenced));
        if (version.getWorkflowType() != SigningWorkflowType.TIMESTAMPING) {
            throw new ValidationException(
                    "The Signing Profile named as the timestamp source uses the %s workflow; a TIMESTAMPING profile is required"
                            .formatted(version.getWorkflowType()));
        }
        if (version.getSigningScheme() != SigningScheme.MANAGED) {
            throw new ValidationException(
                    "The Signing Profile named as the timestamp source is not ILM-managed, so ILM cannot issue its timestamps");
        }
        if (version.getManagedSigningType() != ManagedSigningType.STATIC_KEY) {
            throw new ValidationException(
                    "The Signing Profile named as the timestamp source uses managed signing type %s; only %s can be resolved for issuance"
                            .formatted(version.getManagedSigningType(), ManagedSigningType.STATIC_KEY));
        }
        Optional<String> violation = SigningRecordFloor
                .violation(version.isRecordingEnabled(), version.getPersistenceMode());
        if (violation.isPresent()) {
            throw new ValidationException(
                    "The Signing Profile named as the timestamp source does not meet the signing-record floor: "
                            + violation.get());
        }
    }

    /**
     * The parameter rules that can be decided from the profile alone. Complements {@code @Valid} cascade on the request
     * DTO.
     */
    private static void validateSignatureParameters(ContentSigningWorkflowRequestDto workflow, SignatureFamily family) {
        Set<SignatureParameterGroup> allowed = workflow.getAllowedRequestParameterGroups() == null
                ? Set.of()
                : workflow.getAllowedRequestParameterGroups();
        requireGroupsApplyToFamily(allowed, family);
        requireDefaultsMatchFamily(workflow.getDefaultSignatureParameters(), family);
        requireSatisfiableDefaults(workflow.getDefaultSignatureParameters(), allowed);
    }

    private static void requireGroupsApplyToFamily(Set<SignatureParameterGroup> allowed, SignatureFamily family) {
        List<ValidationError> errors = allowed
                .stream()
                .filter(group -> !group.appliesTo(family))
                .map(group -> ValidationError
                        .create("Signature parameter group '{}' does not apply to the {} family", group.getCode(),
                                family))
                .toList();
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    private static void requireDefaultsMatchFamily(@Nullable SignatureParametersDto defaults, SignatureFamily family) {
        if (defaults != null && !family.equals(defaults.getFamily())) {
            throw new ValidationException(
                    "defaultSignatureParameters declares the %s family, but this workflow produces %s signatures"
                            .formatted(defaults.getFamily(), family));
        }
    }

    /** Checks what a request supplying no parameters would get, so save time reads the object signing reads. */
    private static void requireSatisfiableDefaults(@Nullable SignatureParametersDto defaults,
            Set<SignatureParameterGroup> allowed) {
        if (!(SignatureParameterMerge.merge(defaults, null) instanceof PadesSignatureParametersDto effective)) {
            return;
        }
        List<ValidationError> errors = PadesVisibleSignatureCompleteness
                .missingFields(effective)
                .entrySet()
                .stream()
                .filter(gap -> !allowed.contains(gap.getKey()))
                .map(gap -> unsatisfiable(gap.getKey(), gap.getValue()))
                .toList();
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    private static ValidationError unsatisfiable(SignatureParameterGroup group, List<String> fields) {
        return ValidationError
                .create("The default visible signature is incomplete and no request can complete it: %s %s, and the '%s' group is not allow-listed"
                        .formatted(fields.size() == 1 ? "field" : "fields", String.join(", ", fields),
                                group.getCode()));
    }
}
