package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureLevelDeclarationDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.declaration.ContentSigningDeclarations;
import com.otilm.core.signing.contentsigning.declaration.FamilyAlgorithms;
import com.otilm.core.signing.contentsigning.state.ContentSigningTransitions;
import com.otilm.core.signing.record.SigningRecordFloor;
import jakarta.annotation.Nullable;
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
        SignatureFamilyDeclarationDto declared = requireConnectorServes(connector, workflow.getFamily(),
                workflow.getLevel());
        requireFamilyAcceptsAlgorithm(declared, signatureAlgorithm);
        validateTimestampSource(workflow, workflow.getLevel(), targetProfileUuid);
    }

    /**
     * Checks that the connector declares the family and the level and that Core executes the level. The
     * formatting-attribute discovery applies this same check, so a form built from its answer passes save.
     *
     * @return the connector's declaration of the family
     */
    public SignatureFamilyDeclarationDto requireConnectorServes(Connector connector, String family,
            SignatureLevel level) {
        requireFamily(family);
        requireLevel(level);
        SignatureFamilyDeclarationDto declared = requireDeclaredFamily(connector, family);
        requireDeclaredLevel(connector, declared, level);
        requireExecutableLevel(level);
        return declared;
    }

    private SignatureFamilyDeclarationDto requireDeclaredFamily(Connector connector, String family) {
        return declarations
                .family(connector.getUuid(), family)
                .orElseThrow(() -> new ValidationException(
                        "Signature Formatting Provider '%s' does not declare the %s family"
                                .formatted(connector.getName(), family)));
    }

    private static void requireFamily(String family) {
        if (family == null) {
            throw new ValidationException("Signature family is required for a managed content signing workflow");
        }
    }

    private static void requireLevel(SignatureLevel level) {
        if (level == null) {
            throw new ValidationException("level is required for a managed content signing workflow");
        }
    }

    /**
     * The engine trusts the saved level to be executable, so a level above what it executes is refused here.
     */
    private static void requireExecutableLevel(SignatureLevel level) {
        if (!level.isWithin(ContentSigningTransitions.HIGHEST_EXECUTABLE_LEVEL)) {
            throw new ValidationException(
                    "Signature level %s is not available yet; the highest level this version supports is %s"
                            .formatted(level.name(), ContentSigningTransitions.HIGHEST_EXECUTABLE_LEVEL.name()));
        }
    }

    private static void requireDeclaredLevel(Connector connector, SignatureFamilyDeclarationDto declared,
            SignatureLevel level) {
        boolean reached = declared
                .getLevels()
                .stream()
                .map(SignatureLevelDeclarationDto::getLevel)
                .anyMatch(level::equals);
        if (!reached) {
            throw new ValidationException("Signature Formatting Provider '%s' does not reach level %s for %s"
                    .formatted(connector.getName(), level.name(), declared.getLabel()));
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

    private void validateTimestampSource(ContentSigningWorkflowRequestDto workflow, SignatureLevel level,
            @Nullable UUID targetProfileUuid) {
        UUID referenced = TimestampSourceRequests.internalProfileUuid(workflow.getTimestampSource());
        boolean timestampsEmbedded = level != SignatureLevel.SIGNED;

        if (!timestampsEmbedded) {
            if (referenced != null) {
                throw new ValidationException(
                        "A level of SIGNED embeds no timestamp, so a timestamp source must be omitted");
            }
            return;
        }
        if (referenced == null) {
            throw new ValidationException("A timestamp source is required at level %s".formatted(level.name()));
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
}
