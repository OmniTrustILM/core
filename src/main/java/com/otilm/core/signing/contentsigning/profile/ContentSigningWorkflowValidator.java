package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.state.ContentSigningTransitions;
import com.otilm.core.signing.record.SigningRecordFloor;
import jakarta.annotation.Nullable;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Validates a managed content-signing workflow, so a profile can never advertise a family, level or timestamp source
 * that signing would later refuse.
 */
@Component
public class ContentSigningWorkflowValidator {

    private final SigningProfileVersionRepository versionRepository;

    public ContentSigningWorkflowValidator(SigningProfileVersionRepository versionRepository) {
        this.versionRepository = versionRepository;
    }

    /**
     * @param targetProfileUuid the profile being written, or {@code null} when the profile is being created
     */
    public void validate(ContentSigningWorkflowRequestDto workflow, Connector connector,
            @Nullable UUID targetProfileUuid) {
        SignatureFamily family = requireFamily(workflow);
        SignatureLevel maxLevel = requireMaxLevel(workflow);

        requireConnectorServes(connector, family, maxLevel);
        validateTimestampSource(workflow, maxLevel, targetProfileUuid);
    }

    /**
     * Checks the connector alone: it must advertise the family and reach the ceiling. Discovery applies this same
     * check, so a form built from a discovery answer cannot fail save on the connector's account.
     */
    public static void requireConnectorServes(Connector connector, SignatureFamily family, SignatureLevel maxLevel) {
        requireFamily(family);
        requireMaxLevel(maxLevel);
        ConnectorInterface familyInterface = SignatureFamilyInterfaces.of(family);

        requireFlag(connector, familyInterface, FeatureFlag.CONTENT_SIGNING, family.getLabel());
        rungFlagFor(maxLevel)
                .ifPresent(flag -> requireRung(connector, familyInterface, flag, maxLevel, family.getLabel()));
        requireExecutableMaxLevel(maxLevel);
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

    /** {@code SIGNED} needs no rung flag of its own -- {@code contentSigning} is what declares it. */
    private static Optional<FeatureFlag> rungFlagFor(SignatureLevel maxLevel) {
        return switch (maxLevel) {
            case SIGNED -> Optional.empty();
            case TIMESTAMPED -> Optional.of(FeatureFlag.LEVEL_TIMESTAMPED);
            case LONG_TERM -> Optional.of(FeatureFlag.LEVEL_LONG_TERM);
            case ARCHIVAL -> Optional.of(FeatureFlag.LEVEL_ARCHIVAL);
        };
    }

    private static void requireFlag(Connector connector, ConnectorInterface familyInterface, FeatureFlag flag,
            String familyLabel) {
        if (!declares(connector, familyInterface, flag)) {
            throw new ValidationException(
                    "Signature Formatting Provider '%s' does not advertise the '%s' feature on its '%s' interface, so it cannot serve %s signing"
                            .formatted(connector.getName(), flag.getLabel(), familyInterface.getLabel(), familyLabel));
        }
    }

    private static void requireRung(Connector connector, ConnectorInterface familyInterface, FeatureFlag flag,
            SignatureLevel maxLevel, String familyLabel) {
        if (!declares(connector, familyInterface, flag)) {
            throw new ValidationException(
                    "Signature Formatting Provider '%s' does not reach level %s for %s: the '%s' feature is not advertised on its '%s' interface"
                            .formatted(connector.getName(), maxLevel.name(), familyLabel, flag.getLabel(),
                                    familyInterface.getLabel()));
        }
    }

    private static boolean declares(Connector connector, ConnectorInterface familyInterface, FeatureFlag flag) {
        return connector
                .getInterfaces()
                .stream()
                .filter(i -> i.getInterfaceCode() == familyInterface)
                .map(ConnectorInterfaceEntity::getFeatures)
                .filter(Objects::nonNull)
                .anyMatch(features -> features.contains(flag));
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
}
