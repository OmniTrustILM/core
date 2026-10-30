package com.otilm.core.signing.tsa;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedSigningProfile;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.record.SigningRecordFloor;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import com.otilm.core.signing.tsa.messages.TspRequest;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Issues the timestamps an AdES signature needs from an ILM-managed TIMESTAMPING Signing Profile, in-process.
 *
 * <p>
 * The call goes below the TSP protocol layer, so being referenced by a content-signing profile is the authorization and
 * the referenced profile's {@code enabledProtocols} are not consulted — an in-process protocol can never be listed
 * there anyway.
 * </p>
 */
@Component
public class InternalTimestampSource {

    private static final String CLIENT_MESSAGE = "Internal error while timestamping the signature";

    private final SigningProfileInternalService signingProfileService;
    private final SigningProfileResolverFactory signingProfileResolverFactory;
    private final ManagedTimestampEngine engine;

    public InternalTimestampSource(SigningProfileInternalService signingProfileService,
            SigningProfileResolverFactory signingProfileResolverFactory, ManagedTimestampEngine engine) {
        this.signingProfileService = signingProfileService;
        this.signingProfileResolverFactory = signingProfileResolverFactory;
        this.engine = engine;
    }

    /**
     * Issues a timestamp over {@code imprint} from the named TIMESTAMPING Signing Profile.
     *
     * @param timestampingProfileName the profile's name, which the caller resolves from the {@code signingProfileUuid}
     * its workflow configuration stores — the name is this bridge's key because the profile-model cache is name-keyed
     * @param step the calling workflow step, which names the failure when issuance does not succeed
     * @throws SigningEngineException if the profile cannot be used or the timestamp cannot be issued
     */
    public IssuedTimestamp timestamp(TimestampImprint imprint, String timestampingProfileName, String step)
            throws SigningEngineException {
        try {
            SigningProfileModel<?, ?> profile = loadProfile(timestampingProfileName);
            requireRecordFloor(profile);
            ResolvedManagedTimestampingProfile resolved = resolveTimestampingProfile(profile);
            requireUsableImprint(imprint, resolved);
            return engine.issue(requestFor(imprint), profile, resolved, SigningProtocol.INTERNAL_TSA);
        } catch (SigningEngineException e) {
            throw SigningEngineException.stepFailed(e.failure(), step, e.operatorMessage(), e, e.clientMessage());
        }
    }

    /**
     * Uses the authorization-free loader, per the class-level invariant.
     */
    private SigningProfileModel<?, ?> loadProfile(String timestampingProfileName) throws SigningEngineException {
        SigningProfileModel<?, ?> profile;
        try {
            profile = signingProfileService.loadSigningProfileModel(timestampingProfileName);
        } catch (NotFoundException e) {
            throw misconfigured("timestamping Signing Profile '%s' does not exist".formatted(timestampingProfileName),
                    e);
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw misconfigured("timestamping Signing Profile '%s' cannot be loaded: %s"
                    .formatted(timestampingProfileName, e.getMessage()), e);
        }
        if (!profile.enabled()) {
            throw misconfigured("timestamping Signing Profile '%s' is disabled".formatted(timestampingProfileName),
                    null);
        }
        return profile;
    }

    /**
     * The referencing content-signing profile resolves this profile per request.
     */
    private static void requireRecordFloor(SigningProfileModel<?, ?> profile) throws SigningEngineException {
        Optional<String> violation = SigningRecordFloor
                .violation(profile.recordPolicy().recordingEnabled(), profile.recordPolicy().persistenceMode());
        if (violation.isPresent()) {
            throw misconfigured("timestamping Signing Profile '%s' no longer meets the signing-record floor: %s"
                    .formatted(profile.name(), violation.get()), null);
        }
    }

    private ResolvedManagedTimestampingProfile resolveTimestampingProfile(SigningProfileModel<?, ?> profile)
            throws SigningEngineException {
        ResolvedSigningProfile resolved = signingProfileResolverFactory.resolve(profile);
        if (resolved instanceof ResolvedManagedTimestampingProfile timestampingProfile) {
            return timestampingProfile;
        }
        throw misconfigured(
                "Signing Profile '%s' resolved to %s, not a managed timestamping profile"
                        .formatted(profile.name(), resolved == null ? "null" : resolved.getClass().getSimpleName()),
                null);
    }

    /**
     * The imprint comes from a formatting connector rather than from a client, so the two refusals here have different
     * culprits: an algorithm the profile does not list means the content-signing and timestamping profiles disagree,
     * while a digest of the wrong length for its own algorithm came from no document and so is the connector's fault.
     * The RFC 3161 edge rejects both in {@code TspRequestParser} and {@code TspRequestValidator}; in-process issuance
     * has no parser in front of it.
     */
    private static void requireUsableImprint(TimestampImprint imprint, ResolvedManagedTimestampingProfile resolved)
            throws SigningEngineException {
        List<DigestAlgorithm> allowed = resolved.allowedDigestAlgorithms();
        if (!allowed.isEmpty() && !allowed.contains(imprint.algorithm())) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "timestamping Signing Profile '%s' does not accept %s imprints"
                            .formatted(resolved.name(), imprint.algorithm().getCode()),
                    CLIENT_MESSAGE);
        }
        if (!imprint.hasLengthOfItsAlgorithm()) {
            throw new SigningEngineException(SigningEngineFailure.CONNECTOR_FAULT,
                    "imprint is %d bytes, which %s never produces"
                            .formatted(imprint.length(), imprint.algorithm().getCode()),
                    CLIENT_MESSAGE);
        }
    }

    /**
     * A nonce would only prove freshness to a remote caller, and the signer certificate is always embedded because the
     * token travels inside the signature that a validator checks on its own.
     */
    private static TspRequest requestFor(TimestampImprint imprint) {
        return new TspRequest(imprint.algorithm(), imprint.value(), Optional.empty(), Optional.empty(), true, null);
    }

    private static SigningEngineException misconfigured(String operatorMessage, Throwable cause) {
        return new SigningEngineException(SigningEngineFailure.MISCONFIGURED, operatorMessage, cause, CLIENT_MESSAGE);
    }
}
