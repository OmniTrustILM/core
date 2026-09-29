package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/**
 * What a key import requires of the token profile it imports into: access to the profile and its token, and a profile
 * that takes keys of the key's type and algorithm. An import into the public-key-only record that holds the key's
 * public key requires the right to update that record too.
 *
 * <p>
 * Whoever only asks whether a profile would take keys is answered in the words the import refuses them with, from one
 * answer of the profile's connector for all the keys asked about.
 * </p>
 */
@Component
public class KeyImportGates {

    public static final String DISABLED = "Token profile %s is disabled.";
    public static final String NOT_OFFERED = "Token profile %s does not import a %s.";
    public static final String ALGORITHM_NOT_OFFERED = "Token profile %s does not import the %s algorithm for a %s.";
    public static final String PROFILE_CHANGED = "Token profile %s changed while its import was checked. Try again.";

    private final AuthorizationEnforcer authorizationEnforcer;
    private final TokenProfileRepository tokenProfileRepository;
    private final KeyTransferCapabilityService keyTransferCapabilityService;
    private final CryptographicKeyWriter cryptographicKeyWriter;

    public KeyImportGates(AuthorizationEnforcer authorizationEnforcer, TokenProfileRepository tokenProfileRepository,
            KeyTransferCapabilityService keyTransferCapabilityService, CryptographicKeyWriter cryptographicKeyWriter) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.tokenProfileRepository = tokenProfileRepository;
        this.keyTransferCapabilityService = keyTransferCapabilityService;
        this.cryptographicKeyWriter = cryptographicKeyWriter;
    }

    /**
     * The profile of the token, with the detail of the profile and the detail and members of its token enforced, as
     * exporting a key requires too.
     *
     * @param tokenInstanceUuid UUID of the token
     * @param tokenProfileUuid UUID of the token's profile
     * @return the profile
     * @throws NotFoundException if the token has no such profile
     */
    public TokenProfileFullModel requireAccess(UUID tokenInstanceUuid, UUID tokenProfileUuid) throws NotFoundException {
        TokenProfileFullModel profile = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfileUuid, tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfileUuid));
        authorizationEnforcer
                .enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, SecuredUUID.fromUUID(tokenProfileUuid));
        SecuredUUID token = SecuredUUID.fromUUID(tokenInstanceUuid);
        authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.DETAIL, token);
        authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.MEMBERS, token);
        return profile;
    }

    /**
     * The same, for a profile named without its token.
     *
     * @param tokenProfileUuid UUID of the token profile
     * @return the profile
     * @throws NotFoundException if there is no such profile
     */
    public TokenProfileFullModel requireAccess(UUID tokenProfileUuid) throws NotFoundException {
        UUID tokenInstanceUuid = tokenProfileRepository
                .findByUuid(tokenProfileUuid)
                .map(TokenProfile::getTokenInstanceReferenceUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfileUuid));
        return requireAccess(tokenInstanceUuid, tokenProfileUuid);
    }

    /**
     * Requires that the caller may update the public-key-only record the import would adopt, before the connector is
     * asked.
     *
     * @param recordUuid UUID of the record
     * @throws ValidationException refusing the import as the import of a key held otherwise is, which says nothing of
     * whose the record is, when the caller may not
     */
    public void requireUpdatable(UUID recordUuid) {
        try {
            authorizationEnforcer
                    .enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, SecuredUUID.fromUUID(recordUuid));
        } catch (AccessDeniedException denied) {
            throw heldOtherwise();
        }
    }

    /**
     * The active public-key-only record that holds the public key now, which a registration of the imported key adopts,
     * once the requester is shown to be allowed to update it. The right is checked as the requester, so it holds when
     * the reconciliation registers the key, with nobody signed in, too. A key that holds the public key otherwise is
     * left to the registration, which decides under the attempt's lock: an attempt a concurrent request completed is
     * answered with the key that request registered, and any other import is refused.
     *
     * @param requester the user who asked for the import
     * @param spkiFingerprint the fingerprint of the key's public key, or {@code null} for a secret key
     * @return the record, or nothing when no such record holds the public key
     * @throws ValidationException when the requester may not update the record
     */
    public Optional<UUID> adoptableBy(NameAndUuidDto requester, String spkiFingerprint) {
        if (spkiFingerprint == null) {
            return Optional.empty();
        }
        Optional<UUID> adoptable = cryptographicKeyWriter.adoptableRecord(spkiFingerprint);
        if (adoptable.isPresent() && !authorizationEnforcer
                .isAuthorizedAs(UUID.fromString(requester.getUuid()), Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE,
                        SecuredUUID.fromUUID(adoptable.get()))) {
            throw heldOtherwise();
        }
        return adoptable;
    }

    private static ValidationException heldOtherwise() {
        return new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD));
    }

    /**
     * Core's gates for the profile, in order: enabled, then importing the type at all.
     *
     * @param profile the profile to import into
     * @param type the type of the key
     * @return the algorithms the profile imports for the type
     * @throws ValidationException with a fixed message for a disabled profile or a type it does not import
     * @throws ConnectorException if the connector had to be asked what the profile imports and did not answer
     * @throws NotFoundException if the profile or its connector no longer exists
     */
    public Set<KeyAlgorithm> requireImportable(TokenProfileFullModel profile, KeyRequestType type)
            throws ConnectorException, NotFoundException {
        Offer offer = offerOf(profile);
        Optional<String> refusal = offer.refusalOf(type);
        if (refusal.isPresent()) {
            throw new ValidationException(ValidationError.create(refusal.get()));
        }
        return offer.algorithmsFor(type);
    }

    /**
     * Why the profile cannot take keys of each kind, in the words the import refuses them with. Its connector is asked
     * what the profile imports once for all the kinds, and not at all when there are none.
     *
     * @param profile the profile to import into
     * @param kinds the kinds of key to answer for
     * @return for each kind, the reason, or empty when the profile takes keys of that kind
     * @throws ConnectorException if the connector had to be asked what the profile imports and did not answer
     * @throws NotFoundException if the profile or its connector no longer exists
     */
    public Map<KeyKind, Optional<String>> notImportableReasons(TokenProfileFullModel profile, Set<KeyKind> kinds)
            throws ConnectorException, NotFoundException {
        if (kinds.isEmpty()) {
            return Map.of();
        }
        Offer offer = offerOf(profile);
        return kinds.stream().collect(Collectors.toMap(Function.identity(), offer::reasonAgainst));
    }

    /** What the profile imports, as its connector answers once, or why it takes no key at all. */
    private Offer offerOf(TokenProfileFullModel profile) throws ConnectorException, NotFoundException {
        if (!Boolean.TRUE.equals(profile.enabled())) {
            return Offer.refused(profile.name(), DISABLED.formatted(profile.name()));
        }
        return keyTransferCapabilityService
                .importableKeyTypes(profile)
                .map(importable -> Offer.answered(profile.name(), importable))
                .orElseGet(() -> Offer.refused(profile.name(), PROFILE_CHANGED.formatted(profile.name())));
    }

    /**
     * The type and algorithm of a key, which decide whether a profile takes it.
     *
     * @param type the key's type
     * @param algorithm the key's algorithm
     */
    public record KeyKind(KeyRequestType type, KeyAlgorithm algorithm) {
    }

    /**
     * What a profile imports, from one answer of its connector.
     *
     * @param profileName the profile's name, which the refusals give
     * @param importable the algorithms the profile imports per key type
     * @param refusal why the profile takes no key at all, or {@code null}
     */
    private record Offer(String profileName, Map<KeyRequestType, Set<KeyAlgorithm>> importable, String refusal) {

        static Offer answered(String profileName, Map<KeyRequestType, Set<KeyAlgorithm>> importable) {
            return new Offer(profileName, importable, null);
        }

        static Offer refused(String profileName, String refusal) {
            return new Offer(profileName, Map.of(), refusal);
        }

        Set<KeyAlgorithm> algorithmsFor(KeyRequestType type) {
            return importable.getOrDefault(type, Set.of());
        }

        /** Why the profile takes no key of the type, or empty when it takes some. */
        Optional<String> refusalOf(KeyRequestType type) {
            if (refusal != null) {
                return Optional.of(refusal);
            }
            if (algorithmsFor(type).isEmpty()) {
                return Optional.of(NOT_OFFERED.formatted(profileName, nameOf(type)));
            }
            return Optional.empty();
        }

        /** Why the profile does not take a key of the kind, or empty when it does. */
        Optional<String> reasonAgainst(KeyKind kind) {
            Optional<String> refused = refusalOf(kind.type());
            if (refused.isPresent()) {
                return refused;
            }
            if (algorithmsFor(kind.type()).contains(kind.algorithm())) {
                return Optional.empty();
            }
            return Optional
                    .of(ALGORITHM_NOT_OFFERED.formatted(profileName, kind.algorithm().getLabel(), nameOf(kind.type())));
        }

        private static String nameOf(KeyRequestType type) {
            return type.getLabel().toLowerCase(Locale.ROOT);
        }
    }
}
