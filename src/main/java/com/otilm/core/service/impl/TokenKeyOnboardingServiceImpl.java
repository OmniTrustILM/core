package com.otilm.core.service.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.client.cryptography.key.TokenKeySelectionDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyMetaMatcher;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysRequestV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingResultDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.ProviderKeyPairPage;
import com.otilm.core.model.crypto.ProviderUnaddressableKey;
import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import com.otilm.core.model.crypto.PublicKeyHolderSummary;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.TokenKeyOnboardingExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyListGates;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.UniqueViolations;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads the token outside any transaction and saves each onboarded key in a transaction of its own. This keeps a slow
 * token from holding database locks and one refused key from undoing the others.
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
public class TokenKeyOnboardingServiceImpl implements TokenKeyOnboardingExternalService {

    /** The selection is read again in one listing, within the connector's page cap. */
    static final int MAX_PAIRS_PER_REREAD = ListKeysRequestV2Dto.MAX_LIMIT;

    static final String GONE = "The key storage no longer holds this key pair.";
    static final String AMBIGUOUS = "The key storage holds more than one key pair under this handle.";
    static final String HELD = "Key %s already holds this key pair.";
    static final String NOT_ACTIVE = "Key %s holds this public key without a token instance, but it is not active, so "
            + "the private key cannot join it.";
    static final String PUBLIC_KEY_MISSING = "The key storage holds no public key for this key pair.";
    static final String NO_UNIQUE_ID = "The key storage holds this key without an ID unique to it.";
    static final String HELD_MEANWHILE = "The inventory came to hold this key pair while it was being onboarded.";
    static final String RECORD_CHANGED = "The key holding this public key changed while the private key was joining "
            + "it. List the key storage again.";
    static final String IMPORTING = "An import of this key pair is still in progress.";
    static final String PAGE_OUT_OF_RANGE = "The page must be 1 or later, and hold 1 to "
            + ListKeysRequestV2Dto.MAX_LIMIT + " key pairs.";
    static final String PAGE_BEYOND_LAST_OFFSET = "The page must start at most " + Integer.MAX_VALUE
            + " key pairs into the listing.";
    static final String TOO_MANY = "An onboarding selects at most " + MAX_PAIRS_PER_REREAD + " key pairs.";
    private static final String UNLABELLED_NAME = "Onboarded key";
    private static final int FINGERPRINT_PREFIX_LENGTH = 8;
    private static final Set<UUID> KEEP_GROUPS = null;

    private final KeyListGates keyListGates;
    private final KeyImportGates keyImportGates;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final KeyImportRepository keyImportRepository;
    private final CryptographicKeyWriter cryptographicKeyWriter;
    private final AttributeEngine attributeEngine;

    public TokenKeyOnboardingServiceImpl(KeyListGates keyListGates, KeyImportGates keyImportGates,
            KeyProviderAdapterFactory keyProviderAdapterFactory, CryptographicKeyRepository cryptographicKeyRepository,
            KeyImportRepository keyImportRepository, CryptographicKeyWriter cryptographicKeyWriter,
            AttributeEngine attributeEngine) {
        this.keyListGates = keyListGates;
        this.keyImportGates = keyImportGates;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.keyImportRepository = keyImportRepository;
        this.cryptographicKeyWriter = cryptographicKeyWriter;
        this.attributeEngine = attributeEngine;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST)
    public TokenKeyListResponseDto listTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid, int pageNumber,
            int itemsPerPage) throws ConnectorException, NotFoundException {
        TokenProfileFullModel profile = keyListGates.requireListable(tokenInstanceUuid, tokenProfileUuid);
        TokenKeyPage page = TokenKeyPage.of(pageNumber, itemsPerPage);
        ProviderKeyPairPage listed = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listKeyPairs(profile, page.offset(), page.itemsPerPage(), null);
        Inventory inventory = inventoryOf(listed.keyPairs(), Set.of());
        Stream<TokenKeyDto> keyPairs = listed.keyPairs().stream().map(pair -> describe(pair, inventory));
        Stream<TokenKeyDto> unaddressableKeys = listed
                .unaddressableKeys()
                .stream()
                .map(TokenKeyOnboardingServiceImpl::describe);
        List<TokenKeyDto> entries = Stream.concat(keyPairs, unaddressableKeys).toList();
        return page.response(entries, listed.totalItems());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE)
    public OnboardTokenKeysResponseDto onboardTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            OnboardTokenKeysRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        TokenProfileFullModel profile = keyListGates.requireListable(tokenInstanceUuid, tokenProfileUuid);
        List<TokenKeySelectionDto> selections = request.getKeys();
        if (selections.size() > MAX_PAIRS_PER_REREAD) {
            throw new ValidationException(ValidationError.create(TOO_MANY));
        }
        List<RequestAttribute> customAttributes = request.getCustomAttributes();
        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, customAttributes);
        SecurityResourceFilter customAttributePermissions = attributeEngine
                .loadCustomAttributesSecurityResourceFilter();
        List<List<MetadataAttribute>> selectedPairMeta = distinctHandles(selections);
        Set<String> importingBeforeReread = importingOn(profile);
        ProviderKeyPairPage reread = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listKeyPairs(profile, 0, selectedPairMeta.size(), selectedPairMeta);
        Onboarding onboarding = new Onboarding(profile, reread.keyPairs(),
                inventoryOf(reread.keyPairs(), importingBeforeReread), customAttributes, customAttributePermissions);
        OnboardTokenKeysResponseDto response = new OnboardTokenKeysResponseDto();
        for (TokenKeySelectionDto selection : selections) {
            response.getResults().add(onboard(onboarding, selection));
        }
        return response;
    }

    /** Each handle the selections name, once, so the token answers it with one key pair at most. */
    private static List<List<MetadataAttribute>> distinctHandles(List<TokenKeySelectionDto> selections) {
        List<List<MetadataAttribute>> handles = new ArrayList<>();
        for (TokenKeySelectionDto selection : selections) {
            List<MetadataAttribute> handle = selection.getKeyPairMeta();
            if (handles.stream().noneMatch(named -> KeyMetaMatcher.matches(handle, named))) {
                handles.add(handle);
            }
        }
        return handles;
    }

    /**
     * The fingerprints of the token's unsettled imports, read before the token is read again: an import that settles in
     * between may have destroyed a key pair the token still listed.
     */
    private Set<String> importingOn(TokenProfileFullModel profile) {
        return Set
                .copyOf(keyImportRepository
                        .findImportingSpkiFingerprintsOnToken(profile.tokenInstanceReferenceUuid(),
                                KeyImportState.UNSETTLED));
    }

    private TokenKeyDto describe(ProviderKeyPair pair, Inventory inventory) {
        Standing standing = standingOf(pair, inventory);
        TokenKeyDto.TokenKeyDtoBuilder entry = TokenKeyDto
                .builder()
                .keyPairMeta(pair.keyPairMeta())
                .label(pair.label())
                .keyAlgorithm(pair.privateKey().algorithm())
                .length(pair.privateKey().length())
                .status(standing.status())
                .fingerprint(standing.fingerprint())
                .reason(standing.refusal());
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            entry.inventoryKeyUuid(visibleHolder.keyUuid()).inventoryKeyName(visibleHolder.keyName());
        }
        if (standing.status() == TokenKeyStatus.ONBOARDABLE) {
            entry.suggestedName(suggestedName(pair.label(), standing.fingerprint(), inventory));
        }
        return entry.build();
    }

    /** An unaddressable key is listed for information only. */
    private static TokenKeyDto describe(ProviderUnaddressableKey key) {
        return TokenKeyDto
                .builder()
                .label(key.label())
                .keyAlgorithm(key.algorithm())
                .length(key.length())
                .status(TokenKeyStatus.NO_UNIQUE_ID)
                .reason(NO_UNIQUE_ID)
                .build();
    }

    /**
     * One query each for the pairs' holders, unsettled imports and taken labels, however many pairs a page lists.
     *
     * @param importingAlready fingerprints of unsettled imports read earlier, which count as importing too
     */
    private Inventory inventoryOf(List<ProviderKeyPair> pairs, Set<String> importingAlready) {
        Set<String> fingerprints = pairs
                .stream()
                .map(TokenKeyOnboardingServiceImpl::fingerprintOf)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Set<String> labels = pairs
                .stream()
                .map(ProviderKeyPair::label)
                .filter(TokenKeyOnboardingServiceImpl::isLabelled)
                .map(String::strip)
                .collect(Collectors.toSet());
        Map<String, PublicKeyHolderSummary> holders = new HashMap<>(cryptographicKeyWriter.holdersOf(fingerprints));
        Set<String> importing = new HashSet<>(importingAlready);
        if (!fingerprints.isEmpty()) {
            importing.addAll(keyImportRepository.findImportingSpkiFingerprints(fingerprints, KeyImportState.UNSETTLED));
        }
        Set<String> takenNames = new HashSet<>();
        if (!labels.isEmpty()) {
            takenNames.addAll(cryptographicKeyRepository.findNamesIn(labels));
        }
        return new Inventory(holders, importing, takenNames);
    }

    private Standing standingOf(ProviderKeyPair pair, Inventory inventory) {
        String fingerprint = fingerprintOf(pair);
        if (fingerprint == null) {
            return new Standing(TokenKeyStatus.NO_PUBLIC_KEY, null, null, false, PUBLIC_KEY_MISSING);
        }
        if (inventory.importing().contains(fingerprint)) {
            return new Standing(TokenKeyStatus.IMPORT_IN_PROGRESS, fingerprint, null, false, IMPORTING);
        }
        PublicKeyHolderSummary holder = inventory.holders().get(fingerprint);
        if (holder == null) {
            return new Standing(TokenKeyStatus.ONBOARDABLE, fingerprint, null, false, null);
        }
        boolean visible = keyImportGates.maySeeInDetail(holder.keyUuid(), holder.tokenInstanceUuid());
        return switch (holder.holding()) {
            case PUBLIC_KEY_ONLY -> standingOfRecord(fingerprint, holder, visible);
            case KEY_PAIR -> held(TokenKeyStatus.IN_INVENTORY, fingerprint, holder, visible, HELD);
            case PUBLIC_KEY_IN_TOKEN ->
                held(TokenKeyStatus.IN_INVENTORY, fingerprint, holder, visible, KeyImportGates.HELD_IN_TOKEN);
        };
    }

    /**
     * A public-key-only record takes the private key when it is active and the caller may update it, as an import into
     * it requires.
     */
    private Standing standingOfRecord(String fingerprint, PublicKeyHolderSummary record, boolean visible) {
        if (!record.active()) {
            return held(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN, fingerprint, record, visible, NOT_ACTIVE);
        }
        if (!keyImportGates.mayUpdate(record.keyUuid())) {
            return held(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN, fingerprint, record, visible,
                    KeyImportGates.NOT_UPDATABLE);
        }
        return new Standing(TokenKeyStatus.ONBOARDABLE_INTO_KEY, fingerprint, record, visible, null);
    }

    /** The refusal names the holder only to a caller who may see it in detail. */
    private static Standing held(TokenKeyStatus status, String fingerprint, PublicKeyHolderSummary holder,
            boolean visible, String reason) {
        String refusal = visible ? reason.formatted(holder.keyName()) : CryptographicKeyWriter.KEY_ALREADY_HELD;
        return new Standing(status, fingerprint, holder, visible, refusal);
    }

    private static String fingerprintOf(ProviderKeyPair pair) {
        return pair.publicKey() == null ? null : CryptographyUtil.calculateKeyFingerprint(pair.publicKey().material());
    }

    private static boolean isLabelled(String label) {
        return label != null && !label.isBlank();
    }

    private static String suggestedName(String label, String fingerprint, Inventory inventory) {
        if (isLabelled(label) && !inventory.takenNames().contains(label.strip())) {
            return label.strip();
        }
        String base = isLabelled(label) ? label.strip() : UNLABELLED_NAME;
        return "%s (%s)".formatted(base, fingerprint.substring(0, FINGERPRINT_PREFIX_LENGTH));
    }

    /**
     * Onboards one selection, or reports in its result why it was refused. The other selections then still proceed.
     */
    private TokenKeyOnboardingResultDto onboard(Onboarding onboarding, TokenKeySelectionDto selection)
            throws AttributeException, NotFoundException {
        TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result = TokenKeyOnboardingResultDto
                .builder()
                .keyPairMeta(selection.getKeyPairMeta());
        List<ProviderKeyPair> named = onboarding
                .reread()
                .stream()
                .filter(candidate -> KeyMetaMatcher.matches(selection.getKeyPairMeta(), candidate.keyPairMeta()))
                .toList();
        if (named.isEmpty()) {
            return skipped(result, GONE);
        }
        if (named.size() > 1) {
            return skipped(result, AMBIGUOUS);
        }
        ProviderKeyPair pair = named.getFirst();
        Standing standing = standingOf(pair, onboarding.inventory());
        return switch (standing.status()) {
            case ONBOARDABLE -> onboardAsKeyOfItsOwn(onboarding, selection, pair, standing, result);
            case ONBOARDABLE_INTO_KEY -> onboardIntoRecord(onboarding, pair, standing, result);
            default -> refused(result, standing);
        };
    }

    private TokenKeyOnboardingResultDto onboardAsKeyOfItsOwn(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyPair pair, Standing standing,
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException, NotFoundException {
        String name = selection.getName() == null || selection.getName().isBlank()
                ? suggestedName(pair.label(), standing.fingerprint(), onboarding.inventory())
                : selection.getName().strip();
        if (cryptographicKeyRepository.existsByName(name)) {
            return skipped(result, CryptographicKeyWriter.NAME_TAKEN.formatted(name));
        }
        TokenProfileFullModel profile = onboarding.profile();
        Optional<CryptographicKeyBasicModel> onboarded;
        try {
            onboarded = cryptographicKeyWriter
                    .onboardUnlessImporting(name, profile, standing.fingerprint(), pair.toOnboardedItems(name),
                            onboarding.customAttributes(), onboarding.customAttributePermissions());
        } catch (DataIntegrityViolationException e) {
            if (!UniqueViolations.isUniqueViolation(e)) {
                throw e;
            }
            return skipped(result, HELD_MEANWHILE);
        }
        if (onboarded.isEmpty()) {
            return skipped(result, IMPORTING);
        }
        CryptographicKeyBasicModel key = onboarded.get();
        cryptographicKeyWriter.updateOwnerAndGroups(key, KEEP_GROUPS);
        onboarding.inventory().add(standing.fingerprint(), heldAsKeyPair(key.uuid(), key.name(), profile));
        return onboardedAsNewKey(result, key);
    }

    /**
     * The record keeps its name, owner, groups and custom attributes, as when an import adopts it. The result names it
     * only to a caller who may see it in detail.
     */
    private TokenKeyOnboardingResultDto onboardIntoRecord(Onboarding onboarding, ProviderKeyPair pair,
            Standing standing, TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException {
        PublicKeyHolderSummary record = standing.holder();
        TokenProfileFullModel profile = onboarding.profile();
        Optional<CryptographicKeyBasicModel> onboarded;
        try {
            onboarded = cryptographicKeyWriter
                    .onboardIntoRecordUnlessImporting(record.keyUuid(), profile, standing.fingerprint(),
                            pair.toOnboardedItems(record.keyName()));
        } catch (ValidationException changedMeanwhile) {
            return skipped(result, RECORD_CHANGED);
        }
        if (onboarded.isEmpty()) {
            return skipped(result, IMPORTING);
        }
        onboarding.inventory().add(standing.fingerprint(), heldAsKeyPair(record.keyUuid(), record.keyName(), profile));
        result.onboarded(true).intoExistingKey(true);
        if (standing.holderVisible()) {
            result.keyUuid(onboarded.get().uuid()).keyName(onboarded.get().name());
        }
        return result.build();
    }

    private static TokenKeyOnboardingResultDto onboardedAsNewKey(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, CryptographicKeyBasicModel key) {
        return result.onboarded(true).intoExistingKey(false).keyUuid(key.uuid()).keyName(key.name()).build();
    }

    /** The key an onboarding registered the key pair in, which holds it with its private key on the profile's token. */
    private static PublicKeyHolderSummary heldAsKeyPair(UUID keyUuid, String keyName, TokenProfileFullModel profile) {
        boolean active = true;
        return new PublicKeyHolderSummary(keyUuid, keyName, profile.tokenInstanceReferenceUuid(), Holding.KEY_PAIR,
                active);
    }

    private static TokenKeyOnboardingResultDto refused(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, Standing standing) {
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            result.keyUuid(visibleHolder.keyUuid()).keyName(visibleHolder.keyName());
        }
        return skipped(result, standing.refusal());
    }

    private static TokenKeyOnboardingResultDto skipped(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, String reason) {
        return result.onboarded(false).reason(reason).build();
    }

    /**
     * Where the inventory stands on a listed key pair.
     *
     * @param fingerprint the public key's fingerprint, or null for a pair listed without one
     * @param holder the inventory key holding the public key, or null
     * @param holderVisible whether the caller may see the holder in detail
     * @param refusal the reason the pair is refused, or null for an onboardable pair
     */
    private record Standing(TokenKeyStatus status, String fingerprint, PublicKeyHolderSummary holder,
            boolean holderVisible, String refusal) {

        /** The holder, when the caller may see it in detail. */
        PublicKeyHolderSummary visibleHolder() {
            return holderVisible ? holder : null;
        }
    }

    /**
     * What the inventory and the unsettled imports hold of a page of listed key pairs. An onboarding adds each key it
     * registers, so a selection repeating a key pair finds it held, and a later suggested name avoids its name.
     *
     * @param holders the keys holding the pairs' public keys, by fingerprint
     * @param importing the fingerprints of the pairs' public keys that an unsettled import holds
     * @param takenNames the pairs' labels that keys have as names
     */
    private record Inventory(Map<String, PublicKeyHolderSummary> holders, Set<String> importing,
            Set<String> takenNames) {

        void add(String fingerprint, PublicKeyHolderSummary holder) {
            holders.put(fingerprint, holder);
            takenNames.add(holder.keyName());
        }
    }

    /**
     * One onboarding request after the token was read again for its selection.
     *
     * @param reread the key pairs the token listed for the selection
     * @param inventory what the inventory holds of them
     * @param customAttributes the custom attributes every key of its own takes, or {@code null} for none
     * @param customAttributePermissions permissions applied to the custom attributes
     */
    private record Onboarding(TokenProfileFullModel profile, List<ProviderKeyPair> reread, Inventory inventory,
            List<RequestAttribute> customAttributes, SecurityResourceFilter customAttributePermissions) {
    }

    /** A page of the Core API mapped onto the offset and limit the connector takes. */
    private record TokenKeyPage(int pageNumber, int itemsPerPage, int offset) {

        static TokenKeyPage of(int pageNumber, int itemsPerPage) {
            if (pageNumber < 1 || itemsPerPage < 1 || itemsPerPage > ListKeysRequestV2Dto.MAX_LIMIT) {
                throw new ValidationException(ValidationError.create(PAGE_OUT_OF_RANGE));
            }
            try {
                return new TokenKeyPage(pageNumber, itemsPerPage, Math.multiplyExact(pageNumber - 1, itemsPerPage));
            } catch (ArithmeticException beyondTheLastOffset) {
                throw new ValidationException(ValidationError.create(PAGE_BEYOND_LAST_OFFSET));
            }
        }

        TokenKeyListResponseDto response(List<TokenKeyDto> entries, long totalItems) {
            TokenKeyListResponseDto response = new TokenKeyListResponseDto();
            response.setItems(entries);
            response.setPageNumber(pageNumber);
            response.setItemsPerPage(itemsPerPage);
            response.setTotalItems(totalItems);
            response.setTotalPages((int) Math.ceilDiv(totalItems, itemsPerPage));
            return response;
        }
    }
}
