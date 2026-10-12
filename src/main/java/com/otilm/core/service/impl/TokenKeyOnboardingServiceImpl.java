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
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairMetaMatcher;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeyPairsRequestV2Dto;
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
import com.otilm.core.model.crypto.PublicKeyHolderSummary;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.service.TokenKeyOnboardingExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyListGates;
import com.otilm.core.service.handler.key.KeyPairHandles;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.UniqueViolations;
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
    static final int MAX_PAIRS_PER_REREAD = ListKeyPairsRequestV2Dto.MAX_LIMIT;

    static final String GONE = "The key storage no longer holds this key pair.";
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
            + ListKeyPairsRequestV2Dto.MAX_LIMIT + " key pairs.";
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
        Inventory inventory = inventoryOf(listed.keyPairs());
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
        List<List<MetadataAttribute>> selectedPairMeta = selections
                .stream()
                .map(selection -> KeyPairHandles.decode(selection.getKeyPairHandle()))
                .toList();
        ProviderKeyPairPage reread = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listKeyPairs(profile, 0, selectedPairMeta.size(), selectedPairMeta);
        OnboardTokenKeysResponseDto response = new OnboardTokenKeysResponseDto();
        for (int i = 0; i < selections.size(); i++) {
            response
                    .getResults()
                    .add(onboard(profile, selections.get(i), selectedPairMeta.get(i), reread.keyPairs(),
                            customAttributes));
        }
        return response;
    }

    private TokenKeyDto describe(ProviderKeyPair pair, Inventory inventory) {
        Standing standing = standingOf(pair, inventory);
        TokenKeyDto entry = new TokenKeyDto();
        entry.setKeyPairHandle(KeyPairHandles.encode(pair.keyPairMeta()));
        entry.setLabel(pair.label());
        entry.setKeyAlgorithm(pair.privateKey().algorithm());
        entry.setLength(pair.privateKey().length());
        entry.setStatus(standing.status());
        entry.setFingerprint(standing.fingerprint());
        entry.setReason(standing.refusal());
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            entry.setInventoryKeyUuid(visibleHolder.keyUuid().toString());
            entry.setInventoryKeyName(visibleHolder.keyName());
        }
        if (standing.status() == TokenKeyStatus.ONBOARDABLE) {
            entry.setSuggestedName(suggestedName(pair.label(), standing.fingerprint(), inventory));
        }
        return entry;
    }

    /** An unaddressable key is listed for information only. */
    private static TokenKeyDto describe(ProviderUnaddressableKey key) {
        TokenKeyDto entry = new TokenKeyDto();
        entry.setLabel(key.label());
        entry.setKeyAlgorithm(key.algorithm());
        entry.setLength(key.length());
        entry.setStatus(TokenKeyStatus.NO_UNIQUE_ID);
        entry.setReason(NO_UNIQUE_ID);
        return entry;
    }

    /** One query each for the pairs' holders, unsettled imports and taken labels, however many pairs a page lists. */
    private Inventory inventoryOf(List<ProviderKeyPair> pairs) {
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
        Map<String, PublicKeyHolderSummary> holders = cryptographicKeyWriter.holdersOf(fingerprints);
        Set<String> importing = fingerprints.isEmpty()
                ? Set.of()
                : Set.copyOf(keyImportRepository.findImportingSpkiFingerprints(fingerprints, KeyImportState.UNSETTLED));
        Set<String> takenNames = labels.isEmpty()
                ? Set.of()
                : Set.copyOf(cryptographicKeyRepository.findNamesIn(labels));
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
        boolean visible = keyImportGates.maySeeInDetail(holder.keyUuid());
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
    private TokenKeyOnboardingResultDto onboard(TokenProfileFullModel profile, TokenKeySelectionDto selection,
            List<MetadataAttribute> keyPairMeta, List<ProviderKeyPair> reread, List<RequestAttribute> customAttributes)
            throws AttributeException, NotFoundException {
        TokenKeyOnboardingResultDto result = new TokenKeyOnboardingResultDto();
        result.setKeyPairHandle(selection.getKeyPairHandle());
        Optional<ProviderKeyPair> pair = reread
                .stream()
                .filter(candidate -> KeyPairMetaMatcher.matches(keyPairMeta, candidate.keyPairMeta()))
                .findFirst();
        if (pair.isEmpty()) {
            return skipped(result, GONE);
        }
        Inventory inventory = inventoryOf(List.of(pair.get()));
        Standing standing = standingOf(pair.get(), inventory);
        return switch (standing.status()) {
            case ONBOARDABLE ->
                onboardAsKeyOfItsOwn(profile, selection, pair.get(), standing, inventory, customAttributes, result);
            case ONBOARDABLE_INTO_KEY -> onboardIntoRecord(profile, pair.get(), standing, result);
            default -> refused(result, standing);
        };
    }

    private TokenKeyOnboardingResultDto onboardAsKeyOfItsOwn(TokenProfileFullModel profile,
            TokenKeySelectionDto selection, ProviderKeyPair pair, Standing standing, Inventory inventory,
            List<RequestAttribute> customAttributes, TokenKeyOnboardingResultDto result)
            throws AttributeException, NotFoundException {
        String name = selection.getName() == null || selection.getName().isBlank()
                ? suggestedName(pair.label(), standing.fingerprint(), inventory)
                : selection.getName().strip();
        if (cryptographicKeyRepository.existsByName(name)) {
            return skipped(result, CryptographicKeyWriter.NAME_TAKEN.formatted(name));
        }
        Optional<CryptographicKeyBasicModel> onboarded;
        try {
            onboarded = cryptographicKeyWriter
                    .onboardUnlessImporting(name, profile, standing.fingerprint(), pair.itemsNamed(name),
                            customAttributes);
        } catch (DataIntegrityViolationException e) {
            if (!UniqueViolations.isUniqueViolation(e)) {
                throw e;
            }
            return skipped(result, HELD_MEANWHILE);
        }
        if (onboarded.isEmpty()) {
            return skipped(result, IMPORTING);
        }
        cryptographicKeyWriter.updateOwnerAndGroups(onboarded.get(), KEEP_GROUPS);
        return onboardedAsNewKey(result, onboarded.get());
    }

    /**
     * The record keeps its name, owner, groups and custom attributes, as when an import adopts it. The result names it
     * only to a caller who may see it in detail.
     */
    private TokenKeyOnboardingResultDto onboardIntoRecord(TokenProfileFullModel profile, ProviderKeyPair pair,
            Standing standing, TokenKeyOnboardingResultDto result) throws AttributeException {
        PublicKeyHolderSummary record = standing.holder();
        Optional<CryptographicKeyBasicModel> onboarded;
        try {
            onboarded = cryptographicKeyWriter
                    .onboardIntoRecordUnlessImporting(record.keyUuid(), profile, standing.fingerprint(),
                            pair.itemsNamed(record.keyName()));
        } catch (ValidationException changedMeanwhile) {
            return skipped(result, RECORD_CHANGED);
        }
        if (onboarded.isEmpty()) {
            return skipped(result, IMPORTING);
        }
        result.setOnboarded(true);
        result.setIntoExistingKey(true);
        if (standing.holderVisible()) {
            result.setKeyUuid(onboarded.get().uuid().toString());
            result.setKeyName(onboarded.get().name());
        }
        return result;
    }

    private static TokenKeyOnboardingResultDto onboardedAsNewKey(TokenKeyOnboardingResultDto result,
            CryptographicKeyBasicModel key) {
        result.setOnboarded(true);
        result.setIntoExistingKey(false);
        result.setKeyUuid(key.uuid().toString());
        result.setKeyName(key.name());
        return result;
    }

    private static TokenKeyOnboardingResultDto refused(TokenKeyOnboardingResultDto result, Standing standing) {
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            result.setKeyUuid(visibleHolder.keyUuid().toString());
            result.setKeyName(visibleHolder.keyName());
        }
        return skipped(result, standing.refusal());
    }

    private static TokenKeyOnboardingResultDto skipped(TokenKeyOnboardingResultDto result, String reason) {
        result.setOnboarded(false);
        result.setReason(reason);
        return result;
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
     * What the inventory and the unsettled imports hold of a page of listed key pairs.
     *
     * @param holders the keys holding the pairs' public keys, by fingerprint
     * @param importing the fingerprints of the pairs' public keys that an unsettled import holds
     * @param takenNames the pairs' labels that keys have as names
     */
    private record Inventory(Map<String, PublicKeyHolderSummary> holders, Set<String> importing,
            Set<String> takenNames) {
    }

    /** A page of the Core API mapped onto the offset and limit the connector takes. */
    private record TokenKeyPage(int pageNumber, int itemsPerPage, int offset) {

        static TokenKeyPage of(int pageNumber, int itemsPerPage) {
            if (pageNumber < 1 || itemsPerPage < 1 || itemsPerPage > ListKeyPairsRequestV2Dto.MAX_LIMIT) {
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
