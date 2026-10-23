package com.otilm.core.service.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.client.cryptography.key.TokenKeySelectionDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingResultDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyStatus;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.OnboardedKeys;
import com.otilm.core.model.crypto.OnboardedKeys.OnboardedKey;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.ProviderKeyPairPage;
import com.otilm.core.model.crypto.ProviderKeyPairResolution;
import com.otilm.core.model.crypto.ProviderUnusableKey;
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
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Reads the token outside any transaction and saves each onboarded key in a transaction of its own. This keeps a slow
 * token from holding database locks and one refused key from undoing the others.
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
public class TokenKeyOnboardingServiceImpl implements TokenKeyOnboardingExternalService {

    private static final Logger logger = LoggerFactory.getLogger(TokenKeyOnboardingServiceImpl.class);

    static final String GONE = "The key storage no longer holds this key pair.";
    static final String AMBIGUOUS_PAIR = "The key storage holds more than one key pair under this handle.";
    static final String HELD = "Key %s already holds this key pair.";
    static final String NOT_ACTIVE = "Key %s holds this public key without a token instance, but it is not active, so "
            + "the private key cannot join it.";
    static final String PUBLIC_KEY_MISSING = "The key storage holds no public key for this key pair.";
    static final String NO_USABLE_ID = "The key storage holds this key without an ID the platform can address it by.";
    static final String UNSUPPORTED_KEY_TYPE = "The connector cannot operate a key of this type.";
    static final String UNREADABLE_KEY = "The connector cannot read this key.";
    static final String UNREADABLE_PAIR = "The connector cannot read this key pair.";
    static final String UNRECOGNISED_HANDLE = "The connector does not recognise this handle.";
    static final String HELD_MEANWHILE = "The inventory came to hold this key pair while it was being onboarded.";
    static final String RECORD_CHANGED = "The key holding this public key changed while the private key was joining "
            + "it. List the key storage again.";
    static final String IMPORTING = "An import of this key pair is still in progress.";
    static final String PAGE_BEYOND_LAST_OFFSET = "The page must start at most " + Integer.MAX_VALUE
            + " key pairs into the listing.";
    static final String ONBOARDING_FAILED = "Failed to onboard the key pair.";
    private static final String UNLABELLED_NAME = "Onboarded key";
    private static final int FINGERPRINT_PREFIX_LENGTH = 8;

    private final KeyListGates keyListGates;
    private final KeyImportGates keyImportGates;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final KeyImportRepository keyImportRepository;
    private final CryptographicKeyWriter cryptographicKeyWriter;
    private final AttributeEngine attributeEngine;

    private AuditOperationDataOverride auditOperationDataOverride;

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

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST)
    public TokenKeyListResponseDto listTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid, int pageNumber,
            int itemsPerPage) throws ConnectorException, NotFoundException {
        TokenProfileFullModel profile = keyListGates.requireListable(tokenInstanceUuid, tokenProfileUuid);
        TokenKeyPage page = TokenKeyPage.of(pageNumber, itemsPerPage);
        ProviderKeyPairPage listed = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listKeyPairs(profile, page.offset(), page.itemsPerPage());
        Inventory inventory = inventoryOf(listed.keyPairs(), Set.of());
        List<TokenKeyDto> entries = new ArrayList<>();
        for (ProviderKeyPair pair : listed.keyPairs()) {
            entries.add(describe(pair, inventory));
        }
        for (ProviderUnusableKey key : listed.unusableKeys()) {
            entries.add(describe(key));
        }
        return page.response(entries, listed.totalItems());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE)
    public OnboardTokenKeysResponseDto onboardTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            OnboardTokenKeysRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        TokenProfileFullModel profile = keyListGates.requireListable(tokenInstanceUuid, tokenProfileUuid);
        List<TokenKeySelectionDto> selections = request.getKeys();
        List<RequestAttribute> customAttributes = request.getCustomAttributes();
        SecurityResourceFilter customAttributePermissions = attributeEngine
                .loadCustomAttributesSecurityResourceFilter();
        attributeEngine
                .validateWritableCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, customAttributes,
                        customAttributePermissions);
        Set<String> importingBeforeResolution = importingOn(profile);
        List<List<MetadataAttribute>> handles = selections.stream().map(TokenKeySelectionDto::getKeyPairMeta).toList();
        List<ProviderKeyPairResolution> resolutions = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .resolveKeyPairs(profile, handles);
        List<ProviderKeyPair> found = resolutions
                .stream()
                .map(ProviderKeyPairResolution::keyPair)
                .filter(Objects::nonNull)
                .toList();
        Onboarding onboarding = new Onboarding(profile, inventoryOf(found, importingBeforeResolution), customAttributes,
                customAttributePermissions, new ArrayList<>());
        OnboardTokenKeysResponseDto response = new OnboardTokenKeysResponseDto();
        try {
            for (int index = 0; index < selections.size(); index++) {
                response
                        .getResults()
                        .add(onboardOrReportFailure(onboarding, selections.get(index), resolutions.get(index)));
            }
        } finally {
            listInAuditRecord(onboarding.onboardedKeys());
        }
        nameLoneKeyInAuditRecord(onboarding.onboardedKeys());
        return response;
    }

    private TokenKeyOnboardingResultDto onboardOrReportFailure(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyPairResolution resolution) {
        try {
            return onboard(onboarding, selection, resolution);
        } catch (AttributeException | NotFoundException | DataIntegrityViolationException e) {
            logger.warn("A key pair could not be onboarded to {}", onboarding.profile().toIdentifierString(), e);
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result = TokenKeyOnboardingResultDto
                    .builder()
                    .keyPairMeta(selection.getKeyPairMeta());
            return skipped(result, PlatformException.safeMessage(e, ONBOARDING_FAILED));
        }
    }

    /**
     * Lists every onboarded key in the audit record, including joined records the caller may not see. Each key commits
     * on its own, so a request that fails later still lists the keys it onboarded.
     */
    private void listInAuditRecord(List<OnboardedKey> onboardedKeys) {
        if (inRequestScope()) {
            auditOperationDataOverride.set(new OnboardedKeys(onboardedKeys));
        }
    }

    private static boolean inRequestScope() {
        return RequestContextHolder.getRequestAttributes() != null;
    }

    /**
     * Makes a lone onboarded key the audit record's resource. Only a completed request does this, so a failed request's
     * record lists its keys in the operation data alone.
     */
    private static void nameLoneKeyInAuditRecord(List<OnboardedKey> onboardedKeys) {
        if (onboardedKeys.size() == 1) {
            OnboardedKey onboarded = onboardedKeys.getFirst();
            LoggingHelper.putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY, false, onboarded.uuid(), onboarded.name());
        }
    }

    /**
     * The fingerprints of the token's unsettled imports, read before the token resolves the selections: an import that
     * settles in between may have destroyed a key pair the token still found.
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
            entry.suggestedName(inventory.suggestName(pair.label(), standing.fingerprint()));
        }
        return entry.build();
    }

    /** An unusable key is listed for information only, under the connector's reason. */
    private static TokenKeyDto describe(ProviderUnusableKey key) {
        TokenKeyDto.TokenKeyDtoBuilder entry = TokenKeyDto
                .builder()
                .label(key.label())
                .keyAlgorithm(key.algorithm())
                .length(key.length());
        return switch (key.reason()) {
            case UNADDRESSABLE -> entry.status(TokenKeyStatus.NO_USABLE_ID).reason(NO_USABLE_ID).build();
            case UNSUPPORTED_TYPE ->
                entry.status(TokenKeyStatus.UNSUPPORTED_KEY_TYPE).reason(UNSUPPORTED_KEY_TYPE).build();
            case UNREADABLE -> entry.status(TokenKeyStatus.UNREADABLE).reason(UNREADABLE_KEY).build();
            case NOT_FOUND -> entry.status(TokenKeyStatus.GONE).reason(GONE).build();
        };
    }

    /**
     * One query each for the pairs' holders, unsettled imports and likely names, however many pairs a page lists.
     *
     * @param importingAlready fingerprints of unsettled imports read earlier, which count as importing too
     */
    private Inventory inventoryOf(List<ProviderKeyPair> pairs, Set<String> importingAlready) {
        Set<String> fingerprints = pairs
                .stream()
                .map(TokenKeyOnboardingServiceImpl::fingerprintOf)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Set<String> likelyNames = pairs
                .stream()
                .flatMap(TokenKeyOnboardingServiceImpl::likelyNamesOf)
                .collect(Collectors.toSet());
        Map<String, PublicKeyHolderSummary> holders = new HashMap<>(cryptographicKeyWriter.holdersOf(fingerprints));
        Set<String> importing = new HashSet<>(importingAlready);
        if (!fingerprints.isEmpty()) {
            importing.addAll(keyImportRepository.findImportingSpkiFingerprints(fingerprints, KeyImportState.UNSETTLED));
        }
        Map<String, Boolean> nameTaken = new HashMap<>();
        if (!likelyNames.isEmpty()) {
            Set<String> taken = Set.copyOf(cryptographicKeyRepository.findNamesIn(likelyNames));
            likelyNames.forEach(name -> nameTaken.put(name, taken.contains(name)));
        }
        return new Inventory(holders, importing, nameTaken, cryptographicKeyRepository::existsByName);
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
            case KEY_PAIR -> held(TokenKeyStatus.IN_INVENTORY, fingerprint, holder, visible, HELD);
            case PUBLIC_KEY_IN_TOKEN -> standingAsImported(TokenKeyStatus.IN_INVENTORY, fingerprint, holder, visible);
            case PUBLIC_KEY_ONLY -> holder.active()
                    ? standingAsImported(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN, fingerprint, holder, visible)
                    : held(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN, fingerprint, holder, visible, NOT_ACTIVE);
        };
    }

    /** The holder takes the private key exactly when an import into it could go on. */
    private Standing standingAsImported(TokenKeyStatus refusedStatus, String fingerprint, PublicKeyHolderSummary holder,
            boolean visible) {
        return keyImportGates
                .refusalOf(holder, visible)
                .map(refusal -> new Standing(refusedStatus, fingerprint, holder, visible, refusal))
                .orElseGet(() -> new Standing(TokenKeyStatus.ONBOARDABLE_INTO_KEY, fingerprint, holder, visible, null));
    }

    private static Standing held(TokenKeyStatus status, String fingerprint, PublicKeyHolderSummary holder,
            boolean visible, String reason) {
        String refusal = KeyImportGates.refusalNaming(reason, holder.keyName(), visible);
        return new Standing(status, fingerprint, holder, visible, refusal);
    }

    private static String fingerprintOf(ProviderKeyPair pair) {
        return pair.publicKey() == null ? null : CryptographyUtil.calculateKeyFingerprint(pair.publicKey().material());
    }

    private static boolean isLabelled(String label) {
        return label != null && !label.isBlank();
    }

    /** The names a key pair is most likely suggested: its label, and the shortest name its fingerprint makes. */
    private static Stream<String> likelyNamesOf(ProviderKeyPair pair) {
        String fingerprint = fingerprintOf(pair);
        if (fingerprint == null) {
            return Stream.empty();
        }
        String shortestFingerprinted = withFingerprintPrefix(pair.label(), fingerprint, FINGERPRINT_PREFIX_LENGTH);
        return isLabelled(pair.label())
                ? Stream.of(pair.label().strip(), shortestFingerprinted)
                : Stream.of(shortestFingerprinted);
    }

    private static String withFingerprintPrefix(String label, String fingerprint, int prefixLength) {
        String base = isLabelled(label) ? label.strip() : UNLABELLED_NAME;
        return "%s (%s)".formatted(base, fingerprint.substring(0, prefixLength));
    }

    /**
     * Onboards one selection, or reports in its result why it was refused. The other selections then still proceed.
     */
    private TokenKeyOnboardingResultDto onboard(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyPairResolution resolution) throws AttributeException, NotFoundException {
        TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result = TokenKeyOnboardingResultDto
                .builder()
                .keyPairMeta(selection.getKeyPairMeta());
        return switch (resolution.outcome()) {
            case FOUND -> onboardFoundPair(onboarding, selection, resolution.keyPair(), result);
            case NOT_FOUND -> skipped(result, GONE);
            case AMBIGUOUS -> skipped(result, AMBIGUOUS_PAIR);
            case UNREADABLE -> skipped(result, UNREADABLE_PAIR);
            case INVALID_HANDLE -> skipped(result, UNRECOGNISED_HANDLE);
        };
    }

    private TokenKeyOnboardingResultDto onboardFoundPair(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyPair pair, TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException, NotFoundException {
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
                ? onboarding.inventory().suggestedName(pair.label(), standing.fingerprint())
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
        onboarding.registered(standing.fingerprint(), heldAsKeyPair(key.uuid(), key.name(), profile), false);
        return onboardedAsNewKey(result, key);
    }

    /**
     * The record keeps its name, owner, groups and custom attributes, as when an import adopts it. The result names it
     * only to a caller who may see it in detail.
     */
    private TokenKeyOnboardingResultDto onboardIntoRecord(Onboarding onboarding, ProviderKeyPair pair,
            Standing standing, TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException {
        PublicKeyHolderSummary publicKeyRecord = standing.holder();
        TokenProfileFullModel profile = onboarding.profile();
        Optional<CryptographicKeyBasicModel> onboarded;
        try {
            onboarded = cryptographicKeyWriter
                    .onboardIntoRecordUnlessImporting(publicKeyRecord.keyUuid(), profile, standing.fingerprint(),
                            pair.toOnboardedItems(publicKeyRecord.keyName()));
        } catch (ValidationException changedMeanwhile) {
            return skipped(result, RECORD_CHANGED);
        }
        if (onboarded.isEmpty()) {
            return skipped(result, IMPORTING);
        }
        onboarding
                .registered(standing.fingerprint(),
                        heldAsKeyPair(publicKeyRecord.keyUuid(), publicKeyRecord.keyName(), profile), true);
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
     * What the inventory and the unsettled imports hold of the key pairs a token listed or resolved. Each key an
     * onboarding registers is added, so selecting its key pair again finds it held. Its name and each suggested name
     * count as taken, so a later key pair with the same label is suggested the label with a prefix of its fingerprint,
     * lengthened until no key has the name.
     *
     * @param holders the keys holding the pairs' public keys, by fingerprint
     * @param importing the fingerprints of the pairs' public keys that an unsettled import holds
     * @param nameTaken whether a key has the name or a listed key pair was suggested it, for each name checked
     * @param inInventory whether a key has a name not checked yet
     */
    private record Inventory(Map<String, PublicKeyHolderSummary> holders, Set<String> importing,
            Map<String, Boolean> nameTaken, Predicate<String> inInventory) {

        void add(String fingerprint, PublicKeyHolderSummary holder) {
            holders.put(fingerprint, holder);
            nameTaken.put(holder.keyName(), true);
        }

        String suggestName(String label, String fingerprint) {
            String name = suggestedName(label, fingerprint);
            nameTaken.put(name, true);
            return name;
        }

        String suggestedName(String label, String fingerprint) {
            if (isLabelled(label) && isFree(label.strip())) {
                return label.strip();
            }
            return IntStream
                    .rangeClosed(FINGERPRINT_PREFIX_LENGTH, fingerprint.length())
                    .mapToObj(prefixLength -> withFingerprintPrefix(label, fingerprint, prefixLength))
                    .filter(this::isFree)
                    .findFirst()
                    .orElseGet(() -> withFingerprintPrefix(label, fingerprint, fingerprint.length()));
        }

        private boolean isFree(String name) {
            return !nameTaken.computeIfAbsent(name, inInventory::test);
        }
    }

    /**
     * One onboarding request after the token resolved its selections.
     *
     * @param inventory what the inventory holds of the key pairs the token resolved
     * @param customAttributes the custom attributes every key of its own takes, or {@code null} for none
     * @param customAttributePermissions permissions applied to the custom attributes
     * @param onboardedKeys the keys the key pairs were registered in so far
     */
    private record Onboarding(TokenProfileFullModel profile, Inventory inventory,
            List<RequestAttribute> customAttributes, SecurityResourceFilter customAttributePermissions,
            List<OnboardedKey> onboardedKeys) {

        void registered(String fingerprint, PublicKeyHolderSummary holder, boolean intoExistingKey) {
            inventory.add(fingerprint, holder);
            onboardedKeys.add(new OnboardedKey(holder.keyUuid().toString(), holder.keyName(), intoExistingKey));
        }
    }

    /** A page of the Core API mapped onto the offset and limit the connector takes. */
    private record TokenKeyPage(int pageNumber, int itemsPerPage, int offset) {

        static TokenKeyPage of(int pageNumber, int itemsPerPage) {
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
