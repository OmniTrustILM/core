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
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingOutcome;
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
import com.otilm.core.model.crypto.ProviderKeyEntry;
import com.otilm.core.model.crypto.ProviderKeyEntryPage;
import com.otilm.core.model.crypto.ProviderKeyPair;
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
    static final String UNADDRESSABLE_PAIR = "The connector cannot address this key pair by its handle alone.";
    static final String HELD = "Key '%s' already holds this key pair.";
    static final String NOT_ACTIVE = "Key '%s' holds this public key without a token instance, but it is not active, so "
            + "the private key cannot join it.";
    static final String PUBLIC_KEY_MISSING = "The key storage holds no public key for this key pair.";
    static final String UNADDRESSABLE_KEY = "The connector cannot address this key alone.";
    static final String REFUSED_KEY = "The connector refuses to let the platform onboard this key.";
    static final String UNSUPPORTED_KEY_TYPE = "The connector cannot operate a key of this type.";
    static final String UNREADABLE_KEY = "The connector cannot read this key.";
    static final String UNREADABLE_PAIR = "The connector cannot read this key pair.";
    static final String UNRECOGNISED_HANDLE = "The connector does not recognise this handle.";
    static final String HELD_MEANWHILE = "The inventory came to hold this key pair while it was being onboarded.";
    static final String PUBLIC_KEY_TAKEN_MEANWHILE = "Another key came to hold this public key while the key pair was "
            + "being onboarded. List the key storage again.";
    static final String RECORD_CHANGED = "The key holding this public key changed while the private key was joining "
            + "it. List the key storage again.";
    static final String IMPORTING = "An import of this key pair is still in progress.";
    static final String PAGE_BEYOND_LAST_OFFSET = "The page must start at most " + Integer.MAX_VALUE
            + " entries into the listing.";
    static final String ONBOARDING_FAILED = "Failed to onboard the key pair.";
    private static final String FALLBACK_NAME = "Onboarded key";
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
        ProviderKeyEntryPage listed = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listKeyPairs(profile, page.offset(), page.itemsPerPage());
        Inventory inventory = inventoryOf(listed.entries(), Set.of());
        List<TokenKeyDto> entries = new ArrayList<>();
        for (ProviderKeyEntry entry : listed.entries()) {
            entries.add(describe(entry, inventory));
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
        List<ProviderKeyEntry> resolutions = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .resolveKeyPairs(profile, handles);
        Onboarding onboarding = new Onboarding(profile, inventoryOf(resolutions, importingBeforeResolution),
                customAttributes, customAttributePermissions, new ArrayList<>());
        OnboardTokenKeysResponseDto response = new OnboardTokenKeysResponseDto();
        try {
            for (int index = 0; index < selections.size(); index++) {
                response
                        .getResults()
                        .add(onboardOrReportFailure(onboarding, index, selections.get(index), resolutions.get(index)));
            }
        } finally {
            listInAuditRecord(onboarding.onboardedKeys());
        }
        nameLoneKeyInAuditRecord(onboarding.onboardedKeys());
        return response;
    }

    private TokenKeyOnboardingResultDto onboardOrReportFailure(Onboarding onboarding, int index,
            TokenKeySelectionDto selection, ProviderKeyEntry resolution) {
        TokenKeyOnboardingResultDto result;
        try {
            result = onboard(onboarding, selection, resolution);
        } catch (AttributeException | NotFoundException | DataIntegrityViolationException e) {
            logger
                    .warn("Selection {}, key pair stored as {} with fingerprint {}, could not be onboarded to {}",
                            index, resolution.storageName(), publicKeyFingerprint(resolution),
                            onboarding.profile().toIdentifierString(), e);
            result = failed(resultOf(selection), PlatformException.safeMessage(e, ONBOARDING_FAILED));
        }
        return withDiagnosticUnlessOnboarded(result, resolution);
    }

    /** A connector's diagnostic names the cause behind a key that was not onboarded. */
    private static TokenKeyOnboardingResultDto withDiagnosticUnlessOnboarded(TokenKeyOnboardingResultDto result,
            ProviderKeyEntry resolution) {
        if (!isOnboarded(result.getOutcome())) {
            result.setDiagnostic(resolution.diagnostic());
        }
        return result;
    }

    private static boolean isOnboarded(TokenKeyOnboardingOutcome outcome) {
        return outcome == TokenKeyOnboardingOutcome.ONBOARDED
                || outcome == TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY;
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

    private TokenKeyDto describe(ProviderKeyEntry entry, Inventory inventory) {
        return entry.keyPair() == null ? describeWithoutKeyPair(entry) : describeKeyPair(entry, inventory);
    }

    private TokenKeyDto describeKeyPair(ProviderKeyEntry entry, Inventory inventory) {
        ProviderKeyPair pair = entry.keyPair();
        Standing standing = withConnectorVerdict(standingOf(pair, inventory), entry);
        TokenKeyDto.TokenKeyDtoBuilder tokenKey = TokenKeyDto
                .builder()
                .keyPairMeta(pair.keyPairMeta())
                .storageName(entry.storageName())
                .keyAlgorithm(pair.privateKey().algorithm())
                .length(pair.privateKey().length())
                .status(standing.status())
                .fingerprint(standing.fingerprint())
                .reason(standing.refusal())
                .diagnostic(entry.diagnostic());
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            tokenKey.inventoryKeyUuid(visibleHolder.keyUuid()).inventoryKeyName(visibleHolder.keyName());
        }
        if (standing.status() == TokenKeyStatus.ONBOARDABLE) {
            tokenKey.suggestedName(inventory.suggestName(entry.storageName(), standing.fingerprint()));
        }
        return tokenKey.build();
    }

    /** An entry without a key pair is listed for information only, under the connector's status. */
    private static TokenKeyDto describeWithoutKeyPair(ProviderKeyEntry entry) {
        TokenKeyDto.TokenKeyDtoBuilder tokenKey = TokenKeyDto
                .builder()
                .storageName(entry.storageName())
                .keyAlgorithm(entry.algorithm())
                .length(entry.length())
                .diagnostic(entry.diagnostic());
        return switch (entry.status()) {
            case UNADDRESSABLE -> tokenKey.status(TokenKeyStatus.UNADDRESSABLE).reason(UNADDRESSABLE_KEY).build();
            case UNSUPPORTED_TYPE ->
                tokenKey.status(TokenKeyStatus.UNSUPPORTED_KEY_TYPE).reason(UNSUPPORTED_KEY_TYPE).build();
            case UNREADABLE -> tokenKey.status(TokenKeyStatus.UNREADABLE).reason(UNREADABLE_KEY).build();
            case NOT_FOUND -> tokenKey.status(TokenKeyStatus.GONE).reason(GONE).build();
            case AVAILABLE, REFUSED ->
                throw new IllegalStateException("The connector listed a key without its key pair as " + entry.status());
            case INVALID_HANDLE -> throw new IllegalStateException(
                    "The connector listed a key as " + entry.status().getCode() + ", which only a resolution reports");
        };
    }

    /**
     * One query each for the pairs' holders, unsettled imports and likely names, however many pairs a page lists.
     *
     * @param importingAlready fingerprints of unsettled imports read earlier, which count as importing too
     */
    private Inventory inventoryOf(List<ProviderKeyEntry> entries, Set<String> importingAlready) {
        List<ProviderKeyEntry> carryingKeyPair = entriesCarryingKeyPair(entries);
        Set<String> fingerprints = carryingKeyPair
                .stream()
                .map(entry -> publicKeyFingerprint(entry.keyPair()))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Set<String> likelyNames = carryingKeyPair
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
        String fingerprint = publicKeyFingerprint(pair);
        if (fingerprint == null) {
            return new Standing(TokenKeyStatus.PUBLIC_KEY_UNAVAILABLE, null, null, false, PUBLIC_KEY_MISSING);
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

    /**
     * The connector's refusal outranks every standing but {@code IN_INVENTORY}. No change on the platform's side lifts
     * a refusal. {@code IN_INVENTORY} names the token key that already holds the key pair.
     */
    private static Standing withConnectorVerdict(Standing standing, ProviderKeyEntry entry) {
        if (entry.status() == KeyEntryStatus.REFUSED && standing.status() != TokenKeyStatus.IN_INVENTORY) {
            return new Standing(TokenKeyStatus.REFUSED, standing.fingerprint(), standing.holder(),
                    standing.holderVisible(), REFUSED_KEY);
        }
        return standing;
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

    private static List<ProviderKeyEntry> entriesCarryingKeyPair(List<ProviderKeyEntry> entries) {
        return entries.stream().filter(entry -> entry.keyPair() != null).toList();
    }

    private static String publicKeyFingerprint(ProviderKeyEntry entry) {
        return entry.keyPair() == null ? null : publicKeyFingerprint(entry.keyPair());
    }

    private static String publicKeyFingerprint(ProviderKeyPair pair) {
        return pair.publicKey() == null ? null : CryptographyUtil.calculateKeyFingerprint(pair.publicKey().material());
    }

    private static boolean isGiven(String storageName) {
        return storageName != null && !storageName.isBlank();
    }

    /**
     * The names an entry's key pair is most likely suggested under: its storage name and its shortest fingerprinted
     * name, or none when the pair has no public key.
     */
    private static Stream<String> likelyNamesOf(ProviderKeyEntry entry) {
        String fingerprint = publicKeyFingerprint(entry);
        if (fingerprint == null) {
            return Stream.empty();
        }
        String storageName = entry.storageName();
        String shortestFingerprinted = withFingerprintPrefix(storageName, fingerprint, FINGERPRINT_PREFIX_LENGTH);
        return isGiven(storageName)
                ? Stream.of(storageName.strip(), shortestFingerprinted)
                : Stream.of(shortestFingerprinted);
    }

    private static String withFingerprintPrefix(String storageName, String fingerprint, int prefixLength) {
        String base = isGiven(storageName) ? storageName.strip() : FALLBACK_NAME;
        return "%s (%s)".formatted(base, fingerprint.substring(0, prefixLength));
    }

    /**
     * Onboards one selection, or reports in its result why it was refused. The other selections then still proceed.
     */
    private TokenKeyOnboardingResultDto onboard(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyEntry resolution) throws AttributeException, NotFoundException {
        TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result = resultOf(selection);
        return switch (resolution.status()) {
            case AVAILABLE, REFUSED -> onboardFoundPair(onboarding, selection, resolution, result);
            case NOT_FOUND -> blocked(result, TokenKeyStatus.GONE, GONE);
            case UNADDRESSABLE -> blocked(result, TokenKeyStatus.UNADDRESSABLE, UNADDRESSABLE_PAIR);
            case UNSUPPORTED_TYPE -> blocked(result, TokenKeyStatus.UNSUPPORTED_KEY_TYPE, UNSUPPORTED_KEY_TYPE);
            case UNREADABLE -> blocked(result, TokenKeyStatus.UNREADABLE, UNREADABLE_PAIR);
            case INVALID_HANDLE -> blockedByInvalidHandle(result);
        };
    }

    /** A fresh result, so a failure reports none of the fields an attempt set before it failed. */
    private static TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder resultOf(
            TokenKeySelectionDto selection) {
        return TokenKeyOnboardingResultDto.builder().keyPairMeta(selection.getKeyPairMeta());
    }

    private TokenKeyOnboardingResultDto onboardFoundPair(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyEntry resolution, TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException, NotFoundException {
        ProviderKeyPair pair = resolution.keyPair();
        Standing standing = withConnectorVerdict(standingOf(pair, onboarding.inventory()), resolution);
        return switch (standing.status()) {
            case ONBOARDABLE -> onboardAsKeyOfItsOwn(onboarding, selection, resolution, standing, result);
            case ONBOARDABLE_INTO_KEY -> onboardIntoRecord(onboarding, pair, standing, result);
            default -> blockedByStanding(result, standing);
        };
    }

    private TokenKeyOnboardingResultDto onboardAsKeyOfItsOwn(Onboarding onboarding, TokenKeySelectionDto selection,
            ProviderKeyEntry resolution, Standing standing,
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result)
            throws AttributeException, NotFoundException {
        ProviderKeyPair pair = resolution.keyPair();
        String name = selection.getName() == null || selection.getName().isBlank()
                ? onboarding.inventory().suggestedName(resolution.storageName(), standing.fingerprint())
                : selection.getName().strip();
        if (cryptographicKeyRepository.existsByName(name)) {
            return nameTaken(result, CryptographicKeyWriter.NAME_TAKEN.formatted(name));
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
            return afterLosingThePublicKey(result, standing.fingerprint());
        }
        if (onboarded.isEmpty()) {
            return blocked(result, TokenKeyStatus.IMPORT_IN_PROGRESS, IMPORTING);
        }
        CryptographicKeyBasicModel key = onboarded.get();
        onboarding.registered(standing.fingerprint(), heldAsKeyPair(key.uuid(), key.name(), profile), false);
        return onboardedAsNewKey(result, key);
    }

    /**
     * Another key took the public key's unique fingerprint first. Only a key holding the whole pair blocks the
     * onboarding, because a retry can join a record that holds the public key alone.
     */
    private TokenKeyOnboardingResultDto afterLosingThePublicKey(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, String fingerprint) {
        PublicKeyHolderSummary holder = cryptographicKeyWriter.holdersOf(Set.of(fingerprint)).get(fingerprint);
        if (holder != null && holder.holding() == Holding.KEY_PAIR) {
            if (keyImportGates.maySeeInDetail(holder.keyUuid(), holder.tokenInstanceUuid())) {
                result.keyUuid(holder.keyUuid()).keyName(holder.keyName());
            }
            return blocked(result, TokenKeyStatus.IN_INVENTORY, HELD_MEANWHILE);
        }
        return failed(result, PUBLIC_KEY_TAKEN_MEANWHILE);
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
            return failed(result, RECORD_CHANGED);
        }
        if (onboarded.isEmpty()) {
            return blocked(result, TokenKeyStatus.IMPORT_IN_PROGRESS, IMPORTING);
        }
        CryptographicKeyBasicModel key = onboarded.get();
        onboarding.registered(standing.fingerprint(), heldAsKeyPair(key.uuid(), key.name(), profile), true);
        result.outcome(TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY);
        if (standing.holderVisible()) {
            result.keyUuid(key.uuid()).keyName(key.name());
        }
        return result.build();
    }

    private static TokenKeyOnboardingResultDto onboardedAsNewKey(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, CryptographicKeyBasicModel key) {
        return result.outcome(TokenKeyOnboardingOutcome.ONBOARDED).keyUuid(key.uuid()).keyName(key.name()).build();
    }

    /** The key an onboarding registered the key pair in, which holds it with its private key on the profile's token. */
    private static PublicKeyHolderSummary heldAsKeyPair(UUID keyUuid, String keyName, TokenProfileFullModel profile) {
        boolean active = true;
        return new PublicKeyHolderSummary(keyUuid, keyName, profile.tokenInstanceReferenceUuid(), Holding.KEY_PAIR,
                active);
    }

    private static TokenKeyOnboardingResultDto blockedByStanding(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, Standing standing) {
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            result.keyUuid(visibleHolder.keyUuid()).keyName(visibleHolder.keyName());
        }
        return blocked(result, standing.status(), standing.refusal());
    }

    /** The key's state stops onboarding until it changes. */
    private static TokenKeyOnboardingResultDto blocked(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, TokenKeyStatus status,
            String reason) {
        return result.outcome(TokenKeyOnboardingOutcome.BLOCKED).status(status).reason(reason).build();
    }

    private static TokenKeyOnboardingResultDto blockedByInvalidHandle(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result) {
        return result.outcome(TokenKeyOnboardingOutcome.BLOCKED).reason(UNRECOGNISED_HANDLE).build();
    }

    private static TokenKeyOnboardingResultDto nameTaken(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, String reason) {
        return result.outcome(TokenKeyOnboardingOutcome.NAME_TAKEN).reason(reason).build();
    }

    /** A retry may onboard the key. */
    private static TokenKeyOnboardingResultDto failed(
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, String reason) {
        return result.outcome(TokenKeyOnboardingOutcome.FAILED).reason(reason).build();
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
     * count as taken. A later key pair with the same storage name is then suggested that name with a prefix of its
     * fingerprint, lengthened until no key has the name.
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

        String suggestName(String storageName, String fingerprint) {
            String name = suggestedName(storageName, fingerprint);
            nameTaken.put(name, true);
            return name;
        }

        String suggestedName(String storageName, String fingerprint) {
            if (isGiven(storageName) && isFree(storageName.strip())) {
                return storageName.strip();
            }
            return IntStream
                    .rangeClosed(FINGERPRINT_PREFIX_LENGTH, fingerprint.length())
                    .mapToObj(prefixLength -> withFingerprintPrefix(storageName, fingerprint, prefixLength))
                    .filter(this::isFree)
                    .findFirst()
                    .orElseGet(() -> withFingerprintPrefix(storageName, fingerprint, fingerprint.length()));
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
