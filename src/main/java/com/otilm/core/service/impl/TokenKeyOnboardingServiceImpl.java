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
import com.otilm.api.model.common.enums.cryptography.KeyType;
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
import com.otilm.core.key.description.DescribedKey;
import com.otilm.core.key.description.KeyDescriber;
import com.otilm.core.key.description.KeyParameters;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.HandleHolderSummary;
import com.otilm.core.model.crypto.OnboardedKeys;
import com.otilm.core.model.crypto.OnboardedKeys.OnboardedKey;
import com.otilm.core.model.crypto.ProviderKeyEntry;
import com.otilm.core.model.crypto.ProviderKeyEntryPage;
import com.otilm.core.model.crypto.ProviderKeyItem;
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
    static final String HELD_UNNAMED = "Another key in the inventory already holds this key pair.";
    static final String HANDLE_REUSED = "The token reused the handle of key '%1$s' for this key pair. Remove key '%1$s' "
            + "from the inventory to onboard this key pair.";
    static final String HANDLE_REUSED_UNNAMED = "The token reused the handle of another key in the inventory for this "
            + "key pair. That key must be removed from the inventory to onboard this key pair.";
    static final String NOT_ACTIVE = "Key '%s' holds this public key without a token instance, but it is not active, so "
            + "the private key cannot join it.";
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
    static final String IMPORTING_ON_TOKEN = "An import of a key pair into this key storage is still in progress.";
    static final String PAGE_BEYOND_LAST_OFFSET = "The page must start at most " + Integer.MAX_VALUE
            + " entries into the listing.";
    static final String ONBOARDING_FAILED = "Failed to onboard the key pair.";
    private static final String FALLBACK_NAME = "Onboarded key";
    private static final int DIGEST_PREFIX_LENGTH = 8;
    private static final HolderReason HELD_BY_HANDLE = new HolderReason(HELD, HELD_UNNAMED);
    private static final HolderReason HELD_MEANWHILE_BY_HANDLE = HolderReason.fixed(HELD_MEANWHILE);
    private static final HolderReason HANDLE_REUSED_BY_TOKEN = new HolderReason(HANDLE_REUSED, HANDLE_REUSED_UNNAMED);

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
        Inventory inventory = inventoryOf(profile.tokenInstanceReferenceUuid(), listed.entries(), Set.of());
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
        Onboarding onboarding = new Onboarding(profile,
                inventoryOf(profile.tokenInstanceReferenceUuid(), resolutions, importingBeforeResolution),
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
        ProviderKeyItem describedHalf = pair.isPrivateOnly() ? pair.privateKey() : pair.publicKey();
        Standing standing = withConnectorVerdict(standingOf(pair, inventory), entry);
        TokenKeyDto.TokenKeyDtoBuilder tokenKey = TokenKeyDto
                .builder()
                .keyPairMeta(pair.keyPairMeta())
                .storageName(entry.storageName())
                .keyAlgorithm(describedHalf.algorithm())
                .parameterSet(describedHalf.parameterSet())
                .length(describedHalf.length())
                .privateOnly(pair.isPrivateOnly())
                .status(standing.status())
                .fingerprint(standing.fingerprint())
                .reason(standing.refusal())
                .diagnostic(entry.diagnostic());
        PublicKeyHolderSummary visibleHolder = standing.visibleHolder();
        if (visibleHolder != null) {
            tokenKey.inventoryKeyUuid(visibleHolder.keyUuid()).inventoryKeyName(visibleHolder.keyName());
        }
        if (standing.status() == TokenKeyStatus.ONBOARDABLE) {
            tokenKey.suggestedName(inventory.reserveSuggestedName(entry.storageName(), nameDigestOf(pair)));
        }
        return tokenKey.build();
    }

    /** An entry without a key pair is listed for information only, under the connector's status. */
    private static TokenKeyDto describeWithoutKeyPair(ProviderKeyEntry entry) {
        KeyParameters parameters = entry.algorithmIdentifier() == null
                ? null
                : new KeyParameters(entry.algorithmIdentifier(), null);
        DescribedKey described = KeyDescriber
                .describe(parameters, KeyType.PRIVATE_KEY, entry.algorithm(), entry.length());
        TokenKeyDto.TokenKeyDtoBuilder tokenKey = TokenKeyDto
                .builder()
                .storageName(entry.storageName())
                .keyAlgorithm(described.algorithm())
                .parameterSet(described.parameterSet())
                .length(described.length())
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
     * One query each for the pairs' holders by handle and by public key, unsettled imports and likely names, however
     * many pairs a page lists.
     *
     * @param tokenInstanceUuid the token instance that listed or resolved the entries
     * @param importingAlready fingerprints of unsettled imports read earlier, which count as importing too
     */
    private Inventory inventoryOf(UUID tokenInstanceUuid, List<ProviderKeyEntry> entries,
            Set<String> importingAlready) {
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
        Set<String> handleDigests = carryingKeyPair
                .stream()
                .map(entry -> entry.keyPair().privateKey().handleDigest())
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Map<String, HandleHolderSummary> handleHolders = new HashMap<>(
                cryptographicKeyWriter.holdersOfHandles(tokenInstanceUuid, handleDigests));
        Map<String, PublicKeyHolderSummary> publicKeyHolders = new HashMap<>(
                cryptographicKeyWriter.holdersOf(fingerprints));
        Set<String> importing = new HashSet<>(importingAlready);
        if (!fingerprints.isEmpty()) {
            importing.addAll(keyImportRepository.findImportingSpkiFingerprints(fingerprints, KeyImportState.UNSETTLED));
        }
        Map<String, Boolean> nameTaken = new HashMap<>();
        if (!likelyNames.isEmpty()) {
            Set<String> taken = Set.copyOf(cryptographicKeyRepository.findNamesIn(likelyNames));
            likelyNames.forEach(name -> nameTaken.put(name, taken.contains(name)));
        }
        boolean keyPairImportOnToken = keyPairImportUnsettledOn(tokenInstanceUuid, carryingKeyPair, importingAlready);
        return new Inventory(handleHolders, publicKeyHolders, importing, keyPairImportOnToken, nameTaken,
                cryptographicKeyRepository::existsByName);
    }

    /**
     * Only a private key listed alone waits for this, so a page without one skips the query. An import seen unsettled
     * before the token resolved the selection counts too, since it may have destroyed a key the token still found.
     */
    private boolean keyPairImportUnsettledOn(UUID tokenInstanceUuid, List<ProviderKeyEntry> carryingKeyPair,
            Set<String> importingAlready) {
        boolean listsPrivateKeyAlone = carryingKeyPair.stream().anyMatch(entry -> entry.keyPair().isPrivateOnly());
        if (!listsPrivateKeyAlone) {
            return false;
        }
        if (!importingAlready.isEmpty()) {
            return true;
        }
        return keyImportRepository
                .existsByTokenInstanceUuidAndSpkiFingerprintIsNotNullAndStateIn(tokenInstanceUuid,
                        KeyImportState.UNSETTLED);
    }

    /**
     * The key holding the pair's handle decides first, whatever the token lists of the public key. A private key listed
     * alone then waits for every unsettled key-pair import on its token, and a pair's public key decides the rest.
     */
    private Standing standingOf(ProviderKeyPair pair, Inventory inventory) {
        String fingerprint = publicKeyFingerprint(pair);
        HandleHolderSummary handleHolder = inventory.handleHolderOf(pair);
        if (handleHolder != null) {
            return standingHeldByHandle(pair, fingerprint, handleHolder, HELD_BY_HANDLE);
        }
        if (pair.isPrivateOnly()) {
            return inventory.keyPairImportOnToken()
                    ? new Standing(TokenKeyStatus.IMPORT_IN_PROGRESS, null, null, false, IMPORTING_ON_TOKEN)
                    : Standing.onboardable(null);
        }
        if (inventory.importing().contains(fingerprint)) {
            return new Standing(TokenKeyStatus.IMPORT_IN_PROGRESS, fingerprint, null, false, IMPORTING);
        }
        PublicKeyHolderSummary holder = inventory.publicKeyHolders().get(fingerprint);
        if (holder == null) {
            return Standing.onboardable(fingerprint);
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
     * A key holds the pair's handle: it holds the pair, or the token reused its handle for this pair. The reason names
     * the key only to a caller who may see it in detail.
     */
    private Standing standingHeldByHandle(ProviderKeyPair pair, String fingerprint, HandleHolderSummary handleHolder,
            HolderReason samePairReason) {
        boolean visible = keyImportGates.maySeeInDetail(handleHolder.keyUuid(), handleHolder.tokenInstanceUuid());
        boolean handleReused = !handleHolder.agreesWith(pair.privateKey(), fingerprint);
        HolderReason reason = handleReused ? HANDLE_REUSED_BY_TOKEN : samePairReason;
        return new Standing(TokenKeyStatus.IN_INVENTORY, fingerprint, handleHolder.asKeyPairHolder(), visible,
                reason.forCaller(handleHolder.keyName(), visible), handleReused);
    }

    /**
     * The connector's refusal outranks every standing but a key holding the pair, which tells the caller where the pair
     * already is. No change on the platform's side lifts a refusal.
     */
    private static Standing withConnectorVerdict(Standing standing, ProviderKeyEntry entry) {
        if (entry.status() == KeyEntryStatus.REFUSED && !standing.heldByKey()) {
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
     * A key pair is usually suggested one of these names, so a listing checks them for all its pairs in one query. Only
     * when they are taken does it check names with a longer digest prefix, one at a time.
     */
    private static Stream<String> likelyNamesOf(ProviderKeyEntry entry) {
        String nameDigest = nameDigestOf(entry.keyPair());
        String storageName = entry.storageName();
        String shortestWithDigest = withDigestPrefix(storageName, nameDigest, DIGEST_PREFIX_LENGTH);
        return isGiven(storageName)
                ? Stream.of(storageName.strip(), shortestWithDigest)
                : Stream.of(shortestWithDigest);
    }

    /**
     * When the storage name is already taken, the suggested name adds the start of this digest. A private key listed
     * alone has no public key to fingerprint, so its handle digest stands in.
     */
    private static String nameDigestOf(ProviderKeyPair pair) {
        String fingerprint = publicKeyFingerprint(pair);
        if (fingerprint != null) {
            return fingerprint;
        }
        return Objects.requireNonNull(pair.privateKey().handleDigest(), "A listed private key carries its handle.");
    }

    private static String withDigestPrefix(String storageName, String nameDigest, int prefixLength) {
        String base = isGiven(storageName) ? storageName.strip() : FALLBACK_NAME;
        return "%s (%s)".formatted(base, nameDigest.substring(0, prefixLength));
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
                ? onboarding.inventory().suggestedName(resolution.storageName(), nameDigestOf(pair))
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
            return blockedIfHandleHeldMeanwhile(profile, pair, standing.fingerprint(), result)
                    .orElseGet(() -> afterLosingAUniqueValue(pair, result, standing.fingerprint()));
        }
        if (onboarded.isEmpty()) {
            String importing = pair.isPrivateOnly() ? IMPORTING_ON_TOKEN : IMPORTING;
            return blocked(result, TokenKeyStatus.IMPORT_IN_PROGRESS, importing);
        }
        CryptographicKeyBasicModel key = onboarded.get();
        onboarding.registered(pair, heldAsKeyPair(key, profile, pair, standing.fingerprint()), false);
        return onboardedAsNewKey(result, key);
    }

    /** Another key took the pair's handle first: it holds the pair, or the token reused the handle the key held. */
    private Optional<TokenKeyOnboardingResultDto> blockedIfHandleHeldMeanwhile(TokenProfileFullModel profile,
            ProviderKeyPair pair, String fingerprint,
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result) {
        String handleDigest = pair.privateKey().handleDigest();
        if (handleDigest == null) {
            return Optional.empty();
        }
        HandleHolderSummary handleHolder = cryptographicKeyWriter
                .holdersOfHandles(profile.tokenInstanceReferenceUuid(), Set.of(handleDigest))
                .get(handleDigest);
        return Optional
                .ofNullable(handleHolder)
                .map(holder -> blockedByStanding(result,
                        standingHeldByHandle(pair, fingerprint, holder, HELD_MEANWHILE_BY_HANDLE)));
    }

    /**
     * Runs once no key holds the pair's handle. A private key alone then fails for a retry to settle, and a pair defers
     * to the key holding its public key.
     */
    private TokenKeyOnboardingResultDto afterLosingAUniqueValue(ProviderKeyPair pair,
            TokenKeyOnboardingResultDto.TokenKeyOnboardingResultDtoBuilder result, String fingerprint) {
        return pair.isPrivateOnly() ? failed(result, ONBOARDING_FAILED) : afterLosingThePublicKey(result, fingerprint);
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
        } catch (DataIntegrityViolationException e) {
            if (!UniqueViolations.isUniqueViolation(e)) {
                throw e;
            }
            return blockedIfHandleHeldMeanwhile(profile, pair, standing.fingerprint(), result)
                    .orElseGet(() -> failed(result, RECORD_CHANGED));
        }
        if (onboarded.isEmpty()) {
            return blocked(result, TokenKeyStatus.IMPORT_IN_PROGRESS, IMPORTING);
        }
        CryptographicKeyBasicModel key = onboarded.get();
        onboarding.registered(pair, heldAsKeyPair(key, profile, pair, standing.fingerprint()), true);
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
    private static HandleHolderSummary heldAsKeyPair(CryptographicKeyBasicModel key, TokenProfileFullModel profile,
            ProviderKeyPair pair, String fingerprint) {
        boolean active = true;
        ProviderKeyItem privateKey = pair.privateKey();
        return new HandleHolderSummary(key.uuid(), key.name(), profile.tokenInstanceReferenceUuid(),
                privateKey.algorithm(), privateKey.parameterSet(), privateKey.length(), fingerprint, active);
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
     * @param holder the inventory key holding the pair's public key or handle, or null
     * @param holderVisible whether the caller may see the holder in detail
     * @param refusal the reason the pair is refused, or null for an onboardable pair
     * @param handleReused whether the holder holds the pair's handle only because the token reused it
     */
    private record Standing(TokenKeyStatus status, String fingerprint, PublicKeyHolderSummary holder,
            boolean holderVisible, String refusal, boolean handleReused) {

        Standing(TokenKeyStatus status, String fingerprint, PublicKeyHolderSummary holder, boolean holderVisible,
                String refusal) {
            this(status, fingerprint, holder, holderVisible, refusal, false);
        }

        static Standing onboardable(String fingerprint) {
            return new Standing(TokenKeyStatus.ONBOARDABLE, fingerprint, null, false, null);
        }

        boolean heldByKey() {
            return status == TokenKeyStatus.IN_INVENTORY && !handleReused;
        }

        /** The holder, when the caller may see it in detail. */
        PublicKeyHolderSummary visibleHolder() {
            return holderVisible ? holder : null;
        }
    }

    /**
     * The reason a key blocks a pair: named for a caller who may see the key in detail, unnamed for any other.
     *
     * @param named the reason for a caller who may see the key in detail
     * @param unnamed the reason for any other caller
     */
    private record HolderReason(String named, String unnamed) {

        /** A reason that names no key, so every caller gets it. */
        static HolderReason fixed(String reason) {
            return new HolderReason(reason, reason);
        }

        String forCaller(String keyName, boolean keyVisible) {
            return keyVisible ? named.formatted(keyName) : unnamed;
        }
    }

    /**
     * What the inventory and the unsettled imports hold of the key pairs a token listed or resolved. Each key an
     * onboarding registers is added, so selecting its key pair again finds it held. Its name and each suggested name
     * count as taken. A later key pair with the same storage name is then suggested that name with a prefix of its name
     * digest, lengthened while a key has the name, up to the whole digest.
     *
     * @param handleHolders the keys holding the pairs' private key handles, by handle digest
     * @param publicKeyHolders the keys holding the pairs' public keys, by fingerprint
     * @param importing the fingerprints of the pairs' public keys that an unsettled import holds
     * @param keyPairImportOnToken whether a key-pair import on the token is unsettled, read only for a private key
     * listed alone
     * @param nameTaken whether a key has the name or a listed key pair was suggested it, for each name checked
     * @param inInventory whether a key has a name not checked yet
     */
    private record Inventory(Map<String, HandleHolderSummary> handleHolders,
            Map<String, PublicKeyHolderSummary> publicKeyHolders, Set<String> importing, boolean keyPairImportOnToken,
            Map<String, Boolean> nameTaken, Predicate<String> inInventory) {

        void add(ProviderKeyPair pair, HandleHolderSummary holder) {
            String handleDigest = pair.privateKey().handleDigest();
            if (handleDigest != null) {
                handleHolders.put(handleDigest, holder);
            }
            if (holder.publicKeyFingerprint() != null) {
                publicKeyHolders.put(holder.publicKeyFingerprint(), holder.asKeyPairHolder());
            }
            nameTaken.put(holder.keyName(), true);
        }

        /** The key holding the pair's handle, or null when no key holds it or the pair has no handle. */
        HandleHolderSummary handleHolderOf(ProviderKeyPair pair) {
            String handleDigest = pair.privateKey().handleDigest();
            return handleDigest == null ? null : handleHolders.get(handleDigest);
        }

        String reserveSuggestedName(String storageName, String nameDigest) {
            String name = suggestedName(storageName, nameDigest);
            nameTaken.put(name, true);
            return name;
        }

        String suggestedName(String storageName, String nameDigest) {
            if (isGiven(storageName) && isFree(storageName.strip())) {
                return storageName.strip();
            }
            return IntStream
                    .rangeClosed(DIGEST_PREFIX_LENGTH, nameDigest.length())
                    .mapToObj(prefixLength -> withDigestPrefix(storageName, nameDigest, prefixLength))
                    .filter(this::isFree)
                    .findFirst()
                    .orElseGet(() -> withDigestPrefix(storageName, nameDigest, nameDigest.length()));
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

        void registered(ProviderKeyPair pair, HandleHolderSummary holder, boolean intoExistingKey) {
            inventory.add(pair, holder);
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
